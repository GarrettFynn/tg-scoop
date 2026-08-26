"""RateLimiter + FloodWait 测试（B-05，v0.2；DEVELOPMENT.md §5.3）。

虚拟时钟注入（clock/sleep 可替换），不连真实网络、不真实睡眠。
"""

import asyncio

import pytest

from tg_scoop.exceptions import APIRateLimitError
from tg_scoop.rate_limiter import RateLimiter, run_with_floodwait


class FakeClock:
    """虚拟时钟：sleep 调用推进时间并记录睡眠点。"""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _run(coro):
    return asyncio.run(coro)


def test_token_bucket_virtual_clock():
    """令牌桶：前 30 次零等待；第 31 次等 ≈2.0s；35 次节奏符合补令牌。"""
    fake = FakeClock()
    limiter = RateLimiter(30, clock=fake.clock, sleep=fake.sleep)

    async def drive():
        for _ in range(35):
            await limiter.acquire()

    _run(drive())
    # 30 枚免费额度耗尽后每 2.0s 匀速补 1 枚：31~35 次各等 1 枚
    assert fake.sleeps == [2.0, 2.0, 2.0, 2.0, 2.0]
    assert fake.now == 10.0


class FakeFloodWaitError(Exception):
    """鸭子类型 FloodWait（有 .seconds 属性，不依赖 telethon）。"""

    def __init__(self, seconds: int):
        super().__init__(f"wait {seconds}s on api_id 12345")  # 故意带请求细节
        self.seconds = seconds


def test_floodwait_path():
    """FloodWait：按秒数睡眠 -> APIRateLimitError；消息只含秒数。"""
    fake = FakeClock()

    async def boom():
        raise FakeFloodWaitError(7)

    with pytest.raises(APIRateLimitError) as exc_info:
        _run(run_with_floodwait(boom(), sleep=fake.sleep))
    assert fake.sleeps == [7]
    assert "7" in str(exc_info.value)
    assert "api_id" not in str(exc_info.value)  # 请求细节不外泄


def test_non_floodwait_passthrough():
    """非 FloodWait 异常原样上抛（不包装、不睡眠）。"""
    fake = FakeClock()

    async def boom():
        raise ValueError("plain failure")

    with pytest.raises(ValueError, match="plain failure"):
        _run(run_with_floodwait(boom(), sleep=fake.sleep))
    assert fake.sleeps == []


def test_cli_exit_code_4(monkeypatch, capsys, tmp_path):
    """CLI 退出码 4：run_pipeline 抛 APIRateLimitError -> main 返回 4。"""
    from tg_scoop import cli

    def fake_pipeline(*args, **kwargs):
        raise APIRateLimitError("FloodWait 9s")

    monkeypatch.setattr(cli, "run_pipeline", fake_pipeline)
    code = cli.main(["--tdata-path", str(tmp_path)])
    assert code == cli.EXIT_RATE_LIMIT == 4
    assert "API 限速" in capsys.readouterr().err

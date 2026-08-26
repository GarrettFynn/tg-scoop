"""断点续跑状态文件测试（B-06；DEVELOPMENT.md §5.3 末段）。

覆盖：存读往返、损坏/字段缺失从头（警告日志）、mock client 的
续跑语义（max_id 透传与 progress_cb 即时上报）。
"""

import asyncio

from tg_scoop.message_matcher import fetch_chat_documents
from tg_scoop.rate_limiter import RateLimiter
from tg_scoop.state import STATE_NAME, load_state, save_state


def _run(coro):
    return asyncio.run(coro)


def test_state_roundtrip(tmp_path):
    """存读往返：save -> load 字段一致。"""
    save_state(tmp_path, 12345, 678)
    state = load_state(tmp_path, log=lambda _line: None)
    assert state == {"chat_id": 12345, "last_message_id": 678}


def test_state_corrupt_and_missing(tmp_path):
    """损坏 JSON 与字段缺失：load 返回 None + 警告日志出现。"""
    lines: list[str] = []
    (tmp_path / STATE_NAME).write_bytes(b"not json {{{")
    assert load_state(tmp_path, log=lines.append) is None
    assert any("损坏" in line and "从头" in line for line in lines)

    (tmp_path / STATE_NAME).write_text('{"chat_id": 1}', encoding="utf-8")
    assert load_state(tmp_path, log=lines.append) is None

    # 不存在 -> None 且无警告
    lines.clear()
    assert load_state(tmp_path / "nope", log=lines.append) is None
    assert lines == []


class _FakeDoc:
    def __init__(self, i):
        self.id = 1000 + i
        self.dc_id = 5
        self.size = 10
        self.attributes = []


class _FakeMsg:
    def __init__(self, msg_id: int):
        self.id = msg_id
        self.document = _FakeDoc(msg_id)


class _FakeClient:
    """记录 iter_messages 收到的 max_id；按最新→最旧产出消息。"""

    def __init__(self):
        self.max_id_seen: list = []

    async def iter_messages(self, _entity, **kwargs):
        self.max_id_seen.append(kwargs.get("max_id"))
        for msg_id in (900, 800, 700):
            yield _FakeMsg(msg_id)


def test_resume_semantics(tmp_path):
    """续跑：断点透传为 max_id；progress_cb 逐条即时上报最小 id。"""
    reported: list[int] = []
    client = _FakeClient()
    limiter = RateLimiter(30, clock=lambda: 0.0)

    docs = _run(fetch_chat_documents(
        client, object(), limiter,
        min_id_exclusive=850, progress_cb=reported.append,
    ))
    assert client.max_id_seen == [850]
    assert [d.doc_id for d in docs] == [1900, 1800, 1700]
    assert reported == [900, 800, 700]  # 逐条上报；末值即断点
    save_state(tmp_path, 12345, reported[-1])
    assert load_state(tmp_path, log=lambda _l: None)["last_message_id"] == 700

    # 不传断点：iter_messages 不带 max_id（现状行为）
    client2 = _FakeClient()
    _run(fetch_chat_documents(client2, object(), RateLimiter(30, clock=lambda: 0.0)))
    assert client2.max_id_seen == [None]

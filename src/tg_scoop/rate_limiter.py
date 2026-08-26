"""令牌桶限速器与 FloodWait 处理（B-05，v0.2；DEVELOPMENT.md §5.3）。

硬约束：≤30 msg/min（容量 30，每 2.0 秒匀速补 1 令牌）——稳定低速
比"冲 30 条然后干等"更接近正常客户端行为。一切 API 调用路径必须
过 limiter；FloodWait 必从（按其秒数暂停后抛 APIRateLimitError，
CLI 映射退出码 4）。
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from tg_scoop.exceptions import APIRateLimitError

T = TypeVar("T")


class RateLimiter:
    """令牌桶限速器（DEVELOPMENT.md §5.3）：容量 30，每 2.0 秒补 1 令牌。

    稳定低速比"冲 30 条然后干等"更接近正常客户端行为。
    """

    def __init__(
        self,
        per_minute: int = 30,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """初始化限速器。

        Args:
            per_minute: 每分钟令牌上限（桶容量 = 该值）。
            clock: 时钟（测试注入虚拟时钟）。
            sleep: 睡眠函数（测试注入记录型假睡眠）。
        """
        self._interval = 60.0 / per_minute
        self._capacity = per_minute
        self._tokens = per_minute
        self._clock = clock
        self._sleep = sleep
        self._last = clock()

    async def acquire(self) -> None:
        """取 1 个令牌，不足则 sleep 至下一枚补齐。

        按 clock 结算补充（``(now - last) / 间隔`` 向下取整，余量保留在
        ``_last`` 里），无令牌则 sleep（间隔 - 余量）后取走新补的这枚。
        """
        now = self._clock()
        refill = int((now - self._last) / self._interval)
        if refill:
            self._tokens = min(self._capacity, self._tokens + refill)
            self._last += refill * self._interval  # 余量保留，节奏不漂
        if self._tokens > 0:
            self._tokens -= 1
            return
        wait = self._interval - (now - self._last)
        if wait > 0:
            await self._sleep(wait)
        self._last += self._interval  # 该枚令牌的产生时刻
        self._tokens = 0  # 取走它


async def run_with_floodwait(
    coro: Awaitable[T], *, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
) -> T:
    """执行 API 调用；FloodWait 按其秒数暂停后抛 APIRateLimitError。

    FloodWaitError 按鸭子类型识别（有 ``.seconds`` 属性），避免硬依赖
    telethon 类型。其他异常原样上抛。

    Raises:
        APIRateLimitError: 触发 FloodWait（消息只含秒数，不含请求内容）。
    """
    try:
        return await coro
    except Exception as exc:
        seconds = getattr(exc, "seconds", None)
        if seconds is None:
            raise  # 非 FloodWait：原样上抛
        await sleep(seconds)
        raise APIRateLimitError(f"FloodWait {seconds}s") from exc

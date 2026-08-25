"""MTProto 会话复用（B-02，v0.2；DEVELOPMENT.md §5.1）。

由 A-07 修复后的 ``read_mtp_authorization`` 产出的授权三元组
（user_id / dc_id / auth_key，tdesktop 7.x 布局已适配）构造
Telethon MemorySession 免登录连接——复用本地已有会话，不扫码、
不短信、不触发新设备通知。

工程约束：
- telethon 是可选依赖（pyproject ``mtproto`` extra），本模块顶部
  只放标准库与本项目 import，telethon 一律函数内延迟 import；
- 敏感红线：auth_key / api_hash 不落盘、不进日志与异常消息；
  异常与日志只允许出现 user_id / dc_id。
"""

import re
from typing import TYPE_CHECKING

from tg_scoop.exceptions import MtprotoError
from tg_scoop.tdata_reader import MtpAuthorization

if TYPE_CHECKING:  # 仅类型标注用；运行期一律函数内延迟 import（可选依赖）
    from telethon import TelegramClient
    from telethon.sessions import MemorySession

DC_ADDRESSES: dict[int, tuple[str, int]] = {
    1: ("149.154.175.53", 443),
    2: ("149.154.167.51", 443),
    3: ("149.154.175.100", 443),
    4: ("149.154.167.91", 443),
    5: ("91.108.56.130", 443),
}
"""公开 DC 地址表：dc_id -> (ip, port)。"""

_TELETHON_MISSING = "未安装 telethon；pip install .[mtproto]"


def build_session(auth: MtpAuthorization) -> "MemorySession":
    """由授权三元组构造 MemorySession（延迟 import telethon）。

    set_dc(dc_id, ip, port) + auth_key = AuthKey(data=auth.auth_key)。

    Args:
        auth: TdataReader.read_mtp_authorization 的返回值。

    Returns:
        绑定好 DC 与 auth_key 的 MemorySession。

    Raises:
        MtprotoError: telethon 未安装，或 dc_id 不在 DC 地址表
            （消息只含 dc_id）。
    """
    try:
        from telethon.crypto import AuthKey
        from telethon.sessions import MemorySession
    except ImportError as exc:
        raise MtprotoError(_TELETHON_MISSING) from exc
    if auth.dc_id not in DC_ADDRESSES:
        raise MtprotoError(f"unknown dc_id: {auth.dc_id}")
    ip, port = DC_ADDRESSES[auth.dc_id]
    session = MemorySession()
    session.set_dc(auth.dc_id, ip, port)
    session.auth_key = AuthKey(data=auth.auth_key)
    return session


async def connect(
    auth: MtpAuthorization, api_id: int, api_hash: str
) -> "TelegramClient":
    """免登录连接：复用本地会话，不发起任何登录/扫码流程。

    Args:
        auth: 授权三元组。
        api_id / api_hash: my.telegram.org 注册应用获得（仅传入
            Telethon 构造，不进入日志与异常消息）。

    Returns:
        已连接且已授权的 TelegramClient。

    Raises:
        MtprotoError: telethon 未安装、连接后会话未授权
            （消息只含 user_id / dc_id）。
    """
    try:
        from telethon import TelegramClient
    except ImportError as exc:
        raise MtprotoError(_TELETHON_MISSING) from exc
    client = TelegramClient(build_session(auth), api_id, api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        raise MtprotoError(
            f"session not authorized (user_id={auth.user_id}, dc_id={auth.dc_id})"
        )
    return client


def parse_chat_id(text: str) -> int | str:
    """--chat-id 解析：纯数字（可带负号）→ int；否则视为 username 原样返回。

    Raises:
        MtprotoError: 空串或纯空白。
    """
    stripped = text.strip()
    if not stripped:
        raise MtprotoError("empty --chat-id")
    if re.fullmatch(r"-?\d+", stripped):
        return int(stripped)
    return stripped


async def resolve_entity(client: "TelegramClient", chat_ref: int | str):
    """对话实体解析：client.get_entity(chat_ref)。

    Raises:
        MtprotoError: 解析失败（异常收敛；消息不含 api_hash 等敏感值）。
    """
    try:
        return await client.get_entity(chat_ref)
    except Exception as exc:  # 收敛第三方异常为统一语义，敏感值不回显
        raise MtprotoError(
            f"cannot resolve chat {chat_ref!r}: {type(exc).__name__}"
        ) from exc

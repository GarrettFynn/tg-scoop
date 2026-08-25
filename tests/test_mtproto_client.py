"""MTProto 会话复用测试（B-02）。

不依赖真装 telethon：monkeypatch.setitem(sys.modules, ...) 注入假
telethon / telethon.sessions / telethon.crypto 模块；敏感值（auth_key、
api_hash）全部为合成随机值，且断言不进异常消息。
"""

import asyncio
import os
import sys
import types
from typing import ClassVar

import pytest

from tg_scoop.exceptions import MtprotoError
from tg_scoop.mtproto_client import (
    DC_ADDRESSES,
    build_session,
    connect,
    parse_chat_id,
    resolve_entity,
)
from tg_scoop.tdata_reader import MtpAuthorization

_AUTH_KEY = os.urandom(256)
_API_HASH = "deadbeef" * 4  # 合成值，非真实凭据


class FakeAuthKey:
    def __init__(self, data: bytes):
        self.data = data


class FakeMemorySession:
    def __init__(self):
        self.dc_calls: list[tuple] = []
        self.auth_key = None

    def set_dc(self, dc_id, ip, port):
        self.dc_calls.append((dc_id, ip, port))


class FakeTelegramClient:
    instances: ClassVar[list["FakeTelegramClient"]] = []
    authorized = True

    def __init__(self, session, api_id, api_hash):
        self.session = session
        self.api_id = api_id
        self.api_hash = api_hash
        self.connect_calls = 0
        self.entities: list = []
        FakeTelegramClient.instances.append(self)

    async def connect(self):
        self.connect_calls += 1

    async def is_user_authorized(self):
        return FakeTelegramClient.authorized

    async def get_entity(self, ref):
        if ref == "boom":
            raise ValueError("sensitive=api_hash-should-not-leak")
        self.entities.append(ref)
        return f"entity:{ref}"


def _install_fake_telethon(monkeypatch) -> None:
    """注入假 telethon 三件套到 sys.modules。"""
    telethon = types.ModuleType("telethon")
    telethon.TelegramClient = FakeTelegramClient
    sessions = types.ModuleType("telethon.sessions")
    sessions.MemorySession = FakeMemorySession
    crypto = types.ModuleType("telethon.crypto")
    crypto.AuthKey = FakeAuthKey
    monkeypatch.setitem(sys.modules, "telethon", telethon)
    monkeypatch.setitem(sys.modules, "telethon.sessions", sessions)
    monkeypatch.setitem(sys.modules, "telethon.crypto", crypto)


def _make_auth(dc_id: int = 5) -> MtpAuthorization:
    return MtpAuthorization(user_id=5112581468, dc_id=dc_id, auth_key=_AUTH_KEY)


def test_build_session_fields(monkeypatch):
    """build_session：set_dc 参数正确 + auth_key 经 AuthKey 包装同字节；未知 dc 抛错。"""
    _install_fake_telethon(monkeypatch)
    session = build_session(_make_auth(dc_id=5))
    assert session.dc_calls == [(5, "91.108.56.130", 443)]
    assert session.dc_calls[0][1] == DC_ADDRESSES[5][0]
    assert isinstance(session.auth_key, FakeAuthKey)
    assert session.auth_key.data == _AUTH_KEY

    with pytest.raises(MtprotoError) as exc_info:
        build_session(_make_auth(dc_id=99))
    assert "99" in str(exc_info.value)


def test_parse_chat_id():
    """parse_chat_id 三态 + 空白抛错。"""
    assert parse_chat_id("123") == 123
    assert parse_chat_id("-100123") == -100123
    assert parse_chat_id("@somechannel") == "@somechannel"
    with pytest.raises(MtprotoError):
        parse_chat_id("   ")


def test_connect_authorized_and_not(monkeypatch):
    """connect：已授权返回 client（connect 调一次）；未授权抛 MtprotoError。"""
    _install_fake_telethon(monkeypatch)
    FakeTelegramClient.instances.clear()
    FakeTelegramClient.authorized = True
    client = asyncio.run(connect(_make_auth(), api_id=12345, api_hash=_API_HASH))
    assert client.connect_calls == 1
    assert client.api_id == 12345
    assert client.session.dc_calls  # session 来自 build_session

    FakeTelegramClient.authorized = False
    with pytest.raises(MtprotoError) as exc_info:
        asyncio.run(connect(_make_auth(), api_id=12345, api_hash=_API_HASH))
    msg = str(exc_info.value)
    assert "5112581468" in msg and "5" in msg
    assert _API_HASH not in msg and _AUTH_KEY.hex() not in msg


def test_resolve_entity_sanitizes(monkeypatch):
    """resolve_entity：正常返回实体；第三方异常收敛为 MtprotoError 且不含敏感值。"""
    _install_fake_telethon(monkeypatch)
    FakeTelegramClient.instances.clear()
    client = FakeTelegramClient(FakeMemorySession(), 1, _API_HASH)
    assert asyncio.run(resolve_entity(client, "@chan")) == "entity:@chan"
    with pytest.raises(MtprotoError) as exc_info:
        asyncio.run(resolve_entity(client, "boom"))
    assert "api_hash-should-not-leak" not in str(exc_info.value)


def test_telethon_missing(monkeypatch):
    """telethon 缺失：build_session 抛 MtprotoError 且消息含安装指引。"""
    for name in ("telethon.sessions", "telethon.crypto", "telethon"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "telethon", None)  # 置 None 使 import 失败
    with pytest.raises(MtprotoError) as exc_info:
        build_session(_make_auth())
    assert "pip install .[mtproto]" in str(exc_info.value)

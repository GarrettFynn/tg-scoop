"""binlog 缓存索引解析器测试（B-03 阶段 2）。

fixture：手工构造 binlog 明文（BasicHeader + 记录流），用既有
``make_tdef`` 包成 TDEF 写入假缓存目录 <cache>/1/binlog。
宽度与语义对照 lib_storage（storage_cache_types.h /
storage_cache_binlog_reader.h）。
"""

import os
from pathlib import Path

import pytest

from tests.fixtures import make_tdef
from tg_scoop.cache_decryptor import CacheDecryptor
from tg_scoop.cache_index import (
    place_to_relpath,
    read_cache_index,
)
from tg_scoop.exceptions import CorruptedDataError

_LOCAL_KEY = os.urandom(256)

_KEY_A = bytes.fromhex("05056d0000000000c61c0000cb00f855")
_KEY_B = bytes.fromhex("050879000000000001106b1bf0fff155")
_KEY_C = bytes.fromhex("05090000000000002dbf311b936f3056")
_PLACE_A = bytes.fromhex("fea354d4112750")  # -> "EF/3A454D117205"（probe 实测对）


def _header(flags: int = 1, fmt: int = 0) -> bytes:
    head = (fmt | (flags << 8)).to_bytes(4, "little")
    return head + (1774098122).to_bytes(4, "little") + bytes(8)


def _store(
    key: bytes,
    place: bytes = _PLACE_A,
    tag: int = 1,
    size: int = 5911,
    checksum: int = 938201777,
    use_time: int | None = None,
) -> bytes:
    rec = (
        b"\x01"
        + tag.to_bytes(1)
        + size.to_bytes(3, "little")
        + place
        + checksum.to_bytes(4, "little")
        + key
    )
    if use_time is not None:
        rel1 = use_time & 0xFFFFFFFF
        rel2 = (use_time >> 32) & 0xFFFFFFFF
        rec += rel1.to_bytes(4, "little") + rel2.to_bytes(4, "little")
        rec += (1774098000).to_bytes(4, "little") + bytes(4)  # system + reserved
    return rec


def _multi(rtype: int, count: int, tail: bytes = b"") -> bytes:
    head = rtype.to_bytes(1) + count.to_bytes(3, "little")
    if rtype == 0x04:  # MultiAccess 头含 12B 时间
        return head + bytes(12) + tail
    return head + bytes(12) + tail  # MultiStore/MultiRemove 头含 12B reserved


def _write_binlog(cache_dir: Path, payload: bytes, version: int = 1) -> Path:
    vdir = cache_dir / str(version)
    vdir.mkdir(parents=True)
    (cache_dir / "version").write_bytes(version.to_bytes(4, "little"))
    (vdir / "binlog").write_bytes(make_tdef(_LOCAL_KEY, payload))
    return cache_dir


def test_basic_store_with_time(tmp_path):
    """flags=1 下 2 条 StoreWithTime：逐字段解析正确。"""
    payload = (
        _header(flags=1)
        + _store(_KEY_A, tag=1, size=5911, use_time=0x0102030405)
        + _store(_KEY_B, tag=0, size=131080, use_time=0x42)
    )
    cache = _write_binlog(tmp_path / "cache", payload)
    entries = read_cache_index(cache, CacheDecryptor(_LOCAL_KEY))

    assert set(entries) == {_KEY_A, _KEY_B}
    a = entries[_KEY_A]
    assert a.place_rel == "EF/3A454D117205"
    assert a.tag == 1
    assert a.size == 5911
    assert a.checksum == 938201777
    assert a.use_time == 0x0102030405
    b = entries[_KEY_B]
    assert b.tag == 0 and b.size == 131080
    assert b.use_time == 0x42


def test_multi_store_and_remove(tmp_path):
    """MultiStore 部件展开；Store 后 MultiRemove 删除 -> 终态无该 key。"""
    payload = (
        _header(flags=0)  # 不带时间：Store 32B
        + _multi(0x02, 2, _store(_KEY_A, tag=1) + _store(_KEY_B, tag=0))
        + _store(_KEY_C, tag=7)
        + _multi(0x03, 1, _KEY_A)  # 删除 A
    )
    cache = _write_binlog(tmp_path / "cache", payload)
    entries = read_cache_index(cache, CacheDecryptor(_LOCAL_KEY))

    assert set(entries) == {_KEY_B, _KEY_C}
    assert entries[_KEY_B].tag == 0
    assert entries[_KEY_C].tag == 7
    assert entries[_KEY_B].use_time is None  # flags=0 -> 无时间


def test_multi_access_cursor_advance(tmp_path):
    """MultiAccess(count=2) 后紧跟 Store：游标推进正确不错位（1c 踩坑回归）。"""
    payload = (
        _header(flags=1)
        + _store(_KEY_A, use_time=1)
        + _multi(0x04, 2, _KEY_A + _KEY_B)  # 仅推进游标
        + _store(_KEY_B, tag=9, use_time=2)
    )
    cache = _write_binlog(tmp_path / "cache", payload)
    entries = read_cache_index(cache, CacheDecryptor(_LOCAL_KEY))

    assert set(entries) == {_KEY_A, _KEY_B}
    assert entries[_KEY_B].tag == 9
    assert entries[_KEY_B].use_time == 2


def test_unknown_type_and_bad_format_fail(tmp_path):
    """未知记录类型显式失败（含 offset 与 type）；format!=0 同样失败。"""
    payload = _header(flags=1) + _store(_KEY_A, use_time=1) + b"\x7f" + bytes(47)
    cache = _write_binlog(tmp_path / "cache", payload)
    with pytest.raises(CorruptedDataError) as exc_info:
        read_cache_index(cache, CacheDecryptor(_LOCAL_KEY))
    msg = str(exc_info.value)
    assert "0x7f" in msg and str(16 + 48) in msg  # offset = header16 + store48

    bad = _write_binlog(tmp_path / "cache2", _header(fmt=1) + b"")
    with pytest.raises(CorruptedDataError) as exc2:
        read_cache_index(bad, CacheDecryptor(_LOCAL_KEY))
    assert "format" in str(exc2.value)


def test_place_to_relpath_real_samples():
    """place_to_relpath：对拍 probe_binlog.json 实测样本 + 长度非法。"""
    assert place_to_relpath(bytes.fromhex("fea354d4112750")) == "EF/3A454D117205"
    assert place_to_relpath(bytes.fromhex("ac717c69d5c117")) == "CA/17C7965D1C71"
    assert place_to_relpath(bytes.fromhex("298e0f10b22624")) == "92/E8F0012B6242"
    with pytest.raises(CorruptedDataError):
        place_to_relpath(b"\x01\x02\x03")

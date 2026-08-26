"""binlog 缓存索引只读解析（B-03 阶段 2，v0.2）。

7.x 缓存索引 = ``<cache目录>/<version>/binlog``（TDEF 加密容器，与
缓存媒体文件同族，``CacheDecryptor.decrypt_file`` 可直接解开）。
漂移项 D-7.1.1-2：7.1.1 实测 cache/media_cache 下无 map0/map1，
索引真身为 binlog（阶段 1/1b/1c 探测链闭合）。

布局依据（desktop-app/lib_storage，模块级宽度常量逐一标注出处）：
- ``storage_cache_types.h``：BasicHeader / Store / StoreWithTime /
  MultiStore / MultiRemove / MultiAccess / EstimatedTimePoint 结构体；
- ``storage_cache_binlog_reader.h``：Multi 记录 = sizeof(Head) +
  count×sizeof(Part)，**Part 为完整 Store 结构（含自身 type 字节）**；
- ``storage_cache_database_object.cpp``：Store/MultiStore 设置、
  MultiRemove 删除、MultiAccess 仅刷新访问时间的语义。

只读红线：本模块不打开任何文件做写操作；未知记录类型/版本显式失败
（漂移暴露原则，与 settings 0x4B 严格策略同族）。
"""

from dataclasses import dataclass
from pathlib import Path

from tg_scoop.cache_decryptor import CacheDecryptor
from tg_scoop.exceptions import (
    CacheNotFoundError,
    CorruptedDataError,
)

# 记录类型（storage_cache_types.h：Store/MultiStore/MultiRemove/MultiAccess::kType）
_STORE = 0x01
_MULTI_STORE = 0x02
_MULTI_REMOVE = 0x03
_MULTI_ACCESS = 0x04

# 宽度（storage_cache_types.h 结构体布局）
_BASIC_HEADER_LEN = 16  # format:8|flags:24(u32 LE) + systemTime + reserved×2
_STORE_LEN = 32  # type1+tag1+size3B LE+place7B+checksum4B LE+Key16B
_STORE_WITH_TIME_LEN = 48  # Store + EstimatedTimePoint(12B) + reserved(4B)
_MULTI_HEAD_LEN = 16  # type1+count3B LE+reserved12B（MultiStore/MultiRemove）
_MULTI_ACCESS_HEAD_LEN = 16  # type1+count3B LE+EstimatedTimePoint(12B)
_KEY_LEN = 16  # Key.high(8B LE) + Key.low(8B LE)

_FLAG_TRACK_ESTIMATED_TIME = 0x01  # BasicHeader::kTrackEstimatedTime
_PLACE_LEN = 7  # PlaceId = std::array<uint8, 7>


@dataclass(frozen=True)
class CacheIndexEntry:
    """一条缓存索引记录（Store/MultiStore 语义的最终态）。"""

    key: bytes  # 16B（Key.high + Key.low，小端各 8B，原序保留）
    place_rel: str  # PlaceFromId 等价换算的相对路径，如 "A5/5B40637E62FA"
    tag: int
    size: int
    checksum: int  # XXH32（仅原样保留，本阶段不校验）
    use_time: int | None  # StoreWithTime 的相对时间；无则 None


def place_to_relpath(place: bytes) -> str:
    """PlaceFromId 等价：每字节低 4 位在前、高 4 位在后（0-9A-F），
    首字节两字符后插 '/'。

    Raises:
        CorruptedDataError: place 不是 7 字节。
    """
    if len(place) != _PLACE_LEN:
        raise CorruptedDataError(f"place must be 7 bytes, got {len(place)}")
    digits = []
    for b in place:
        digits.append("0123456789ABCDEF"[b & 0x0F])
        digits.append("0123456789ABCDEF"[b >> 4])
    return digits[0] + digits[1] + "/" + "".join(digits[2:])


def path_to_place_rel(cache_dir: Path, path: Path) -> str:
    """缓存文件路径 → place 相对路径（binlog place_rel 的反算）。

    结构 ``cache_dir/<version>/<place_rel>``（如 cache/1/A5/5B40637E62FA
    → "A5/5B40637E62FA"）：去掉版本目录层后按 '/' 拼接。
    """
    return "/".join(Path(path).relative_to(cache_dir).parts[1:])


def _locate_binlog(cache_dir: Path) -> Path:
    """定位 binlog：version 文件（4B LE int32 版本号目录名）优先，
    失败回退扫描纯数字命名子目录，取含 binlog 的最大版本号者。

    Raises:
        CacheNotFoundError: 两种途径都找不到 binlog。
    """
    cache_dir = Path(cache_dir)
    version_file = cache_dir / "version"
    if version_file.is_file():
        raw = version_file.read_bytes()
        if len(raw) == 4:
            version = int.from_bytes(raw, "little")
            candidate = cache_dir / str(version) / "binlog"
            if candidate.is_file():
                return candidate
    # 回退：纯数字子目录中取含 binlog 的最大版本号
    candidates = []
    if cache_dir.is_dir():
        for child in cache_dir.iterdir():
            if child.is_dir() and child.name.isdigit() and (child / "binlog").is_file():
                candidates.append((int(child.name), child / "binlog"))
    if candidates:
        return max(candidates)[1]
    raise CacheNotFoundError(f"binlog not found under: {cache_dir}")


def _parse_store(
    record: bytes, with_time: bool
) -> CacheIndexEntry:
    """解析一条 Store/StoreWithTime 记录（也用于 MultiStore 部件）。"""
    tag = record[1]
    size = int.from_bytes(record[2:5], "little")
    place_rel = place_to_relpath(record[5:12])
    checksum = int.from_bytes(record[12:16], "little")
    key = record[16:32]
    use_time = None
    if with_time:
        # EstimatedTimePoint.getRelative() = relative1 | relative2<<32
        use_time = int.from_bytes(record[32:36], "little") | (
            int.from_bytes(record[36:40], "little") << 32
        )
    return CacheIndexEntry(
        key=key,
        place_rel=place_rel,
        tag=tag,
        size=size,
        checksum=checksum,
        use_time=use_time,
    )


def read_cache_index(
    cache_dir: Path, decryptor: CacheDecryptor
) -> dict[bytes, CacheIndexEntry]:
    """读取并解析 <cache_dir>/<version>/binlog，返回 key → CacheIndexEntry。

    语义（storage_cache_database_object.cpp）：Store/MultiStore 部件 =
    设置 key 条目（覆盖同 key 旧条目）；MultiRemove 部件 = 删除 key 条目；
    MultiAccess 仅更新 use_time（本阶段不反映在返回值，但计数正确推进
    游标）。

    Raises:
        CacheNotFoundError: binlog 不存在。
        DecryptionError: 解密失败（decrypt_file 上抛）。
        CorruptedDataError: 头部 format 非 Format_0、记录结构不合法、
            残尾不足一条记录、或遇未知记录类型（消息含 offset 与 type，
            供漂移裁决）。
    """
    binlog = _locate_binlog(cache_dir)
    plain = decryptor.decrypt_file(binlog)

    if len(plain) < _BASIC_HEADER_LEN:
        raise CorruptedDataError(
            f"binlog too short for BasicHeader: {len(plain)} bytes"
        )
    header = int.from_bytes(plain[0:4], "little")
    fmt = header & 0xFF
    flags = (header >> 8) & 0xFFFFFF
    if fmt != 0:  # Format 只定义了 Format_0（storage_cache_types.h）
        raise CorruptedDataError(f"unsupported binlog format: {fmt}")
    with_time = bool(flags & _FLAG_TRACK_ESTIMATED_TIME)
    store_len = _STORE_WITH_TIME_LEN if with_time else _STORE_LEN

    entries: dict[bytes, CacheIndexEntry] = {}
    pos = _BASIC_HEADER_LEN
    while pos < len(plain):
        rtype = plain[pos]
        if rtype == _STORE:
            if pos + store_len > len(plain):
                raise CorruptedDataError(
                    f"truncated Store record at offset {pos}"
                )
            entry = _parse_store(plain[pos : pos + store_len], with_time)
            entries[entry.key] = entry
            pos += store_len
        elif rtype == _MULTI_STORE:
            if pos + _MULTI_HEAD_LEN > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiStore head at offset {pos}"
                )
            count = int.from_bytes(plain[pos + 1 : pos + 4], "little")
            parts = pos + _MULTI_HEAD_LEN
            if parts + count * store_len > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiStore parts at offset {pos} (count={count})"
                )
            for i in range(count):
                off = parts + i * store_len
                entry = _parse_store(plain[off : off + store_len], with_time)
                entries[entry.key] = entry
            pos = parts + count * store_len
        elif rtype == _MULTI_REMOVE:
            if pos + _MULTI_HEAD_LEN > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiRemove head at offset {pos}"
                )
            count = int.from_bytes(plain[pos + 1 : pos + 4], "little")
            parts = pos + _MULTI_HEAD_LEN
            if parts + count * _KEY_LEN > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiRemove parts at offset {pos} (count={count})"
                )
            for i in range(count):
                off = parts + i * _KEY_LEN
                entries.pop(plain[off : off + _KEY_LEN], None)
            pos = parts + count * _KEY_LEN
        elif rtype == _MULTI_ACCESS:
            if pos + _MULTI_ACCESS_HEAD_LEN > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiAccess head at offset {pos}"
                )
            count = int.from_bytes(plain[pos + 1 : pos + 4], "little")
            parts = pos + _MULTI_ACCESS_HEAD_LEN
            if parts + count * _KEY_LEN > len(plain):
                raise CorruptedDataError(
                    f"truncated MultiAccess parts at offset {pos} (count={count})"
                )
            # 仅刷新访问时间：本阶段不反映在返回值，但必须正确推进游标
            pos = parts + count * _KEY_LEN
        else:
            raise CorruptedDataError(
                f"unknown binlog record type {rtype:#04x} at offset {pos}"
            )
    return entries

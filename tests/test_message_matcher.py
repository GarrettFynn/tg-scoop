"""三级匹配测试（B-04，v0.2；DEVELOPMENT.md §5.2）。

全部 mock/合成：不连真实网络（真实验证归 H-04），telethon 不参与
（matcher 全鸭子类型）。
"""

import asyncio
import json
import os

import pytest

from tg_scoop.cache_index import CacheIndexEntry
from tg_scoop.exceptions import APIRateLimitError
from tg_scoop.extractor import ExtractionStats
from tg_scoop.manifest import write_manifest
from tg_scoop.message_matcher import (
    DocumentInfo,
    MatchResult,
    document_bigfile_cache_key,
    document_cache_key,
    fetch_chat_documents,
    match_documents,
    match_with_content,
)
from tg_scoop.rate_limiter import RateLimiter


def _entry(place_rel: str, size: int, tag: int = 0) -> CacheIndexEntry:
    return CacheIndexEntry(
        key=os.urandom(16), place_rel=place_rel, tag=tag,
        size=size, checksum=0, use_time=None,
    )


def _run(coro):
    return asyncio.run(coro)


def test_document_cache_key_formula():
    """key 公式逐字节对拍手算期望值（data_types.cpp 取证）。"""
    # DocumentCacheKey(dc=5, id=0x1122334455667788)：high = 0x100|5 = 0x105
    key = document_cache_key(5, 0x1122334455667788)
    expected = (0x105).to_bytes(8, "little") + (0x1122334455667788).to_bytes(8, "little")
    assert key == expected
    # bigFile 基准键（image_location.cpp 取证）：high=0x10000|(id>>48), low=id<<16
    big = document_bigfile_cache_key(5, 0x1122334455667788)
    assert big[:8] == (0x10000 | 0x1122).to_bytes(8, "little")
    assert big[8:] == ((0x1122334455667788 << 16) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def test_p1_exact_match():
    """P1：document_cache_key 命中索引 -> level P1、字段正确。"""
    doc = DocumentInfo(doc_id=42, dc_id=5, size=100, original_name="a.mp4")
    key = document_cache_key(5, 42)
    index = {key: _entry("A5/5B40637E62FA", 100)}
    results = match_documents([doc], index, dc_id=5)
    assert len(results) == 1
    r = results[0]
    assert r.level == "P1" and r.place_rel == "A5/5B40637E62FA"
    assert r.document_id == 42 and r.original_name == "a.mp4"
    # 未命中不进结果
    assert match_documents([DocumentInfo(43, 5, 100, None)], index, dc_id=5) == []


def test_p2_head_hash_match_and_mismatch():
    """P2：尺寸候选 + 双头哈希一致 -> P2；不一致 -> 不中（唯一候选则 P3）。"""
    doc = DocumentInfo(doc_id=7, dc_id=5, size=500, original_name=None)
    local_head = os.urandom(1024)
    index = {"k1": _entry("B0/AAAA", 500), "k2": _entry("B1/BBBB", 999)}
    limiter = RateLimiter(30, clock=lambda: 0.0)

    async def fetch_same(_doc):
        return local_head

    async def fetch_other(_doc):
        return os.urandom(1024)

    def read_local(place_rel: str) -> bytes:
        assert place_rel == "B0/AAAA"
        return local_head

    hit = _run(match_with_content(
        [doc], index, 5,
        read_local_head=read_local, fetch_remote_head=fetch_same,
        limiter=limiter,
    ))
    assert len(hit) == 1 and hit[0].level == "P2" and hit[0].place_rel == "B0/AAAA"

    miss = _run(match_with_content(
        [doc], index, 5,
        read_local_head=read_local, fetch_remote_head=fetch_other,
        limiter=limiter,
    ))
    # P2 未中且同尺寸候选唯一 -> P3
    assert len(miss) == 1 and miss[0].level == "P3"


def test_p3_multiple_candidates_no_match():
    """P3：同尺寸候选多个 -> 不匹配（不进结果）。"""
    doc = DocumentInfo(doc_id=8, dc_id=5, size=500, original_name=None)
    index = {"k1": _entry("B0/AAAA", 500), "k2": _entry("B1/BBBB", 500)}
    limiter = RateLimiter(30, clock=lambda: 0.0)

    async def fetch(_doc):
        return os.urandom(1024)

    results = _run(match_with_content(
        [doc], index, 5,
        read_local_head=lambda _p: os.urandom(1024),
        fetch_remote_head=fetch, limiter=limiter,
    ))
    assert results == []


def test_rate_limit_and_floodwait():
    """限速与 FloodWait：acquire 按消息数调用；FloodWait -> APIRateLimitError。"""

    class FakeDoc:
        def __init__(self, i):
            self.id = i
            self.dc_id = 5
            self.size = 100 + i
            self.attributes = []

    class FakeMsg:
        def __init__(self, i, with_doc=True):
            self.document = FakeDoc(i) if with_doc else None

    class FakeClient:
        def __init__(self, msgs):
            self._msgs = msgs

        async def iter_messages(self, _entity):
            for m in self._msgs:
                yield m

    acquire_calls = []

    class CountingLimiter(RateLimiter):
        async def acquire(self):
            acquire_calls.append(1)

    msgs = [FakeMsg(1), FakeMsg(2, with_doc=False), FakeMsg(3)]
    docs = _run(fetch_chat_documents(FakeClient(msgs), object(), CountingLimiter()))
    assert [d.doc_id for d in docs] == [1, 3]  # 无文档消息被滤除
    assert len(acquire_calls) == 3  # 消息粒度限速（≥翻页数）

    class FloodClient:
        async def iter_messages(self, _entity):
            exc = type("FW", (Exception,), {"seconds": 3})()
            raise exc
            yield  # pragma: no cover

    async def noop_sleep(_s):
        return None

    with pytest.raises(APIRateLimitError):
        _run(fetch_chat_documents(FloodClient(), object(), CountingLimiter()))


def test_manifest_v2_with_matches(tmp_path):
    """manifest v2：带 matches 写盘 -> version==2、match 子对象与汇总正确；
    不带 matches（旧路径）结构不变。"""
    from tg_scoop.manifest import ExtractedEntry

    stats = ExtractionStats(succeeded=2)
    extracted = [
        ExtractedEntry("a.mp4", "aa" * 32, 100, "2026-08-26T00:00:00", "mp4", "cache"),
        ExtractedEntry("b.png", "bb" * 32, 200, "2026-08-26T00:00:01", "png", "cache"),
    ]
    matches = [
        MatchResult("A5/XX", "P1", 42, "a.mp4", file_name="a.mp4"),
        MatchResult("B1/YY", "P3", 77, None, file_name=None),  # 未关联到条目
    ]
    path = write_manifest(
        tmp_path, tdata_path=tmp_path, stats=stats,
        extracted=extracted, skipped=[], failed=[], matches=matches,
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == 2
    assert doc["entries"][0]["match"] == {
        "level": "P1", "document_id": 42, "original_name": "a.mp4",
    }
    assert "match" not in doc["entries"][1]
    assert doc["match_summary"] == {"P1": 1, "P2": 0, "P3": 1}

    # 旧路径（不带 matches）：无 match 子对象、无 match_summary
    (tmp_path / "v1").mkdir()
    path2 = write_manifest(
        tmp_path / "v1", tdata_path=tmp_path, stats=stats,
        extracted=extracted, skipped=[], failed=[],
    )
    doc2 = json.loads(path2.read_text(encoding="utf-8"))
    assert doc2["version"] == 2
    assert "match_summary" not in doc2
    assert all("match" not in e for e in doc2["entries"])

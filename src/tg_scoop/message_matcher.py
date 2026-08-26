"""三级匹配（B-04，v0.2；DEVELOPMENT.md §5.2）。

缓存条目 ↔ 消息文档的匹配按置信度三级逐级降级：
- P1：document.id 精确（cache key 命中 binlog 索引）
- P2：尺寸候选 + 本地/远端前 1KB 内容哈希联合比对
- P3：同尺寸候选唯一（低置信，需人工核对；manifest 标注）

匹配只产出 manifest 标注，不改提取命名（命名生效是 B-07）。
本模块全鸭子类型（client/entity 无类型硬依赖），telethon 只在
生产胶水层（cli）与 mtproto_client 中延迟 import。

敏感红线：auth_key / api_hash / access_hash / file_reference
不进日志、异常消息与 manifest。
"""

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from tg_scoop.cache_index import CacheIndexEntry
from tg_scoop.extractor import sanitize_filename
from tg_scoop.rate_limiter import RateLimiter, run_with_floodwait


def document_cache_key(dc_id: int, doc_id: int) -> bytes:
    """DocumentCacheKey(dcId, id) = Key{high = 0x100 | (dcId & 0xFF), low = id}
    （tdesktop data_types.cpp 原文取证）；binlog 中两个 uint64 小端序：
    返回 high.to_bytes(8,"little") + id.to_bytes(8,"little")。"""
    high = 0x100 | (dc_id & 0xFF)
    return high.to_bytes(8, "little") + doc_id.to_bytes(8, "little")


def document_bigfile_cache_key(dc_id: int, doc_id: int) -> bytes:
    """media_cache 大文件（视频流式）基准键。

    取证自 tdesktop ``StorageFileLocation::bigFileBaseCacheKey()``
    （ui/image/image_location.cpp，Document 分支）：
    high = 0x10000 | ((dcId << 16) & 0xFF00) | (id >> 48)；
    low = id << 16。两个 uint64 小端序拼接（同 binlog Key 布局）。
    """
    high = 0x10000 | ((dc_id << 16) & 0xFF00) | (doc_id >> 48)
    low = (doc_id << 16) & 0xFFFFFFFFFFFFFFFF
    return high.to_bytes(8, "little") + low.to_bytes(8, "little")


@dataclass(frozen=True)
class DocumentInfo:
    """一条消息中文档媒体的最小信息（鸭子类型采集，见 fetch_chat_documents）。"""

    doc_id: int
    dc_id: int
    size: int
    original_name: str | None  # DocumentAttributeFilename，无则 None
    raw: object | None = None  # 生产胶水的原始 document 对象（远端拉取用）；测试不涉及
    sender_name: str | None = None  # 发送者昵称/标题（B-07），取不到 None


@dataclass(frozen=True)
class MatchResult:
    """一条匹配结果；file_name 在 manifest 关联阶段回填（输出文件名）。"""

    place_rel: str  # cache_index 的 place 相对路径
    level: str  # "P1" / "P2" / "P3"
    document_id: int
    original_name: str | None
    file_name: str | None = None
    sender_name: str | None = None  # 真实发送者（B-07 降级命名用）


def _sender_name_of(msg) -> str | None:
    """从消息发送者采集昵称/标题（鸭子类型）：title > first_name > username。"""
    sender = getattr(msg, "sender", None)
    if sender is None:
        return None
    for attr in ("title", "first_name", "username"):
        value = getattr(sender, attr, None)
        if value:
            return str(value)
    return None


def build_naming(
    matches: list[MatchResult],
) -> tuple[dict[str, str], dict[str, str], set[str]]:
    """由匹配结果构建命名三件套（B-07；§6.1 净化规则复用）。

    规则：P1/P2 命中且有 original_name → name_map（净化后原始文件名）；
    命中但无原始名且有 sender → sender_map（提取时按降级规则用真实
    sender 命名）；P3 → needs_review（文件名照旧，落 needs-review/）。

    Returns:
        (name_map, sender_map, needs_review)，均以 place_rel 为键。
    """
    name_map: dict[str, str] = {}
    sender_map: dict[str, str] = {}
    needs_review: set[str] = set()
    for m in matches:
        if m.level in ("P1", "P2"):
            if m.original_name:
                name_map[m.place_rel] = sanitize_filename(m.original_name)
            elif m.sender_name:
                sender_map[m.place_rel] = m.sender_name
        elif m.level == "P3":
            needs_review.add(m.place_rel)
    return name_map, sender_map, needs_review


async def fetch_chat_documents(
    client,
    entity,
    limiter: RateLimiter,
    min_id_exclusive: int | None = None,
    progress_cb: Callable[[int], None] | None = None,
) -> list[DocumentInfo]:
    """iter_messages(entity) 翻页拉取，仅收集含文档媒体的条目。

    限速红线：按消息粒度在每条处理前 ``await limiter.acquire()``
    （保守近似"每页请求前"——宁可多等也不超 30/min）。FloodWait
    经 run_with_floodwait 转为 APIRateLimitError 上抛。

    续跑（B-06）：``min_id_exclusive`` 透传 ``iter_messages`` 的
    ``max_id``（消息按最新→最旧翻页，断点 = 已处理最小 id）；
    ``progress_cb`` 每处理一条消息即时回调当前最小 message_id——
    中断时已处理部分不丢（调用方凭最近上报值落盘断点）。
    未传断点参数 = 现状行为（全量翻页）。
    mock 友好：client/entity 为鸭子类型。
    """
    return await run_with_floodwait(
        _collect_documents(client, entity, limiter, min_id_exclusive, progress_cb)
    )


async def _collect_documents(
    client,
    entity,
    limiter: RateLimiter,
    min_id_exclusive: int | None = None,
    progress_cb: Callable[[int], None] | None = None,
) -> list[DocumentInfo]:
    docs: list[DocumentInfo] = []
    kwargs = {"max_id": min_id_exclusive} if min_id_exclusive is not None else {}
    async for msg in client.iter_messages(entity, **kwargs):
        await limiter.acquire()
        msg_id = getattr(msg, "id", None)
        doc = getattr(msg, "document", None)
        if doc is not None:
            name = None
            for attr in getattr(doc, "attributes", None) or []:
                file_name = getattr(attr, "file_name", None)
                if file_name:
                    name = file_name
                    break
            docs.append(
                DocumentInfo(
                    doc_id=doc.id,
                    dc_id=getattr(doc, "dc_id", 0),
                    size=doc.size,
                    original_name=name,
                    raw=doc,
                    sender_name=_sender_name_of(msg),
                )
            )
        if progress_cb is not None and msg_id is not None:
            progress_cb(msg_id)
    return docs


def match_documents(
    docs: list[DocumentInfo],
    index: dict[bytes, CacheIndexEntry],
    dc_id: int,
    *,
    key_fn: Callable[[int, int], bytes] = document_cache_key,
) -> list[MatchResult]:
    """P1 精确：document_cache_key(dc_id, doc.doc_id) 命中索引 → "P1"。

    （P2/P3 见 match_with_content，本函数纯本地。）
    ``key_fn`` 供 media_cache 的大文件键（document_bigfile_cache_key）。
    """
    results: list[MatchResult] = []
    for doc in docs:
        entry = index.get(key_fn(dc_id, doc.doc_id))
        if entry is not None:
            results.append(
                MatchResult(entry.place_rel, "P1", doc.doc_id, doc.original_name)
            )
    return results


async def match_with_content(
    docs: list[DocumentInfo],
    index: dict[bytes, CacheIndexEntry],
    dc_id: int,
    *,
    read_local_head: Callable[[str], bytes],
    fetch_remote_head: Callable[[DocumentInfo], Awaitable[bytes]],
    limiter: RateLimiter,
    key_fn: Callable[[int, int], bytes] = document_cache_key,
) -> list[MatchResult]:
    """完整三级匹配（P1 精确 → P2 尺寸+前 1KB 哈希 → P3 仅尺寸唯一）。

    P1 未中的条目：按 ``doc.size == entry.size`` 收候选；候选存在时，
    ``read_local_head(place_rel)`` 读本地明文前 1KB 与
    ``fetch_remote_head(doc)``（远端前 1KB）比对 SHA-256，一致 → P2；
    P2 仍未中且同尺寸候选唯一 → P3；候选多个或为零 → 不匹配（不进结果）。
    限速红线：``fetch_remote_head`` 每次调用前必须先 ``limiter.acquire()``，
    且调用经 run_with_floodwait 包装。
    """
    results: list[MatchResult] = []
    for doc in docs:
        entry = index.get(key_fn(dc_id, doc.doc_id))
        if entry is not None:
            results.append(
                MatchResult(entry.place_rel, "P1", doc.doc_id, doc.original_name)
            )
            continue

        candidates = [e for e in index.values() if e.size == doc.size]
        if candidates:
            await limiter.acquire()  # 远端拉取前必过限速（红线）
            remote_head = await run_with_floodwait(fetch_remote_head(doc))
            remote_sha = hashlib.sha256(remote_head).digest()
            hit = None
            for candidate in candidates:
                if hashlib.sha256(read_local_head(candidate.place_rel)).digest() == remote_sha:
                    hit = candidate
                    break
            if hit is not None:
                results.append(
                    MatchResult(hit.place_rel, "P2", doc.doc_id, doc.original_name)
                )
                continue
            if len(candidates) == 1:
                results.append(
                    MatchResult(
                        candidates[0].place_rel, "P3", doc.doc_id, doc.original_name
                    )
                )
        # 候选为零或 P2 未中且候选多个 → 不匹配
    return results

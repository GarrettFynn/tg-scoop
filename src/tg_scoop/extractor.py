"""提取编排：命名、去重、落盘。

对应 DEVELOPMENT.md §2.1 环节 ⑥⑦、§6 命名与去重规则、
§7 错误处理规范。协调 CacheDecryptor 与 MediaDetector 完成
"解密 -> 识别 -> 命名 -> 写盘"的完整流程。

硬性规则：绝不覆盖已有文件（§6.2）；写盘失败立即中止（§2.2）。
"""

import hashlib
import itertools
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from tg_scoop.cache_decryptor import CacheDecryptor, iter_cache_files
from tg_scoop.cache_index import path_to_place_rel
from tg_scoop.exceptions import DecryptionError, ExtractionError
from tg_scoop.manifest import ExtractedEntry, FailedEntry, SkippedEntry
from tg_scoop.media_detector import SNIFF_LEN, MediaDetector, MediaType

MAX_NAME_ATTEMPTS = 9999
"""unique_path 的序号探测上限；耗尽抛 ExtractionError——
无限循环比报错更难排查（DEVELOPMENT.md §6.2）。"""

FILENAME_MAX_LEN = 200
"""文件名净化后的长度上限（字符）。"""

# Windows 非法字符（§6.1 净化规则）；控制字符另行按 ord < 32 过滤
ILLEGAL_FILENAME_CHARS = '<>:"/\\|?*'
_ILLEGAL_SET = frozenset(ILLEGAL_FILENAME_CHARS)

_partial_seq = itertools.count()
"""流式管线临时文件序号（.tg-scoop-partial-{pid}-{序号}）。"""


@dataclass
class ExtractionStats:
    """一次提取运行的统计（报告口径见 DEVELOPMENT.md §2.1）。"""

    succeeded: int = 0
    skipped: int = 0  # 无法识别媒体类型
    failed: int = 0  # 解密失败
    duplicates: int = 0  # 内容哈希命中已有文件，未重复落盘
    failed_reasons: dict[str, int] = field(default_factory=dict)

    def merge(self, other: "ExtractionStats") -> None:
        """把另一次运行的统计累加进本统计（多缓存目录场景）。"""
        self.succeeded += other.succeeded
        self.skipped += other.skipped
        self.failed += other.failed
        self.duplicates += other.duplicates
        for reason, count in other.failed_reasons.items():
            self.failed_reasons[reason] = self.failed_reasons.get(reason, 0) + count


def sanitize_filename(name: str) -> str:
    """净化文件名：剔除 Windows 非法字符与控制字符，截断到上限。

    非法字符与控制字符替换为 "_"（而非删除），避免 "a<b>c" 变成
    "abc" 这类语义粘连；尾部点/空格去除（Windows 不允许）；空结果
    回退 "unnamed"。

    Args:
        name: 原始文件名（可能来自消息附件名）。

    Returns:
        可安全写盘的文件名。
    """
    cleaned = "".join(
        "_" if (c in _ILLEGAL_SET or ord(c) < 32) else c for c in name
    )
    cleaned = cleaned.rstrip(" .")[:FILENAME_MAX_LEN]
    return cleaned or "unnamed"


def build_fallback_name(
    mtime: datetime,
    digest: bytes,
    media_type: MediaType,
    sender: str = "unknown",
) -> str:
    """生成 API 不可用时的降级文件名（DEVELOPMENT.md §6.1）。

    格式：{发送者名}_{时间戳}_{哈希前8位}.{扩展名}
    例：Alice_20260314_153022_a1b2c3d4.mp4

    为什么带哈希：时间戳精度只有秒，同秒多文件是常态；8 位哈希
    把冲突概率降到可忽略，并保证幂等——重复运行同一文件算出同一
    名字，配合不覆盖规则天然实现增量提取。

    Args:
        mtime: 缓存文件的修改时间（本地时区）。
        digest: 明文 SHA-256 摘要。
        media_type: 识别出的媒体类型。
        sender: 发送者名，v0.1 恒为 "unknown"。

    Returns:
        净化后的文件名。
    """
    raw = f"{sender}_{mtime:%Y%m%d_%H%M%S}_{digest.hex()[:8]}.{media_type.value}"
    return sanitize_filename(raw)


def unique_path(out_dir: Path, filename: str) -> Path:
    """返回不冲突的输出路径；冲突时追加 " (1)"、" (2)" ... 后缀。

    后缀在扩展名之前，如 video (1).mp4。绝不覆盖已有文件。

    Args:
        out_dir: 输出目录。
        filename: 期望文件名。

    Returns:
        不冲突的目标路径。

    Raises:
        ExtractionError: 序号探测超过 MAX_NAME_ATTEMPTS。
    """
    candidate = Path(out_dir) / filename
    if not candidate.exists():
        return candidate
    stem, suffix = os.path.splitext(filename)
    for i in range(1, MAX_NAME_ATTEMPTS + 1):
        candidate = Path(out_dir) / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
    raise ExtractionError(
        f"naming sequence exhausted ({MAX_NAME_ATTEMPTS}) for: {filename}"
    )


def save_media(
    data: bytes,
    out_dir: Path,
    filename: str,
    mtime: datetime | None = None,
) -> Path:
    """落盘并按需恢复修改时间，返回实际写入路径。

    mtime 来自缓存文件自身的修改时间——这是"按时间排序找回
    已删除内容"场景的关键元数据。

    Args:
        data: 明文媒体字节。
        out_dir: 输出目录（不存在则创建）。
        filename: 期望文件名（内部经 unique_path 去冲突）。
        mtime: 要恢复的修改时间；None 则不修改。

    Returns:
        实际写入的路径。

    Raises:
        OSError: 写盘失败（磁盘满、权限不足）——调用方应中止整批。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = unique_path(out_dir, filename)
    target.write_bytes(data)
    if mtime is not None:
        ts = mtime.timestamp()
        os.utime(target, (ts, ts))
    return target


class Extractor:
    """提取编排器：遍历缓存 -> 解密 -> 识别 -> 命名 -> 落盘。"""

    def __init__(
        self,
        decryptor: CacheDecryptor,
        detector: MediaDetector | None = None,
        allowed_types: set[MediaType] | None = None,
        name_map: dict[str, str] | None = None,
        sender_map: dict[str, str] | None = None,
        needs_review: set[str] | None = None,
    ) -> None:
        """初始化提取器。

        Args:
            decryptor: 持有 LocalKey 的缓存解密器。
            detector: 媒体嗅探器；None 时创建默认实例。
            allowed_types: 可选输出类型过滤集合（C-13）；None=不过滤
                （现状行为），命中集合外类型计入 skipped 并记
                ``filtered_by_type:{类型}``。
            name_map: 可选命名映射（B-07）：place_rel → 期望文件名
                （API 匹配命中的原始文件名）；None=降级命名（现状）。
            sender_map: 可选 sender 映射（B-07）：place_rel → 真实
                发送者名，命中无原始名时用于降级命名的 sender 参数。
            needs_review: 可选 P3 集合（B-07）：place_rel 命中时
                落 ``out_dir/needs-review/`` 子目录（文件名照旧）。
        """
        self._decryptor = decryptor
        self._detector = detector or MediaDetector()
        self._allowed_types = allowed_types
        self._name_map = name_map
        self._sender_map = sender_map
        self._needs_review = needs_review
        self._seen: set[bytes] = set()  # 本次运行内已落盘的明文 SHA-256
        # manifest 记录（N-1）：由 extract_all 逐分支追加，run_pipeline 统一落盘
        self.extracted_entries: list[ExtractedEntry] = []
        self.skipped_entries: list[SkippedEntry] = []
        self.failed_entries: list[FailedEntry] = []

    def extract_all(
        self,
        cache_dir: Path,
        out_dir: Path,
        file_cb: "Callable[[], None] | None" = None,
        cancel_event: object | None = None,
    ) -> ExtractionStats:
        """对 cache 目录执行完整提取流程。

        逐文件容错：单个解密失败计入 failed 并继续；无法识别计入
        skipped；内容重复计入 duplicates。写盘 OSError 直接上抛
        （系统性故障，继续跑只是假进度，DEVELOPMENT.md §2.2）。

        Args:
            cache_dir: tdata/user_data/cache 目录。
            out_dir: 输出目录（不存在则创建）。
            file_cb: 可选进度回调，每处理完一个文件恰好调用一次
                （无论该文件落入哪个分支），供 GUI 进度条计数。
            cancel_event: 可选协作式取消事件（threading.Event 风格鸭子
                类型）；每个文件处理前检查 is_set()，置位即跳过本轮
                剩余文件并返回部分统计——不杀线程、不中断当前文件。

        Returns:
            提取统计；取消时为已处理部分的部分统计。

        Raises:
            CacheNotFoundError: 缓存目录不存在或为空。
            OSError: 写盘失败，立即中止。
        """
        stats = ExtractionStats()
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        source_name = Path(cache_dir).name  # manifest 来源目录字段："cache" / "media_cache"
        # 清理上次中断残留的临时文件（流式管线清理契约）
        for leftover in out_dir.glob(".tg-scoop-partial-*"):
            leftover.unlink(missing_ok=True)

        for path in iter_cache_files(cache_dir):
            if cancel_event is not None and cancel_event.is_set():
                break
            self._process_one(
                path, source_name, out_dir, stats,
                place_rel=path_to_place_rel(cache_dir, path),
            )
            if file_cb is not None:
                file_cb()

        return stats

    def _process_one(
        self,
        path: Path,
        source_name: str,
        out_dir: Path,
        stats: ExtractionStats,
        place_rel: str,
    ) -> None:
        """流式处理单个缓存文件（N-5）：首块嗅探 -> 临时文件+流式哈希 -> 查重改名。

        对外契约（stats 四计数、manifest 字段与口径、文件名、幂等、
        失败/跳过原因）与旧全量路径逐字节一致；内存峰值与文件大小脱钩。
        """
        tmp_path: Path | None = None
        try:
            stream = self._decryptor.decrypt_file_iter(path)
            first = next(stream, b"")  # 空数据边界：TDEF 无媒体数据
            media_type = self._detector.sniff(first[:SNIFF_LEN])
            if media_type is None:
                # 早停：不读取该文件余量
                stats.skipped += 1
                self.skipped_entries.append(
                    SkippedEntry(path.name, source_name, "unrecognized_media_type")
                )
                return
            if self._allowed_types is not None and media_type not in self._allowed_types:
                # 类型过滤（C-13）：与未识别同样早停，不读余量、不落盘
                stats.skipped += 1
                self.skipped_entries.append(
                    SkippedEntry(path.name, source_name, f"filtered_by_type:{media_type.value}")
                )
                return
            # 识别为媒体：解密 -> 哈希 -> 写临时文件一趟完成
            hasher = hashlib.sha256()
            size = 0
            tmp_path = (
                out_dir / f".tg-scoop-partial-{os.getpid()}-{next(_partial_seq)}"
            )
            with open(tmp_path, "wb") as f:
                chunk = first
                while chunk:
                    hasher.update(chunk)
                    f.write(chunk)
                    size += len(chunk)
                    chunk = next(stream, b"")
            digest = hasher.digest()
        except DecryptionError as exc:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            stats.failed += 1
            reason = type(exc).__name__
            stats.failed_reasons[reason] = stats.failed_reasons.get(reason, 0) + 1
            self.failed_entries.append(
                FailedEntry(path.name, source_name, reason)
            )
            return

        self._finalize(
            path, source_name, out_dir, stats, tmp_path, digest, size,
            media_type, place_rel,
        )

    def _finalize(
        self,
        path: Path,
        source_name: str,
        out_dir: Path,
        stats: ExtractionStats,
        tmp_path: Path,
        digest: bytes,
        size: int,
        media_type: MediaType,
        place_rel: str,
    ) -> None:
        """查重、命名、改名落盘与计数记录（串行管线与并行消费共用）。

        命名（B-07）：name_map 命中 → 期望文件名（原始文件名）；
        sender_map 命中 → 降级名用真实 sender；needs_review 命中 →
        落 ``out_dir/needs-review/``（文件名照旧，manifest 记录相对
        out_dir 的路径）。三映射全 None = 现状逐字节一致。
        """
        if self._is_duplicate(digest):
            tmp_path.unlink(missing_ok=True)
            stats.duplicates += 1
            self.skipped_entries.append(
                SkippedEntry(path.name, source_name, "duplicate")
            )
            return

        # §6.1 要求本地时区朴素时间：naive datetime 是有意选择，不加 tz
        mtime = datetime.fromtimestamp(path.stat().st_mtime)  # noqa: DTZ006
        target_dir = out_dir
        if self._name_map is not None and place_rel in self._name_map:
            # name_map 值生产路径已经 sanitize（build_naming），此处防御性
            # 再过一遍（幂等）：任何来源的映射都不会写出非法文件名
            name = sanitize_filename(self._name_map[place_rel])
        else:
            sender = (
                self._sender_map.get(place_rel)
                if self._sender_map is not None
                else None
            ) or "unknown"
            name = build_fallback_name(mtime, digest, media_type, sender=sender)
        if self._needs_review is not None and place_rel in self._needs_review:
            target_dir = out_dir / "needs-review"
            target_dir.mkdir(parents=True, exist_ok=True)

        # 幂等关键：确定性命名下，目标已存在且内容相同 -> 计重复跳过；
        # 内容不同（同名不同物）则由 unique_path 加序号（原 save_media 语义；
        # needs-review 子目录内查重作用域随目标目录）
        target = target_dir / name
        if target.exists() and self._file_digest(target) == digest:
            tmp_path.unlink(missing_ok=True)
            self._seen.add(digest)
            stats.duplicates += 1
            self.skipped_entries.append(
                SkippedEntry(path.name, source_name, "duplicate")
            )
            return

        final_path = unique_path(target_dir, name)
        os.replace(tmp_path, final_path)  # OSError 上抛
        ts = mtime.timestamp()
        os.utime(final_path, (ts, ts))
        self._seen.add(digest)
        stats.succeeded += 1
        self.extracted_entries.append(
            ExtractedEntry(
                file_name=final_path.relative_to(out_dir).as_posix(),
                sha256=digest.hex(),
                size=size,
                mtime=mtime.isoformat(timespec="seconds"),
                media_type=media_type.value,
                source_cache_dir=source_name,
            )
        )

    def _is_duplicate(self, digest: bytes) -> bool:
        """查询本次运行内是否已落盘过相同内容（SHA-256 查重）。

        Args:
            digest: 明文 SHA-256 摘要。

        Returns:
            已落盘过返回 True。
        """
        return digest in self._seen

    @staticmethod
    def _file_digest(path: Path) -> bytes:
        """计算已有输出文件的 SHA-256（用于幂等判定）。"""
        return hashlib.sha256(Path(path).read_bytes()).digest()

    def consume_predecrypted(
        self,
        path: Path,
        source_name: str,
        out_dir: Path,
        stats: ExtractionStats,
        plain_path: str | None,
        error_reason: str | None,
        place_rel: str,
    ) -> None:
        """消费并行 worker 的预解密产物（C-02），与 _process_one 同口径。

        池内明文文件即临时文件：sniff/流式哈希后直接交 _finalize
        查重改名（不二次写盘）；未识别/失败分支负责删除池文件。

        Args:
            path: 原始缓存文件路径（命名/mtime/记录来源）。
            source_name: 来源缓存目录名。
            out_dir: 输出目录。
            stats: 累计统计（并行路径直接消费进合并统计）。
            plain_path: 池内明文临时文件路径；None 表示解密失败。
            error_reason: 解密失败的异常类型名；None 表示成功。
            place_rel: 该缓存文件的 place 相对路径（B-07 命名映射键）。
        """
        if error_reason is not None:
            stats.failed += 1
            stats.failed_reasons[error_reason] = (
                stats.failed_reasons.get(error_reason, 0) + 1
            )
            self.failed_entries.append(
                FailedEntry(path.name, source_name, error_reason)
            )
            return
        assert plain_path is not None  # 与 error_reason 互斥（worker 契约）
        tmp_path = Path(plain_path)
        with open(tmp_path, "rb") as f:
            first = f.read(SNIFF_LEN)
        media_type = self._detector.sniff(first)
        if media_type is None:
            tmp_path.unlink(missing_ok=True)
            stats.skipped += 1
            self.skipped_entries.append(
                SkippedEntry(path.name, source_name, "unrecognized_media_type")
            )
            return
        if self._allowed_types is not None and media_type not in self._allowed_types:
            # 类型过滤（C-13）：删除池文件，与未识别分支同构
            tmp_path.unlink(missing_ok=True)
            stats.skipped += 1
            self.skipped_entries.append(
                SkippedEntry(path.name, source_name, f"filtered_by_type:{media_type.value}")
            )
            return
        hasher = hashlib.sha256()
        size = 0
        with open(tmp_path, "rb") as f:
            while chunk := f.read(1 << 20):
                hasher.update(chunk)
                size += len(chunk)
        self._finalize(
            path, source_name, out_dir, stats,
            tmp_path, hasher.digest(), size, media_type, place_rel,
        )


# ---------------------------------------------------------------------------
# 并行 worker（C-02）：multiprocessing.Pool 的 initializer 与任务函数。
# 必须是模块级函数（Windows spawn 依赖按限定名 pickle）。worker 只解密
# 并写池内临时文件，不写最终输出、不共享状态；LocalKey 仅进程内存持有。
# ---------------------------------------------------------------------------

_POOL_DECRYPTOR: CacheDecryptor | None = None
_POOL_DIR: Path | None = None


def _pool_worker_init(local_key: bytes, pool_root: str) -> None:
    """Pool worker 初始化：各自持有 LocalKey 构造解密器并建私有子目录。"""
    global _POOL_DECRYPTOR, _POOL_DIR
    _POOL_DECRYPTOR = CacheDecryptor(local_key)
    _POOL_DIR = Path(pool_root) / str(os.getpid())
    _POOL_DIR.mkdir(parents=True, exist_ok=True)


def _pool_decrypt_one(path_str: str) -> tuple[str, str | None, str | None]:
    """worker 任务：解密一个缓存文件并写池内临时文件。

    Returns:
        ``(缓存路径, 池内明文临时路径 或 None, 异常类型名 或 None)``。
    """
    path = Path(path_str)
    assert _POOL_DECRYPTOR is not None and _POOL_DIR is not None
    try:
        data = _POOL_DECRYPTOR.decrypt_file(path)
    except DecryptionError as exc:
        return path_str, None, type(exc).__name__
    tmp = _POOL_DIR / path.name
    tmp.write_bytes(data)
    return path_str, str(tmp), None

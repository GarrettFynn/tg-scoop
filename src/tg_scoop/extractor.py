"""提取编排：命名、去重、落盘。

对应 DEVELOPMENT.md §2.1 环节 ⑥⑦、§6 命名与去重规则、
§7 错误处理规范。协调 CacheDecryptor 与 MediaDetector 完成
"解密 -> 识别 -> 命名 -> 写盘"的完整流程。

硬性规则：绝不覆盖已有文件（§6.2）；写盘失败立即中止（§2.2）。
"""

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from tg_scoop.cache_decryptor import CacheDecryptor, iter_cache_files
from tg_scoop.exceptions import DecryptionError, ExtractionError
from tg_scoop.media_detector import SNIFF_LEN, MediaDetector, MediaType

MAX_NAME_ATTEMPTS = 9999
"""unique_path 的序号探测上限；耗尽抛 ExtractionError——
无限循环比报错更难排查（DEVELOPMENT.md §6.2）。"""

FILENAME_MAX_LEN = 200
"""文件名净化后的长度上限（字符）。"""

# Windows 非法字符（§6.1 净化规则）；控制字符另行按 ord < 32 过滤
ILLEGAL_FILENAME_CHARS = '<>:"/\\|?*'
_ILLEGAL_SET = frozenset(ILLEGAL_FILENAME_CHARS)


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
    ) -> None:
        """初始化提取器。

        Args:
            decryptor: 持有 LocalKey 的缓存解密器。
            detector: 媒体嗅探器；None 时创建默认实例。
        """
        self._decryptor = decryptor
        self._detector = detector or MediaDetector()
        self._seen: set[bytes] = set()  # 本次运行内已落盘的明文 SHA-256

    def extract_all(self, cache_dir: Path, out_dir: Path) -> ExtractionStats:
        """对 cache 目录执行完整提取流程。

        逐文件容错：单个解密失败计入 failed 并继续；无法识别计入
        skipped；内容重复计入 duplicates。写盘 OSError 直接上抛
        （系统性故障，继续跑只是假进度，DEVELOPMENT.md §2.2）。

        Args:
            cache_dir: tdata/user_data/cache 目录。
            out_dir: 输出目录（不存在则创建）。

        Returns:
            提取统计。

        Raises:
            CacheNotFoundError: 缓存目录不存在或为空。
            OSError: 写盘失败，立即中止。
        """
        stats = ExtractionStats()
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for path in iter_cache_files(cache_dir):
            try:
                data = self._decryptor.decrypt_file(path)
            except DecryptionError as exc:
                stats.failed += 1
                reason = type(exc).__name__
                stats.failed_reasons[reason] = stats.failed_reasons.get(reason, 0) + 1
                continue

            media_type = self._detector.sniff(data[:SNIFF_LEN])
            if media_type is None:
                stats.skipped += 1
                continue

            digest = hashlib.sha256(data).digest()
            if self._is_duplicate(digest):
                stats.duplicates += 1
                continue

            # §6.1 要求本地时区朴素时间：naive datetime 是有意选择，不加 tz
            mtime = datetime.fromtimestamp(path.stat().st_mtime)  # noqa: DTZ006
            name = build_fallback_name(mtime, digest, media_type)

            # 幂等关键：确定性命名下，目标已存在且内容相同 -> 计重复跳过；
            # 内容不同（同名不同物）则由 save_media 的 unique_path 加序号
            target = out_dir / name
            if target.exists() and self._file_digest(target) == digest:
                self._seen.add(digest)
                stats.duplicates += 1
                continue

            save_media(data, out_dir, name, mtime)  # OSError 上抛
            self._seen.add(digest)
            stats.succeeded += 1

        return stats

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

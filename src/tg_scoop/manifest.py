"""提取清单 manifest（路线图 §四 N-1；DEVELOPMENT.md §6）。

每次提取运行结束在输出目录写 manifest.json：落盘条目、跳过条目
（未识别/重复）、失败条目的完整记录，供用户审计与 v0.2 三级匹配
输入。每轮覆盖重写——本文件是工具自身的报告，"绝不覆盖"红线
针对的是提取出的媒体文件，不含报告自身。
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 避免与 extractor 循环导入（extractor 引用本模块的记录类型）
    from tg_scoop.extractor import ExtractionStats

MANIFEST_VERSION = 1
MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class ExtractedEntry:
    """成功落盘的一条媒体记录。"""

    file_name: str
    sha256: str  # 明文 SHA-256 hex（64 位）
    size: int  # 字节
    mtime: str  # 本地朴素 ISO（秒级），与降级命名的 mtime 同源
    media_type: str
    source_cache_dir: str  # "cache" / "media_cache"


@dataclass(frozen=True)
class SkippedEntry:
    """未落盘的缓存条目（未识别媒体类型或内容重复）。"""

    cache_file: str
    source_cache_dir: str
    reason: str  # "unrecognized_media_type" / "duplicate"


@dataclass(frozen=True)
class FailedEntry:
    """解密失败的缓存条目。"""

    cache_file: str
    source_cache_dir: str
    reason: str  # 异常类型名（如 DecryptionError）


def write_manifest(
    out_dir: Path,
    *,
    tdata_path: Path,
    stats: "ExtractionStats",
    extracted: list[ExtractedEntry],
    skipped: list[SkippedEntry],
    failed: list[FailedEntry],
) -> Path:
    """在输出目录写 manifest.json（覆盖重写），返回其路径。

    口径契约：len(extracted) == stats.succeeded；
    len(skipped) == stats.skipped + stats.duplicates；
    len(failed) == stats.failed。
    generated_at 用本地朴素时间是有意选择，与 entries 的 mtime
    字段及 §6.1 命名时间戳同口径（先例 extractor.py 的 noqa: DTZ006）。

    Raises:
        OSError: 写盘失败（与提取写盘同一语义，调用方应中止）。
    """
    doc = {
        "version": MANIFEST_VERSION,
        "tdata_path": str(tdata_path),
        "generated_at": datetime.now().isoformat(timespec="seconds"),  # noqa: DTZ005
        "stats": {
            "succeeded": stats.succeeded,
            "skipped": stats.skipped,
            "failed": stats.failed,
            "duplicates": stats.duplicates,
        },
        "entries": [asdict(e) for e in extracted],
        "skipped_entries": [asdict(e) for e in skipped],
        "failed_entries": [asdict(e) for e in failed],
    }
    path = Path(out_dir) / MANIFEST_NAME
    path.write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return path

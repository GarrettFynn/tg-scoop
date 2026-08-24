"""Extractor 单元测试（P0-11 移植自 _selftest_extract.py 检查 1–8）。

覆盖点对应 DEVELOPMENT.md §6（命名与去重）与 §9.1（测试策略）：
sanitize_filename / build_fallback_name / unique_path / save_media /
extract_all 统计与幂等 / 序号耗尽保护。
"""

import os
from datetime import datetime

import pytest

from tests.fixtures import make_tdef
from tg_scoop.cache_decryptor import CacheDecryptor
from tg_scoop.exceptions import ExtractionError
from tg_scoop.extractor import (
    Extractor,
    build_fallback_name,
    sanitize_filename,
    save_media,
    unique_path,
)
from tg_scoop.media_detector import MediaType

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"
_PNG_DATA = _PNG + os.urandom(500)
_MP4_DATA = b"\x00\x00\x00\x18ftypisom" + os.urandom(500)
_GARBAGE_DATA = os.urandom(300)  # 能解密但不可识别 -> skipped


def test_sanitize_filename():
    """非法字符/控制字符替换、尾部点空格去除、截断、空回退。"""
    assert sanitize_filename('a<b>:"c/\\d|e?f*g') == "a_b___c__d_e_f_g"
    assert sanitize_filename("bad\x00name\x1f") == "bad_name_"
    assert sanitize_filename("trailing. . .") == "trailing"
    assert sanitize_filename("x" * 300) == "x" * 200
    assert sanitize_filename("") == "unnamed"
    assert sanitize_filename('<>:"/\\|?*') == "_________"


def test_build_fallback_name():
    """格式 {sender}_{时间戳}_{哈希前8位}.{ext} 且确定性（幂等前提）。"""
    mtime = datetime(2026, 3, 14, 15, 30, 22)  # noqa: DTZ001 —— 刻意 naive：对齐 §6.1 本地时区命名语义
    digest = bytes.fromhex("a1b2c3d4" + "00" * 28)
    name1 = build_fallback_name(mtime, digest, MediaType.MP4, sender="Alice")
    assert name1 == "Alice_20260314_153022_a1b2c3d4.mp4"
    name2 = build_fallback_name(mtime, digest, MediaType.MP4, sender="Alice")
    assert name1 == name2  # 同一输入恒定同名


def test_unique_path(tmp_path):
    """序号后缀探测 + 绝不覆盖已有文件。"""
    (tmp_path / "video.mp4").write_bytes(b"a")
    (tmp_path / "video (1).mp4").write_bytes(b"b")
    assert unique_path(tmp_path, "video.mp4").name == "video (2).mp4"
    assert unique_path(tmp_path, "new.png").name == "new.png"
    assert (tmp_path / "video.mp4").read_bytes() == b"a"  # 内容未被触碰


def test_save_media(tmp_path):
    """落盘 + mtime 恢复。"""
    out = tmp_path / "out"
    ts = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001 —— 刻意 naive：对齐 §6.1 本地时区命名语义
    saved = save_media(b"payload", out, "f.bin", mtime=ts)
    assert saved.read_bytes() == b"payload"
    assert abs(saved.stat().st_mtime - ts.timestamp()) < 1e-6


def test_extract_all_stats_and_idempotency(tmp_path):
    """混合目录统计正确；同 Extractor 连跑与跨运行均幂等。"""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "good_png").write_bytes(make_tdef(_LOCAL_KEY, _PNG_DATA))
    (cache / "good_mp4").write_bytes(make_tdef(_LOCAL_KEY, _MP4_DATA))
    (cache / "corrupted").write_bytes(os.urandom(200))  # 解密失败
    (cache / "unreadable").write_bytes(make_tdef(_LOCAL_KEY, _GARBAGE_DATA))
    (cache / "map0").write_bytes(b"index")  # 被遍历过滤
    out = tmp_path / "out"

    # 首次：统计口径正确、内容还原正确
    stats = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)
    assert stats.succeeded == 2
    assert stats.failed == 1
    assert stats.skipped == 1
    assert stats.duplicates == 0
    outputs = list(out.iterdir())
    assert len(outputs) == 2
    assert any(p.name.endswith(".png") for p in outputs)
    assert any(p.name.endswith(".mp4") for p in outputs)
    contents = {p.read_bytes() for p in outputs}
    assert _PNG_DATA in contents and _MP4_DATA in contents

    # 同一 Extractor 连跑：本次运行内查重
    extractor = Extractor(CacheDecryptor(_LOCAL_KEY))
    extractor.extract_all(cache, out)
    stats2 = extractor.extract_all(cache, out)
    assert stats2.duplicates == 2 and stats2.succeeded == 0

    # 跨运行（新 Extractor，无 _seen）：靠"同名同内容"判定重复
    stats3 = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)
    assert stats3.duplicates == 2 and stats3.succeeded == 0
    assert len(list(out.iterdir())) == 2  # 未产生 (1) 后缀文件


def test_naming_exhaustion_guard(tmp_path, monkeypatch):
    """序号探测达上限抛 ExtractionError（不无限循环）。"""
    monkeypatch.setattr("tg_scoop.extractor.MAX_NAME_ATTEMPTS", 3)
    for i in range(4):
        suffix = "" if i == 0 else f" ({i})"
        (tmp_path / f"f{suffix}.bin").write_bytes(b"x")
    with pytest.raises(ExtractionError):
        unique_path(tmp_path, "f.bin")

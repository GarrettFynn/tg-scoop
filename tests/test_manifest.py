"""提取清单 manifest 测试（B-01 / N-1，DEVELOPMENT.md §6.3）。

覆盖：字段与口径契约、skipped/failed 记录、幂等重跑的 manifest
语义、media_cache 来源字段。命名与去重逻辑不在此测（见
test_extractor.py），本文件只断言记录与落盘 JSON。
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import run_pipeline

_LOCAL_KEY = os.urandom(256)
_PNG_DATA = b"\x89PNG\r\n\x1a\n" + os.urandom(500)
_GARBAGE = os.urandom(500)  # 合法 TDEF 但明文无法识别媒体类型


def _read_manifest(out: Path) -> dict:
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _media_files(out: Path) -> set[str]:
    return {p.name for p in out.iterdir() if p.name != "manifest.json"}


def test_manifest_fields_and_stats(tmp_path):
    """字段与口径：stats 四计数一致；entries[0] 各字段与明文/输出一致。"""
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    stats = run_pipeline(tdata, out, None)

    doc = _read_manifest(out)
    assert doc["version"] == 2  # B-04：manifest v2（新增字段可选，v1 兼容）
    assert doc["tdata_path"] == str(tdata)
    assert doc["stats"] == {
        "succeeded": stats.succeeded,
        "skipped": stats.skipped,
        "failed": stats.failed,
        "duplicates": stats.duplicates,
    }
    # 口径契约
    assert len(doc["entries"]) == stats.succeeded
    assert len(doc["skipped_entries"]) == stats.skipped + stats.duplicates
    assert len(doc["failed_entries"]) == stats.failed

    entry = doc["entries"][0]
    assert entry["sha256"] == hashlib.sha256(_PNG_DATA).hexdigest()
    assert entry["size"] == len(_PNG_DATA)
    assert entry["media_type"] == "png"
    assert entry["source_cache_dir"] == "cache"
    datetime.fromisoformat(entry["mtime"])  # 可解析即合格
    output_names = _media_files(out)
    assert entry["file_name"] in output_names
    assert (out / entry["file_name"]).read_bytes() == _PNG_DATA


def test_manifest_skipped_and_failed(tmp_path):
    """未识别计入 skipped_entries；损坏计入 failed_entries（含文件名）。"""
    tdata = make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={
            "good": make_tdef(_LOCAL_KEY, _PNG_DATA),
            "unrec": make_tdef(_LOCAL_KEY, _GARBAGE),
            "broken": os.urandom(200),  # 损坏 -> 解密失败
        },
    )
    out = tmp_path / "out"
    run_pipeline(tdata, out, None)

    doc = _read_manifest(out)
    skipped = doc["skipped_entries"]
    assert len(skipped) == 1
    assert skipped[0]["cache_file"] == "unrec"
    assert skipped[0]["reason"] == "unrecognized_media_type"
    assert skipped[0]["source_cache_dir"] == "cache"
    failed = doc["failed_entries"]
    assert len(failed) == 1
    assert failed[0]["cache_file"] == "broken"
    assert failed[0]["reason"] == "DecryptionError"


def test_manifest_idempotent_rerun(tmp_path):
    """幂等重跑：第二遍全计 duplicate；媒体文件集合两遍一致，无矛盾条目。"""
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    run_pipeline(tdata, out, None)
    first_files = _media_files(out)

    stats2 = run_pipeline(tdata, out, None)
    assert stats2.succeeded == 0
    assert stats2.duplicates == 1
    doc2 = _read_manifest(out)
    assert doc2["entries"] == []
    assert len(doc2["skipped_entries"]) == 1
    assert all(
        e["reason"] == "duplicate" for e in doc2["skipped_entries"]
    )
    assert _media_files(out) == first_files


def test_manifest_media_cache_source(tmp_path):
    """media_cache 来源：entries[0].source_cache_dir == "media_cache"。"""
    tdata = make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={},
        media_cache_files={"m1": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    run_pipeline(tdata, out, None)

    doc = _read_manifest(out)
    assert len(doc["entries"]) == 1
    assert doc["entries"][0]["source_cache_dir"] == "media_cache"

"""输出类型过滤测试（C-13，v0.1.4）。

最高红线：allowed_types=None（默认全选）时行为与过滤前逐字节一致；
过滤分支只加不改。覆盖串行/并行两路径与 CLI 非法类型参数。
"""

import hashlib
import json
import os
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import EXIT_NOT_FOUND, main, run_pipeline
from tg_scoop.media_detector import MediaType

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"
_JPG = b"\xff\xd8\xff\xe0"
_MP4 = b"\x00\x00\x00\x18ftypisom"


def _make_multi_type_tdata(tmp_path: Path) -> Path:
    """PNG/JPEG/MP4 各一 + 1 个不可识别（合法 TDEF 随机内容）。"""
    return make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={
            "a_png": make_tdef(_LOCAL_KEY, _PNG + os.urandom(300)),
            "b_jpg": make_tdef(_LOCAL_KEY, _JPG + os.urandom(300)),
            "c_mp4": make_tdef(_LOCAL_KEY, _MP4 + os.urandom(300)),
            "d_garbage": make_tdef(_LOCAL_KEY, os.urandom(300)),
        },
    )


def _media_names(out: Path) -> set[str]:
    return {p.name for p in out.iterdir() if p.name != "manifest.json"}


def _manifest(out: Path) -> dict:
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    doc.pop("generated_at", None)
    return doc


def test_filter_keeps_only_selected(tmp_path):
    """过滤生效：只选 jpg -> 输出仅 jpg；其余计入 skipped 且 manifest 三类并存。"""
    tdata = _make_multi_type_tdata(tmp_path)
    out = tmp_path / "out"
    stats = run_pipeline(tdata, out, None, allowed_types={MediaType.JPEG})

    names = _media_names(out)
    assert len(names) == 1 and next(iter(names)).endswith(".jpg")
    assert stats.succeeded == 1
    assert stats.skipped == 3  # png + mp4 被过滤 + garbage 未识别
    assert stats.failed == 0

    doc = _manifest(out)
    reasons = sorted(e["reason"] for e in doc["skipped_entries"])
    assert reasons == [
        "filtered_by_type:mp4",
        "filtered_by_type:png",
        "unrecognized_media_type",
    ]
    # 口径等式不破
    assert len(doc["skipped_entries"]) == stats.skipped + stats.duplicates
    assert len(doc["entries"]) == stats.succeeded


def test_default_none_unchanged(tmp_path):
    """默认全选（None）：行为与过滤前一致，无 filtered 记录。"""
    tdata = _make_multi_type_tdata(tmp_path)
    out = tmp_path / "out"
    stats = run_pipeline(tdata, out, None)  # 不传 allowed_types

    assert stats.succeeded == 3
    assert stats.skipped == 1  # 仅未识别
    assert stats.failed == 0
    doc = _manifest(out)
    assert all(
        e["reason"] == "unrecognized_media_type" for e in doc["skipped_entries"]
    )
    assert len(_media_names(out)) == 3


def test_parallel_filter_equals_serial(tmp_path):
    """并行路径一致：jobs=2 + 过滤 与 jobs=1 + 过滤 产物全等。"""
    tdata = _make_multi_type_tdata(tmp_path)
    out1, out2 = tmp_path / "out1", tmp_path / "out2"
    allowed = {MediaType.MP4}
    stats1 = run_pipeline(tdata, out1, None, jobs=1, allowed_types=allowed)
    stats2 = run_pipeline(tdata, out2, None, jobs=2, allowed_types=allowed)

    def hashes(o: Path) -> dict[str, str]:
        return {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in o.iterdir()
            if p.name != "manifest.json"
        }

    assert hashes(out1) == hashes(out2)
    assert len(hashes(out1)) == 1
    for field in ("succeeded", "skipped", "failed", "duplicates"):
        assert getattr(stats1, field) == getattr(stats2, field), field
    assert _manifest(out1) == _manifest(out2)


def test_cli_invalid_type_exit_2(tmp_path, capsys):
    """非法类型：--types mp4,foo -> 退出码 2，stderr 含"未知类型"。"""
    tdata = _make_multi_type_tdata(tmp_path)
    code = main(["--tdata-path", str(tdata), "--types", "mp4,foo"])
    assert code == EXIT_NOT_FOUND
    assert "未知类型" in capsys.readouterr().err

"""并行解密测试（C-02）。

最高红线：并行输出与串行逐字节一致（文件集合/内容/stats/manifest）。
另覆盖顺序确定性、recommended_jobs 边界与并行取消语义。
"""

import hashlib
import json
import os
import threading
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import run_pipeline
from tg_scoop.hardware import HardwareInfo, recommended_jobs

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"
_MP4 = b"\x00\x00\x00\x18ftypisom"


def _make_mixed_tdata(tmp_path: Path) -> Path:
    """8 个缓存文件：好（png/mp4）/损坏/未识别/内容重复 四类混合。"""
    png1 = _PNG + os.urandom(300)
    files = {
        "a_png1": make_tdef(_LOCAL_KEY, png1),
        "b_png2": make_tdef(_LOCAL_KEY, _PNG + os.urandom(300)),
        "c_mp4": make_tdef(_LOCAL_KEY, _MP4 + os.urandom(300)),
        "d_mp4b": make_tdef(_LOCAL_KEY, _MP4 + os.urandom(300)),
        "e_dup": make_tdef(_LOCAL_KEY, png1),  # 与 a_png1 内容重复
        "f_garbage": make_tdef(_LOCAL_KEY, os.urandom(300)),  # 未识别
        "g_broken": os.urandom(200),  # 损坏 -> 解密失败
        "h_png3": make_tdef(_LOCAL_KEY, _PNG + os.urandom(300)),
    }
    return make_fake_tdata(tmp_path, _LOCAL_KEY, cache_files=files)


def _tree_hashes(out: Path) -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in out.iterdir()
        if p.name != "manifest.json"
    }


def _manifest(out: Path) -> dict:
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    doc.pop("generated_at", None)
    return doc


def test_parallel_equals_serial(tmp_path):
    """并行 == 串行：文件集合与逐文件哈希、stats、manifest 全等。"""
    tdata = _make_mixed_tdata(tmp_path)
    out1, out3 = tmp_path / "out1", tmp_path / "out3"
    stats1 = run_pipeline(tdata, out1, None, jobs=1)
    stats3 = run_pipeline(tdata, out3, None, jobs=3)

    assert _tree_hashes(out1) == _tree_hashes(out3)
    for field in ("succeeded", "skipped", "failed", "duplicates"):
        assert getattr(stats1, field) == getattr(stats3, field), field
    m1, m3 = _manifest(out1), _manifest(out3)
    assert m1["stats"] == m3["stats"]
    assert m1["entries"] == m3["entries"]
    assert m1["skipped_entries"] == m3["skipped_entries"]
    assert m1["failed_entries"] == m3["failed_entries"]


def test_parallel_order_determinism(tmp_path):
    """顺序确定性：jobs=3 重复两跑，manifest entries 顺序一致。"""
    tdata = _make_mixed_tdata(tmp_path)
    orders = []
    for i in (1, 2):
        out = tmp_path / f"out{i}"
        run_pipeline(tdata, out, None, jobs=3)
        doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        orders.append([e["file_name"] for e in doc["entries"]])
    assert orders[0] == orders[1]


def test_recommended_jobs_boundaries():
    """recommended_jobs：1 核/未知/8 核 16GB/4 核 2GB/16 核未知 RAM。"""
    assert recommended_jobs(HardwareInfo(cores=1, ram_gb=None)) == 1
    assert recommended_jobs(HardwareInfo(cores=None, ram_gb=None)) == 1
    assert recommended_jobs(HardwareInfo(cores=8, ram_gb=16.0)) == 7
    assert recommended_jobs(HardwareInfo(cores=4, ram_gb=2.0)) == 2
    assert recommended_jobs(HardwareInfo(cores=16, ram_gb=None)) == 8


def test_parallel_cancel_preset(tmp_path):
    """并行取消：预置事件 -> 部分统计（全零）+ 无池临时文件残留。"""
    tdata = _make_mixed_tdata(tmp_path)
    event = threading.Event()
    event.set()
    out = tmp_path / "out"
    lines: list[str] = []
    stats = run_pipeline(
        tdata, out, None,
        progress_cb=lines.append, cancel_event=event, jobs=3,
    )
    assert stats.succeeded == 0
    assert stats.skipped == 0 and stats.failed == 0 and stats.duplicates == 0
    assert any("已按用户要求取消" in line for line in lines)
    assert not (out / ".tg-scoop-pool").exists()
    assert (out / "manifest.json").is_file()

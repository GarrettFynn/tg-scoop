"""逐文件进度回报与协作式取消测试（v0.1.2 UX 包任务 1）。

覆盖：file_progress_cb 计数契约、预置取消即停、中途取消、
以及不传新参数时的 CLI 兼容（行为不变）。
"""

import json
import os
import threading
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import run_pipeline

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"
_MP4 = b"\x00\x00\x00\x18ftypisom"
_WEBM = b"\x1a\x45\xdf\xa3"


def _make_three_file_tdata(tmp_path: Path) -> Path:
    """合成含 3 个不同内容缓存文件的假 tdata。"""
    return make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={
            "f1": make_tdef(_LOCAL_KEY, _PNG + os.urandom(100)),
            "f2": make_tdef(_LOCAL_KEY, _MP4 + os.urandom(100)),
            "f3": make_tdef(_LOCAL_KEY, _WEBM + os.urandom(100)),
        },
    )


def test_file_progress_cb_counts(tmp_path):
    """进度回调：3 个文件恰好回调 3 次，首 (1,3) 末 (3,3)。"""
    tdata = _make_three_file_tdata(tmp_path)
    calls: list[tuple[int, int]] = []
    run_pipeline(
        tdata, tmp_path / "out", None,
        file_progress_cb=lambda d, t: calls.append((d, t)),
    )
    assert len(calls) == 3
    assert calls[0] == (1, 3)
    assert calls[-1] == (3, 3)


def test_cancel_before_start(tmp_path):
    """预置位取消事件： succeeded==0、日志含取消行、manifest 照常生成。"""
    tdata = _make_three_file_tdata(tmp_path)
    event = threading.Event()
    event.set()
    out = tmp_path / "out"
    lines: list[str] = []
    stats = run_pipeline(
        tdata, out, None,
        progress_cb=lines.append,
        cancel_event=event,
    )
    assert stats.succeeded == 0
    assert stats.skipped == 0 and stats.failed == 0 and stats.duplicates == 0
    assert any("已按用户要求取消" in line for line in lines)
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert doc["stats"]["succeeded"] == 0
    assert doc["stats"]["skipped"] == 0
    assert doc["stats"]["failed"] == 0
    assert doc["stats"]["duplicates"] == 0


def test_cancel_mid_run(tmp_path):
    """中途取消：第 1 次回调时置位 -> 处理数 ≤1，日志含取消行。"""
    tdata = _make_three_file_tdata(tmp_path)
    event = threading.Event()
    calls: list[tuple[int, int]] = []

    def on_progress(done: int, total: int) -> None:
        calls.append((done, total))
        event.set()  # 第一个文件处理完后请求取消

    lines: list[str] = []
    stats = run_pipeline(
        tdata, tmp_path / "out", None,
        progress_cb=lines.append,
        file_progress_cb=on_progress,
        cancel_event=event,
    )
    processed = stats.succeeded + stats.skipped + stats.failed + stats.duplicates
    assert processed <= 1
    assert len(calls) == processed
    assert any("已按用户要求取消" in line for line in lines)


def test_cli_compat_without_new_params(tmp_path):
    """CLI 兼容：不传新参数（现状调用方式）行为不变。"""
    tdata = _make_three_file_tdata(tmp_path)
    stats = run_pipeline(tdata, tmp_path / "out", None)
    assert stats.succeeded == 3
    assert stats.failed == 0

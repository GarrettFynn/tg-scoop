"""gui 自测：run_pipeline 契约 + GUI 冒烟（无 mainloop）。

运行：
    .venv/Scripts/python _selftest_gui.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "src")

from _selftest_common import make_fake_tdata, make_tdef

from tg_scoop.cli import run_pipeline
from tg_scoop.exceptions import DecryptionError, TDataNotFoundError
from tg_scoop.media_detector import PNG_MAGIC

LOCAL_KEY = os.urandom(256)
PNG_DATA = PNG_MAGIC + os.urandom(500)


def test_run_pipeline():
    """run_pipeline：正常统计 + progress_cb 日志 + 异常路径。"""
    with tempfile.TemporaryDirectory() as tmp:
        tdata = make_fake_tdata(
            Path(tmp),
            LOCAL_KEY,
            cache_files={"a1b2": make_tdef(LOCAL_KEY, PNG_DATA)},
        )
        out = Path(tmp) / "out"
        lines: list[str] = []
        stats = run_pipeline(tdata, out, None, progress_cb=lines.append)
        assert stats.succeeded == 1 and stats.failed == 0, stats
        assert any("LocalKey" in line for line in lines), lines
        assert (next(out.iterdir())).read_bytes() == PNG_DATA
    print("1. run_pipeline happy path + progress_cb OK")

    with tempfile.TemporaryDirectory() as tmp:
        try:
            run_pipeline(Path(tmp) / "nope", Path(tmp) / "out", None)
            raise AssertionError("missing tdata not rejected")
        except TDataNotFoundError:
            pass
        tdata = make_fake_tdata(
            Path(tmp),
            LOCAL_KEY,
            cache_files={"a1b2": make_tdef(LOCAL_KEY, PNG_DATA)},
            passcode=b"test1234",
        )
        try:
            run_pipeline(tdata, Path(tmp) / "out2", "wrong")
            raise AssertionError("wrong password not rejected")
        except DecryptionError:
            pass
    print("2. run_pipeline error paths OK")


def test_gui_smoke():
    """GUI 冒烟：无显示环境时降级为 import 检查并明确标注。"""
    try:
        from tg_scoop import gui

        # 弹窗在自动化中会阻塞，替换为静默桩
        gui.messagebox.showinfo = lambda *a, **k: None
        gui.messagebox.showerror = lambda *a, **k: None
        app = gui.ScoopApp()
    except Exception as exc:  # 无显示环境（TclError 等）
        print(f"3. GUI smoke SKIPPED（无法创建窗口: {exc}）；需人工跑一次 tg-scoop-gui")
        return

    try:
        app.withdraw()
        with tempfile.TemporaryDirectory() as tmp:
            tdata = make_fake_tdata(
                Path(tmp),
                LOCAL_KEY,
                cache_files={"a1b2": make_tdef(LOCAL_KEY, PNG_DATA)},
            )
            out = Path(tmp) / "out"
            app._tdata_var.set(str(tdata))
            app._output_var.set(str(out))
            app._start_extraction()

            deadline = time.time() + 30
            while time.time() < deadline:
                app.update()  # 手动泵事件循环（替代 mainloop）
                if str(app._start_button.cget("state")) == "normal":
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("extraction did not finish within 30s")

            assert "成功 1" in app._stats_var.get(), app._stats_var.get()
            outputs = list(out.iterdir())
            assert len(outputs) == 1 and outputs[0].read_bytes() == PNG_DATA
            assert app._start_button.cget("state") == "normal"  # 按钮已恢复
        print("3. GUI smoke (worker->queue->UI pump) OK")
    finally:
        app.destroy()


def main():
    test_run_pipeline()
    test_gui_smoke()
    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

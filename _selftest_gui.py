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
from tg_scoop.extractor import ExtractionStats
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
        assert (next(p for p in out.iterdir() if p.suffix == ".png")).read_bytes() == PNG_DATA
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
        gui.messagebox.askyesno = lambda *a, **k: False
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
            outputs = [p for p in out.iterdir() if p.name != "manifest.json"]
            assert len(outputs) == 1 and outputs[0].read_bytes() == PNG_DATA
            assert app._start_button.cget("state") == "normal"  # 按钮已恢复
            assert app._progress_bar.get() == 1  # 完成时进度条拉满
        print("3. GUI smoke (worker->queue->UI pump) OK")
    finally:
        app.destroy()


def test_gui_progress_and_cancel():
    """进度/取消冒烟：桩 run_pipeline 投 _MSG_PROGRESS，断言进度条与按钮态。

    不做真提取（保持冒烟性质）：run_pipeline 替换为原地回调的桩。
    """
    try:
        from tg_scoop import gui

        gui.messagebox.showinfo = lambda *a, **k: None
        gui.messagebox.showerror = lambda *a, **k: None
        gui.messagebox.askyesno = lambda *a, **k: False
        app = gui.ScoopApp()
    except Exception as exc:  # 无显示环境（TclError 等）
        print(f"4. progress/cancel smoke SKIPPED（无法创建窗口: {exc}）")
        return

    def fake_run_pipeline(tdata_path, output_dir, password, **kwargs):
        cb = kwargs["file_progress_cb"]
        cb(1, 2)  # worker 侧逐文件回调 -> _MSG_PROGRESS 入队
        cb(2, 2)
        assert kwargs["cancel_event"] is not None
        return ExtractionStats(succeeded=2)

    try:
        app.withdraw()
        gui.run_pipeline = fake_run_pipeline
        app._start_extraction()

        deadline = time.time() + 10
        while time.time() < deadline:
            app.update()
            if str(app._start_button.cget("state")) == "normal":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("stub run did not finish within 10s")

        assert app._progress_bar.get() == 1, app._progress_bar.get()
        assert str(app._open_button.cget("state")) == "normal"
        assert str(app._export_button.cget("state")) == "normal"
        assert str(app._cancel_button.cget("state")) == "disabled"

        # 取消按钮路径：新一轮开始后可点，点击仅置位事件
        app._start_extraction()
        assert str(app._cancel_button.cget("state")) == "normal"
        app._cancel()
        assert app._cancel_event.is_set()
        deadline = time.time() + 10
        while time.time() < deadline:
            app.update()
            if str(app._start_button.cget("state")) == "normal":
                break
            time.sleep(0.05)
        print("4. progress bar + cancel event smoke OK")
    finally:
        app.destroy()


def main():
    test_run_pipeline()
    test_gui_smoke()
    test_gui_progress_and_cancel()
    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

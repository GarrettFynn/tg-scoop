"""Telegram 进程运行检测测试（A-04）。

覆盖 find_running_telegram 的三态（命中 / 未命中 / 检测异常）
与 run_pipeline 集成：命中时日志含醒目警告且提取流程不中断。
"""

import os
import subprocess

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop import process_check
from tg_scoop.cli import run_pipeline

_LOCAL_KEY = os.urandom(256)
_PNG_DATA = b"\x89PNG\r\n\x1a\n" + os.urandom(500)


def _patch_windows(monkeypatch):
    """把平台固定为 Windows，使三态单测跨平台走同一条 tasklist 分支。"""
    monkeypatch.setattr(process_check.platform, "system", lambda: "Windows")


def test_find_running_telegram_hit(monkeypatch):
    """命中：tasklist 输出含 Telegram.exe -> 返回进程名。"""
    _patch_windows(monkeypatch)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0, stdout="Telegram.exe                 1234 Console"
        )

    monkeypatch.setattr(process_check.subprocess, "run", fake_run)
    assert process_check.find_running_telegram() == "Telegram.exe"


def test_find_running_telegram_miss(monkeypatch):
    """未命中：tasklist 输出无匹配行 -> None。"""
    _patch_windows(monkeypatch)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0], 0, stdout="INFO: No tasks are running which match"
        )

    monkeypatch.setattr(process_check.subprocess, "run", fake_run)
    assert process_check.find_running_telegram() is None


def test_find_running_telegram_error(monkeypatch):
    """检测异常（命令不存在 / 权限 / 超时）一律返回 None，不向上抛。"""
    _patch_windows(monkeypatch)

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("tasklist not found")

    monkeypatch.setattr(process_check.subprocess, "run", fake_run)
    assert process_check.find_running_telegram() is None


def test_run_pipeline_warns_when_telegram_running(tmp_path, monkeypatch):
    """run_pipeline 集成：命中时日志含警告行，提取流程不中断。"""
    monkeypatch.setattr(
        process_check, "find_running_telegram", lambda: "Telegram.exe"
    )
    tdata = make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    lines: list[str] = []
    stats = run_pipeline(tdata, out, None, progress_cb=lines.append)
    assert stats.succeeded == 1
    assert any(
        "警告：检测到 Telegram Desktop 正在运行（进程 Telegram.exe）" in line
        for line in lines
    )
    assert next(p for p in out.iterdir() if p.suffix == ".png").read_bytes() == _PNG_DATA

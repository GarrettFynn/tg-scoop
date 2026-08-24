"""Telegram Desktop 运行状态检测（提示性质，永不阻断主流程）。

用户最高频翻车场景是"忘了完全退出 Telegram"：缓存可能仍处于
写入中状态。提取前检测一次并在命中时给出醒目警告，但是否继续
由用户承担——只读操作不会损坏 tdata。任何检测失败（命令不存在、
权限不足、超时）都按"未运行"处理，绝不影响提取流程。
"""

import platform
import subprocess

# 子进程超时上限（秒）：检测是提示性质，不允许拖慢主流程
_TIMEOUT = 5


def _pgrep_hit(name: str) -> bool:
    """pgrep -x 精确匹配进程名，returncode==0 视为命中。"""
    result = subprocess.run(
        ["pgrep", "-x", name],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
        check=False,
    )
    return result.returncode == 0


def find_running_telegram() -> str | None:
    """检测 Telegram Desktop 进程是否正在运行。

    Returns:
        运行中的进程名（如 ``Telegram.exe``）；未运行或检测失败
        （命令不存在、权限不足、超时等任何异常）返回 None。
    """
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq Telegram.exe", "/NH"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_TIMEOUT,
                check=False,
            )
            if "Telegram.exe" in result.stdout:
                return "Telegram.exe"
        elif system == "Darwin":
            if _pgrep_hit("Telegram"):
                return "Telegram"
        else:  # Linux 及其他：两种常见进程名依次试
            for name in ("telegram-desktop", "Telegram"):
                if _pgrep_hit(name):
                    return name
    except (OSError, subprocess.SubprocessError):
        pass
    return None

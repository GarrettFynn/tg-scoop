"""硬件检测与并行档位推荐（C-02）。

检测是提示性质：任何异常都按"未知"处理，永不阻断主流程。
仅标准库，无第三方依赖。
"""

import os
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class HardwareInfo:
    """检测结果；未知字段为 None。"""

    cores: int | None
    ram_gb: float | None


def _detect_ram_gb() -> float | None:
    """读取物理内存总量（GB），任何失败返回 None。"""
    try:
        if sys.platform == "win32":
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return None
            return stat.ullTotalPhys / (1 << 30)
        if sys.platform == "darwin":
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return int(out.stdout.strip()) / (1 << 30)
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1 << 20)  # kB -> GB
        return None
    except Exception:  # noqa: BLE001 —— 检测是提示性质，任何异常都按未知处理
        return None


def detect_hardware() -> HardwareInfo:
    """检测 CPU 核数与内存；失败字段为 None，永不抛异常。"""
    try:
        cores = os.cpu_count()
    except Exception:  # noqa: BLE001 —— 同上，检测失败按未知处理
        cores = None
    return HardwareInfo(cores=cores, ram_gb=_detect_ram_gb())


def recommended_jobs(info: HardwareInfo) -> int:
    """推荐并行进程数：min(cores-1, 8)；低内存（<4GB）收敛到 2；保底 1。"""
    if not info.cores or info.cores <= 1:
        return 1
    jobs = max(1, min(info.cores - 1, 8))
    if info.ram_gb is not None and info.ram_gb < 4:
        jobs = min(2, jobs)
    return jobs

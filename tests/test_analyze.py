"""只读缓存清理建议报告测试（C-11）。

覆盖：Top-N/最旧排序与统计口径、只读无副作用（不写 tdata、
不建输出目录、不产生 manifest）。
"""

import os
from pathlib import Path

from tests.fixtures import make_fake_tdata
from tg_scoop.cli import EXIT_OK, analyze_cache, main

_LOCAL_KEY = os.urandom(256)


def _make_sized_tdata(tmp_path: Path) -> Path:
    """合成 5 个已知大小/mtime 的缓存文件（内容无关紧要，不解密）。"""
    tdata = make_fake_tdata(tmp_path, _LOCAL_KEY, cache_files={})
    cache = tdata / "user_data" / "cache"
    specs = {  # name: (size, mtime 距今秒数)
        "big_old": (5000, 86400 * 5),
        "big_new": (5000, 60),
        "mid": (2000, 86400 * 3),
        "small_oldest": (100, 86400 * 9),
        "tiny": (10, 3600),
    }
    now = 1_800_000_000.0  # 固定基准，避免测试依赖真实时钟
    for name, (size, age) in specs.items():
        p = cache / name
        p.write_bytes(os.urandom(size))
        ts = now - age
        os.utime(p, (ts, ts))
    return tdata


def test_analyze_sorting_and_stats(tmp_path):
    """排序与口径：Top 按大小降序、最旧按 mtime 升序、总数正确。"""
    tdata = _make_sized_tdata(tmp_path)
    lines: list[str] = []
    analyze_cache(tdata, log=lines.append)

    text = "\n".join(lines)
    assert "文件数：5" in text
    total = 5000 + 5000 + 2000 + 100 + 10
    assert f"缓存总大小：{total} 字节" in text
    assert "tg-scoop 不删除任何 tdata 内文件" in text

    top_idx = text.index("占空间 Top 20：")
    old_idx = text.index("最旧 20 个：")
    top_section = text[top_idx:old_idx]
    old_section = text[old_idx:]
    # Top：两个 5000 在前（big_old 更旧排前），然后 mid
    assert top_section.index("big_old") < top_section.index("big_new")
    assert top_section.index("big_new") < top_section.index("mid")
    # 最旧：small_oldest 第一
    first_line = old_section.splitlines()[1]
    assert "small_oldest" in first_line


def test_analyze_no_side_effects(tmp_path):
    """只读契约：tdata 内容不变、不建输出目录、不产生 manifest。"""
    tdata = _make_sized_tdata(tmp_path)
    before = {
        str(p.relative_to(tdata)): p.read_bytes()
        for p in tdata.rglob("*")
        if p.is_file()
    }
    out_dir = tmp_path / "tg-scoop-output"  # 缺省输出目录不得被创建

    code = main(["--analyze", "--tdata-path", str(tdata)])
    assert code == EXIT_OK

    after = {
        str(p.relative_to(tdata)): p.read_bytes()
        for p in tdata.rglob("*")
        if p.is_file()
    }
    assert before == after
    assert not out_dir.exists()
    assert not list(tdata.rglob("manifest.json"))

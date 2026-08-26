"""原始文件名命名与 --chat-id 转正测试（B-07；DEVELOPMENT.md §6.1）。

红线：name_map 确定性 -> 凭据路径重跑全重复无覆盖；默认路径
（无映射）与现状逐字节一致。全部本地合成，不连网络。
"""

import json
import os
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import run_pipeline

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"


def _make_sharded_tdata(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """合成版本/分片结构的缓存：cache/1/<shard>/<leaf>（对齐 binlog 布局）。"""
    tdata = make_fake_tdata(tmp_path, _LOCAL_KEY, cache_files={})
    cache = tdata / "user_data" / "cache"
    for rel, raw in files.items():  # rel 形如 "A5/5B40637E62FA"
        p = cache / "1" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    return tdata


def _png_file(name: str) -> bytes:
    return make_tdef(_LOCAL_KEY, _PNG + os.urandom(200))


def _names(out: Path) -> list[str]:
    return sorted(
        str(p.relative_to(out).as_posix())
        for p in out.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    )


def test_original_name_and_sanitization(tmp_path):
    """原始名命名：name_map 命中 -> 净化后的原始文件名（非法字符回归）。"""
    rel = "A5/5B40637E62FA"
    tdata = _make_sharded_tdata(tmp_path, {rel: _png_file("a")})
    out = tmp_path / "out"
    stats = run_pipeline(
        tdata, out, None, name_map={rel: '报告<2026>:"最终"|?.png'}
    )
    assert stats.succeeded == 1
    assert _names(out) == ["报告_2026___最终___.png"]
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert doc["entries"][0]["file_name"] == "报告_2026___最终___.png"


def test_sender_fallback_name(tmp_path):
    """sender 接入：命中但无原始名 -> 降级名含真实 sender（不再 unknown）。"""
    rel = "B0/112233445566"
    tdata = _make_sharded_tdata(tmp_path, {rel: _png_file("b")})
    out = tmp_path / "out"
    run_pipeline(tdata, out, None, sender_map={rel: "Alice"})
    (name,) = _names(out)
    assert name.startswith("Alice_")


def test_p3_needs_review(tmp_path):
    """P3 落 needs-review：文件在 needs-review/ 且 manifest file_name 反映路径。"""
    rel = "C1/CAFEBABE1234"
    tdata = _make_sharded_tdata(tmp_path, {rel: _png_file("c")})
    out = tmp_path / "out"
    run_pipeline(tdata, out, None, needs_review={rel})
    (name,) = _names(out)
    assert name.startswith("needs-review/")
    assert name.endswith(".png")
    doc = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert doc["entries"][0]["file_name"] == name


def test_idempotent_rerun_with_name_map(tmp_path):
    """幂等红线：同 name_map 重跑 -> 全重复、无覆盖、文件集合不变。"""
    rel = "A5/5B40637E62FA"
    tdata = _make_sharded_tdata(tmp_path, {rel: _png_file("a")})
    out = tmp_path / "out"
    run_pipeline(tdata, out, None, name_map={rel: "final.png"})
    first = _names(out)
    stats2 = run_pipeline(tdata, out, None, name_map={rel: "final.png"})
    assert stats2.succeeded == 0 and stats2.duplicates == 1
    assert _names(out) == first  # 无 " (1)" 副本、无覆盖


def test_default_path_unchanged(tmp_path):
    """默认路径：无映射 -> 降级名 unknown_sender、落输出根目录（现状一致）。"""
    rel = "A5/5B40637E62FA"
    tdata = _make_sharded_tdata(tmp_path, {rel: _png_file("a")})
    out = tmp_path / "out"
    stats = run_pipeline(tdata, out, None)
    assert stats.succeeded == 1
    (name,) = _names(out)
    assert name.startswith("unknown_")
    assert "/" not in name


def test_partial_mapping_falls_back(tmp_path):
    """--chat-id 过滤单测：映射只含目标聊天文档；未命中条目走降级名。"""
    rel_hit = "A5/5B40637E62FA"
    rel_miss = "B0/998877665544"
    tdata = _make_sharded_tdata(
        tmp_path, {rel_hit: _png_file("h"), rel_miss: _png_file("m")}
    )
    out = tmp_path / "out"
    stats = run_pipeline(tdata, out, None, name_map={rel_hit: "命中.png"})
    assert stats.succeeded == 2
    names = _names(out)
    assert "命中.png" in names
    assert any(n.startswith("unknown_") for n in names)  # 未命中走降级名

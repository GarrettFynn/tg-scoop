"""诊断脚本冒烟（P0-11 规格：subprocess 真实跑 scripts/diagnose_tdata.py）。

覆盖报告格式契约的四段标记词（PASS / FAIL / 结论行）与敏感数据
不外泄（auth_key 本体不得出现在 stdout）。
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.fixtures import make_fake_tdata, make_mtp_auth_file, make_tdef
from tg_scoop.tdata_reader import compute_data_name_key

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "diagnose_tdata.py"
_PNG = b"\x89PNG\r\n\x1a\n"


def _make_tdata(tmp_path: Path, with_mtp: bool = True) -> tuple[Path, bytes]:
    """合成含双缓存目录（各 1 好 1 坏）与 MTP 文件的假 tdata。"""
    local_key = os.urandom(256)
    auth_key = os.urandom(256)
    png = _PNG + os.urandom(200)
    tdata = make_fake_tdata(
        tmp_path,
        local_key,
        cache_files={
            "good": make_tdef(local_key, png),
            "broken": os.urandom(200),  # 损坏 -> 解密失败
        },
        media_cache_files={"good2": make_tdef(local_key, png)},
    )
    if with_mtp:
        (tdata / compute_data_name_key("data")).write_bytes(
            make_mtp_auth_file(local_key, 12345678901234, 2, auth_key)
        )
    return tdata, auth_key


def _run(tdata: Path, *extra: str) -> subprocess.CompletedProcess:
    """以仓库根为 cwd 真实运行诊断脚本，extra 为追加的命令行参数。"""
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(tdata), *extra],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",  # 子进程以 PYTHONIOENCODING 锁定 UTF-8，父进程同步按 UTF-8 解码
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=60,
        check=False,
    )


def test_diagnose_all_pass(tmp_path):
    """全 PASS 路径：退出码 0，四段标记词齐全，敏感数据不外泄。"""
    tdata, auth_key = _make_tdata(tmp_path)
    result = _run(tdata)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[1] key 链: PASS" in result.stdout
    assert "[2] MTP 授权: PASS" in result.stdout
    assert "[3] 缓存抽样: PASS" in result.stdout
    assert "全部格式假设成立" in result.stdout
    assert auth_key.hex() not in result.stdout


def test_diagnose_missing_mtp_auth(tmp_path):
    """缺 MTP 文件：[2] FAIL、结论含"发回主脑"、退出码 1。"""
    tdata, auth_key = _make_tdata(tmp_path, with_mtp=False)
    result = _run(tdata)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "[1] key 链: PASS" in result.stdout
    assert "[2] MTP 授权: FAIL" in result.stdout
    assert "发回主脑" in result.stdout
    assert auth_key.hex() not in result.stdout


def test_diagnose_json_all_pass(tmp_path):
    """--json 全 PASS：stdout 可被 json.loads，字段齐全且三段 verdict 全 PASS。"""
    tdata, auth_key = _make_tdata(tmp_path)
    result = _run(tdata, "--json")
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["tdata_path"] == str(tdata)
    assert report["exit_code"] == 0
    assert report["conclusion"] == "全部格式假设成立"
    assert [section["id"] for section in report["sections"]] == [1, 2, 3]
    for section in report["sections"]:
        assert set(section) == {"id", "name", "verdict", "detail"}
        assert section["verdict"] == "PASS"
    assert auth_key.hex() not in result.stdout


def test_diagnose_json_missing_mtp_auth(tmp_path):
    """--json 缺 MTP：sections[1].verdict == FAIL、exit_code 1、进程退出码 1。"""
    tdata, _auth_key = _make_tdata(tmp_path, with_mtp=False)
    result = _run(tdata, "--json")
    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["sections"][1]["verdict"] == "FAIL"
    assert report["exit_code"] == 1

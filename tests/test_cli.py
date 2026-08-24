"""CLI 与共享管道测试（P0-11 移植自 _selftest_cli.py 检查 1–4
与 _selftest_gui.py 的 run_pipeline 部分）。

覆盖点对应 DEVELOPMENT.md §7.2（退出码）与 §11.3（run_pipeline 契约）。
直接调用 cli.main(argv) / run_pipeline(...)，不捕获 print 输出、
不断言 stdout 文本。
"""

import os

import pytest

from tests.fixtures import make_fake_tdata, make_tdef
from tg_scoop.cli import (
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_PASSWORD,
    main,
    run_pipeline,
)
from tg_scoop.exceptions import DecryptionError, TDataNotFoundError

_LOCAL_KEY = os.urandom(256)
_PNG_DATA = b"\x89PNG\r\n\x1a\n" + os.urandom(500)
_MP4_DATA = b"\x00\x00\x00\x18ftypisom" + os.urandom(500)


def test_end_to_end_dual_cache_dirs(tmp_path):
    """cache + media_cache 双目录：跨目录去重只落盘一次，退出码 0。"""
    tdata = make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={
            "a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA),
            "c3d4": make_tdef(_LOCAL_KEY, _MP4_DATA),
            "broken": os.urandom(200),  # 损坏 -> failed
        },
        media_cache_files={"e5f6": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    code = main(["--tdata-path", str(tdata), "--output-dir", str(out)])
    assert code == EXIT_OK
    outputs = list(out.iterdir())
    # media_cache 中的文件与 cache 内容相同 -> 跨目录去重，只落盘一次
    assert len(outputs) == 2
    contents = [p.read_bytes() for p in outputs]
    assert _MP4_DATA in contents
    assert contents.count(_PNG_DATA) == 1


def test_password_paths(tmp_path):
    """错误密码 -> 退出码 3；正确密码 -> 退出码 0。"""
    tdata = make_fake_tdata(
        tmp_path,
        _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
        passcode=b"test1234",
    )
    out = tmp_path / "out"
    code = main(
        ["--tdata-path", str(tdata), "--output-dir", str(out),
         "--password", "wrong"]
    )
    assert code == EXIT_PASSWORD
    code = main(
        ["--tdata-path", str(tdata), "--output-dir", str(out),
         "--password", "test1234"]
    )
    assert code == EXIT_OK


def test_missing_tdata_exit_2(tmp_path):
    """tdata 不存在 -> 退出码 2。"""
    code = main(["--tdata-path", str(tmp_path / "nope")])
    assert code == EXIT_NOT_FOUND


def test_chat_id_reserved_warning(tmp_path):
    """--chat-id 警告并忽略：退出码 0 且结果不受影响。"""
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    code = main(["--tdata-path", str(tdata), "--output-dir", str(out),
                 "--chat-id", "12345"])
    assert code == EXIT_OK
    assert len(list(out.iterdir())) == 1


def test_run_pipeline_happy_path(tmp_path):
    """run_pipeline：统计正确 + progress_cb 收到日志行 + 内容还原。"""
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
    )
    out = tmp_path / "out"
    lines: list[str] = []
    stats = run_pipeline(tdata, out, None, progress_cb=lines.append)
    assert stats.succeeded == 1 and stats.failed == 0
    assert any("LocalKey" in line for line in lines)
    assert next(out.iterdir()).read_bytes() == _PNG_DATA


def test_run_pipeline_error_paths(tmp_path):
    """run_pipeline：missing tdata 抛 TDataNotFoundError；错误密码抛 DecryptionError。"""
    with pytest.raises(TDataNotFoundError):
        run_pipeline(tmp_path / "nope", tmp_path / "out", None)
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        cache_files={"a1b2": make_tdef(_LOCAL_KEY, _PNG_DATA)},
        passcode=b"test1234",
    )
    with pytest.raises(DecryptionError):
        run_pipeline(tdata, tmp_path / "out2", "wrong")

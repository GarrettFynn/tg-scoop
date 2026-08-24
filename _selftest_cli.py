"""cli 端到端自测：完整假 tdata -> cli.main() -> 输出与退出码断言。

运行：
    .venv/Scripts/python _selftest_cli.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from _selftest_common import make_fake_tdata, make_tdef

from tg_scoop.cli import (
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_PASSWORD,
    main,
)
from tg_scoop.media_detector import PNG_MAGIC

LOCAL_KEY = os.urandom(256)
PNG_DATA = PNG_MAGIC + os.urandom(500)
MP4_DATA = b"\x00\x00\x00\x18ftypisom" + os.urandom(500)


def run(argv):
    """调用 CLI 并返回退出码。"""
    return main(argv)


def main_():
    # 1. 端到端：无密码 tdata，cache + media_cache 双目录
    with tempfile.TemporaryDirectory() as tmp:
        tdata = make_fake_tdata(
            Path(tmp),
            LOCAL_KEY,
            cache_files={
                "a1b2": make_tdef(LOCAL_KEY, PNG_DATA),
                "c3d4": make_tdef(LOCAL_KEY, MP4_DATA),
                "broken": os.urandom(200),  # 损坏 -> failed
            },
            media_cache_files={"e5f6": make_tdef(LOCAL_KEY, PNG_DATA)},
        )
        out = Path(tmp) / "out"
        code = run(["--tdata-path", str(tdata), "--output-dir", str(out)])
        assert code == EXIT_OK, code
        outputs = list(out.iterdir())
        # media_cache 中的文件与 cache 内容相同 -> 跨目录去重，只落盘一次
        assert len(outputs) == 2, outputs
        contents = [p.read_bytes() for p in outputs]
        assert MP4_DATA in contents
        assert contents.count(PNG_DATA) == 1

    print("1. end-to-end (cache + media_cache) OK" )

    # 2. 密码错误 -> 退出码 3
    with tempfile.TemporaryDirectory() as tmp:
        tdata = make_fake_tdata(
            Path(tmp),
            LOCAL_KEY,
            cache_files={"a1b2": make_tdef(LOCAL_KEY, PNG_DATA)},
            passcode=b"test1234",
        )
        out = Path(tmp) / "out"
        code = run(
            ["--tdata-path", str(tdata), "--output-dir", str(out),
             "--password", "wrong"]
        )
        assert code == EXIT_PASSWORD, code
        # 密码正确 -> 0
        code = run(
            ["--tdata-path", str(tdata), "--output-dir", str(out),
             "--password", "test1234"]
        )
        assert code == EXIT_OK, code
    print("2. password paths (wrong -> 3, right -> 0) OK")

    # 3. tdata 不存在 -> 退出码 2
    with tempfile.TemporaryDirectory() as tmp:
        code = run(["--tdata-path", str(Path(tmp) / "nope")])
        assert code == EXIT_NOT_FOUND, code
    print("3. missing tdata -> exit 2 OK")

    # 4. --chat-id 警告并忽略，不影响结果
    with tempfile.TemporaryDirectory() as tmp:
        tdata = make_fake_tdata(
            Path(tmp), LOCAL_KEY,
            cache_files={"a1b2": make_tdef(LOCAL_KEY, PNG_DATA)},
        )
        out = Path(tmp) / "out"
        code = run(["--tdata-path", str(tdata), "--output-dir", str(out),
                    "--chat-id", "12345"])
        assert code == EXIT_OK and len(list(out.iterdir())) == 1
    print("4. --chat-id reserved warning OK")

    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main_()

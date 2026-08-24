"""自测共享脚手架（兼容层，P0-11 起）。

fixture 构造函数已迁移至 tests/fixtures/（DEVELOPMENT.md §9.1）。
本模块仅做再导出，保证 6 套 _selftest_*.py 不经修改继续运行。
新代码请直接引用 tests.fixtures。
"""

import sys

sys.path.insert(0, "src")

from tests.fixtures import (
    ctr_encrypt,
    encrypt_local,
    ige_encrypt,
    make_fake_tdata,
    make_key_datas,
    make_tdef,
    qt_bytes,
    wrap_tdf,
    xor,
)

__all__ = [
    "ctr_encrypt",
    "encrypt_local",
    "ige_encrypt",
    "make_fake_tdata",
    "make_key_datas",
    "make_tdef",
    "qt_bytes",
    "wrap_tdf",
    "xor",
]

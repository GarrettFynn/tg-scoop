"""加密 fixture 构造函数（DEVELOPMENT.md §9.1 策略落地）。

所有函数都是 src/tg_scoop 解密路径的逆运算，用于把已知明文
加密成合法的 TDF$/TDEF/key_datas 结构。自 _selftest_common.py
迁入（P0-11），为全仓唯一 fixture 来源。
"""

from tests.fixtures.make_tdata import (
    ctr_encrypt,
    encrypt_local,
    ige_encrypt,
    make_fake_tdata,
    make_key_datas,
    make_mtp_auth_file,
    make_mtp_auth_file_s,
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
    "make_mtp_auth_file",
    "make_mtp_auth_file_s",
    "make_tdef",
    "qt_bytes",
    "wrap_tdf",
    "xor",
]

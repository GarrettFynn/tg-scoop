"""tdata_reader 往返自测：构造合成 key_datas -> 读回 LocalKey/账号索引。

用共享脚手架（_selftest_common）的逆运算构造加密 fixture
（与 DEVELOPMENT.md §9.1 的 fixture 策略一致），验证解密链路能
还原已知明文。运行：
    .venv/Scripts/python _selftest_tdata.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from _selftest_common import (
    ctr_encrypt,
    ige_encrypt,
    encrypt_local,
    make_key_datas,
    qt_bytes,
    wrap_tdf,
)

from tg_scoop.exceptions import CorruptedDataError, DecryptionError
from tg_scoop.tdata_reader import (
    QtStreamReader,
    TdataReader,
    aes_ige_decrypt,
    compute_data_name_key,
    create_local_key,
    decrypt_local,
    parse_tdf,
)


def main():
    # 1. IGE 加解密往返
    key, iv = os.urandom(32), os.urandom(32)
    plain = os.urandom(64)
    assert aes_ige_decrypt(ige_encrypt(plain, key, iv), key, iv) == plain
    print("1. aes_ige_decrypt roundtrip OK")

    # 2. decrypt_local 往返 + 错误密钥拒绝
    lkey = os.urandom(256)
    blob = b"hello local encryption"
    enc = encrypt_local(blob, lkey)
    assert decrypt_local(enc, lkey) == blob
    try:
        decrypt_local(enc, os.urandom(256))
        raise AssertionError("wrong key not rejected")
    except DecryptionError as e:
        assert "checksum" in str(e)
    print("2. decrypt_local roundtrip + wrong-key rejection OK")

    # 3. 合成 key_datas -> TdataReader 完整链路
    real_local_key = os.urandom(256)
    tdf_bytes = make_key_datas(real_local_key, os.urandom(32))
    with tempfile.TemporaryDirectory() as tmp:
        tdata = Path(tmp)
        (tdata / "key_datas").write_bytes(tdf_bytes)
        reader = TdataReader(tdata)
        got = reader.read_local_key("")
        assert got == real_local_key, "LocalKey mismatch"
        assert reader.read_account_indexes(got) == [0]
    print("3. TdataReader.read_local_key + read_account_indexes OK")

    # 4. QtStreamReader：大端 + null 标记 + 截断
    r = QtStreamReader(b"\x00\x00\x00\x2a" + b"\xff\xff\xff\xff")
    assert r.read_int32() == 42  # 大端
    assert r.read_bytes() == b""  # null QByteArray
    try:
        QtStreamReader(b"\x00\x00\x00\x10ab").read_bytes()
        raise AssertionError("truncated read not rejected")
    except CorruptedDataError as e:
        assert "truncated" in str(e)
    print("4. QtStreamReader OK")

    # 5. parse_tdf 拒绝篡改
    good = parse_tdf(tdf_bytes)
    assert good.version == 0
    bad = bytearray(tdf_bytes)
    bad[20] ^= 0x01
    try:
        parse_tdf(bytes(bad))
        raise AssertionError("tampered TDF not rejected")
    except CorruptedDataError as e:
        assert "checksum" in str(e)
    print("5. parse_tdf MD5 verification OK")

    # 6. compute_data_name_key 已知值（"data" -> md5 前 8 字节半字节互换）
    assert compute_data_name_key("data") == "D877F783D5D3EF8C"
    print("6. compute_data_name_key OK")

    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

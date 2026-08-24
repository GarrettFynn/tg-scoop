"""cache_decryptor 往返自测：构造合成 TDEF -> 解密还原已知明文。

加密 fixture 来自共享脚手架 _selftest_common（DEVELOPMENT.md §9.1
策略）。运行：
    .venv/Scripts/python _selftest_cache.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from _selftest_common import ctr_encrypt, make_tdef

from tg_scoop.cache_decryptor import (
    CacheDecryptor,
    CtrDecryptor,
    decrypt_storage_file,
    derive_storage_key_iv,
    iter_cache_files,
)
from tg_scoop.exceptions import CacheNotFoundError, DecryptionError

LOCAL_KEY = os.urandom(256)
MEDIA = os.urandom(1024)  # 1KB，整块
MEDIA_ODD = os.urandom(1000)  # 非整块尾包


def main():
    # 1. CtrDecryptor：分块 == 一次性（计数器连续性对拍）
    key, iv = os.urandom(32), os.urandom(16)
    data = os.urandom(160)
    one_pass = CtrDecryptor(key, iv).decrypt(ctr_encrypt(data, key, iv))
    d = CtrDecryptor(key, iv)
    ct = ctr_encrypt(data, key, iv)
    chunked = d.decrypt(ct[:48]) + d.decrypt(ct[48:112]) + d.decrypt(ct[112:])
    assert one_pass == chunked == data
    print("1. CtrDecryptor chunked == single-pass OK")

    # 2. CtrDecryptor：尾包后禁止继续（防计数器错位）
    d = CtrDecryptor(key, iv)
    d.decrypt(ctr_encrypt(b"x" * 8, key, iv))
    try:
        d.decrypt(b"y" * 16)
        raise AssertionError("post-finalized decrypt not rejected")
    except DecryptionError as e:
        assert "finalized" in str(e)
    print("2. CtrDecryptor finalization guard OK")

    # 3. TDEF 完整往返（整块 + 非整块尾包）
    for media in (MEDIA, MEDIA_ODD):
        raw = make_tdef(LOCAL_KEY, media)
        assert decrypt_storage_file(raw, LOCAL_KEY) == media
    print("3. decrypt_storage_file roundtrip (aligned + partial tail) OK")

    # 4. 错误密钥 / 篡改校验块 / 非 TDEF / 截断
    raw = make_tdef(LOCAL_KEY, MEDIA)
    try:
        decrypt_storage_file(raw, os.urandom(256))
        raise AssertionError("wrong key not rejected")
    except DecryptionError as e:
        assert "wrong key" in str(e)
    bad = bytearray(raw)
    bad[80] ^= 0x01  # 篡改校验块
    try:
        decrypt_storage_file(bytes(bad), LOCAL_KEY)
        raise AssertionError("tampered check block not rejected")
    except DecryptionError:
        pass
    for bad_raw in (b"NOPE" + raw[4:], raw[:100]):
        try:
            decrypt_storage_file(bad_raw, LOCAL_KEY)
            raise AssertionError("invalid input not rejected")
        except DecryptionError:
            pass
    print("4. wrong-key / tampered / non-TDEF / truncated rejection OK")

    # 5. iter_cache_files：跳过元数据、目录不存在、空目录
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "cache"
        (cache / "sub").mkdir(parents=True)
        (cache / "a1b2").write_bytes(b"x")
        (cache / "sub" / "c3d4").write_bytes(b"y")
        for skip in ("version", "binlog", "map0", "map1"):
            (cache / skip).write_bytes(b"z")
        found = [p.name for p in iter_cache_files(cache)]
        assert found == ["a1b2", "c3d4"], found
        try:
            list(iter_cache_files(Path(tmp) / "nonexistent"))
            raise AssertionError("missing dir not rejected")
        except CacheNotFoundError:
            pass
        empty = Path(tmp) / "empty"
        empty.mkdir()
        try:
            list(iter_cache_files(empty))
            raise AssertionError("empty dir not rejected")
        except CacheNotFoundError:
            pass
    print("5. iter_cache_files OK")

    # 6. CacheDecryptor：短密钥拒绝、批量容错、异常带路径
    try:
        CacheDecryptor(b"short")
        raise AssertionError("short local_key not rejected")
    except DecryptionError:
        pass
    dec = CacheDecryptor(LOCAL_KEY)
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp)
        (cache / "good").write_bytes(make_tdef(LOCAL_KEY, MEDIA))
        (cache / "bad").write_bytes(os.urandom(200))  # 非 TDEF
        results = dict(dec.decrypt_all(cache))
        assert list(results) == [cache / "good"]
        assert results[cache / "good"] == MEDIA
        try:
            dec.decrypt_file(cache / "bad")
            raise AssertionError("bad file not rejected")
        except DecryptionError as e:
            assert "bad" in str(e)  # 异常信息带文件路径
    print("6. CacheDecryptor OK")

    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

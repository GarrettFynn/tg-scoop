"""CacheDecryptor 单元测试骨架。

覆盖点对应 DEVELOPMENT.md §9.1：
- CtrDecryptor：跨分块计数器连续性（与整段解密结果一致）
- TDEF 往返：用逆运算加密已知明文构造 fixture，再解密断言相等
- 校验失败路径：错误密钥 / 非 TDEF magic / 损坏数据
- 遍历：跳过 version/binlog/map*，目录不存在抛 CacheNotFoundError
"""

import os

import pytest

from tests.fixtures import ctr_encrypt, make_tdef
from tg_scoop.cache_decryptor import (
    CacheDecryptor,
    CtrDecryptor,
    decrypt_storage_file,
    derive_storage_key_iv,
    iter_cache_files,
)
from tg_scoop.exceptions import CacheNotFoundError, DecryptionError

# 自生成回归字面值（P0-11）：由实现运行一次取得，算法
# SHA256(local_key[:128]+salt[:32]) / SHA256(local_key[128:]+salt[32:])[:16]
# 已人工核对 §3.5。固定输入 local_key=bytes(range(256))、salt=bytes(range(64))。
_DERIVED_KEY = bytes.fromhex(
    "7d716e77dadcc45750c6b258c648ca867917b1f0a74e3e441836b42d10867528"
)
_DERIVED_IV = bytes.fromhex("ba56661258182ca616316b3ccadc920d")


class TestCtrDecryptor:
    """AES-256-CTR 流式解密器。"""

    def test_chunked_equals_single_pass(self):
        """分块解密与一次性解密结果一致（计数器跨调用连续）。"""
        key, iv = os.urandom(32), os.urandom(16)
        data = os.urandom(160)
        ct = ctr_encrypt(data, key, iv)
        assert CtrDecryptor(key, iv).decrypt(ct) == data
        d = CtrDecryptor(key, iv)
        chunked = d.decrypt(ct[:48]) + d.decrypt(ct[48:112]) + d.decrypt(ct[112:])
        assert chunked == data

    def test_counter_continues_across_calls(self):
        """第二次 decrypt 不从计数器 0 重启（keystream 复用防护，§3.5）。"""
        key, iv = os.urandom(32), os.urandom(16)
        d = CtrDecryptor(key, iv)
        d.decrypt(ctr_encrypt(b"x" * 8, key, iv))  # 非整块尾包 -> 流终结
        with pytest.raises(DecryptionError, match="finalized"):
            d.decrypt(b"y" * 16)


class TestDeriveStorageKeyIv:
    """TDEF 密钥派生。"""

    def test_golden_vector(self):
        """固定 local_key + salt 的 key/iv 回归值。"""
        key, iv = derive_storage_key_iv(bytes(range(256)), bytes(range(64)))
        assert key == _DERIVED_KEY
        assert iv == _DERIVED_IV


class TestDecryptStorageFile:
    """TDEF 文件解密。"""

    def test_roundtrip_with_fixture(self):
        """TDEF 加密 fixture -> 解密还原明文。"""
        local_key = os.urandom(256)
        for media in (os.urandom(1024), os.urandom(1000)):  # 整块 + 非整块尾包
            assert decrypt_storage_file(make_tdef(local_key, media), local_key) == media

    def test_not_tdef_raises(self):
        """magic 非 TDEF 抛 DecryptionError。"""
        local_key = os.urandom(256)
        raw = make_tdef(local_key, os.urandom(64))
        with pytest.raises(DecryptionError):
            decrypt_storage_file(b"NOPE" + raw[4:], local_key)

    def test_wrong_key_raises(self):
        """SHA-256 密钥校验失败抛 DecryptionError。"""
        local_key = os.urandom(256)
        raw = make_tdef(local_key, os.urandom(64))
        with pytest.raises(DecryptionError, match="wrong key"):
            decrypt_storage_file(raw, os.urandom(256))
        tampered = bytearray(raw)
        tampered[80] ^= 0x01  # 篡改校验块
        with pytest.raises(DecryptionError):
            decrypt_storage_file(bytes(tampered), local_key)

    def test_truncated_file_raises(self):
        """不足 116 字节的截断文件抛 DecryptionError。"""
        local_key = os.urandom(256)
        raw = make_tdef(local_key, os.urandom(64))
        with pytest.raises(DecryptionError):
            decrypt_storage_file(raw[:100], local_key)


class TestIterCacheFiles:
    """缓存目录遍历。"""

    def test_skips_metadata_files(self, tmp_path):
        """version/binlog/map0/map1 被跳过。"""
        cache = tmp_path / "cache"
        (cache / "sub").mkdir(parents=True)
        (cache / "a1b2").write_bytes(b"x")
        (cache / "sub" / "c3d4").write_bytes(b"y")
        for skip in ("version", "binlog", "map0", "map1"):
            (cache / skip).write_bytes(b"z")
        found = [p.name for p in iter_cache_files(cache)]
        assert found == ["a1b2", "c3d4"]

    def test_missing_dir_raises(self, tmp_path):
        """目录不存在抛 CacheNotFoundError。"""
        with pytest.raises(CacheNotFoundError):
            list(iter_cache_files(tmp_path / "nonexistent"))

    def test_empty_dir_raises(self, tmp_path):
        """空目录抛 CacheNotFoundError。"""
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(CacheNotFoundError):
            list(iter_cache_files(empty))


class TestCacheDecryptor:
    """批量解密编排。"""

    def test_rejects_short_local_key(self):
        """local_key 非 256 字节抛 DecryptionError。"""
        with pytest.raises(DecryptionError):
            CacheDecryptor(b"short")

    def test_decrypt_all_skips_bad_files(self, tmp_path):
        """混入损坏文件时其余文件正常产出（逐文件容错）。"""
        local_key = os.urandom(256)
        media = os.urandom(512)
        (tmp_path / "good").write_bytes(make_tdef(local_key, media))
        (tmp_path / "bad").write_bytes(os.urandom(200))  # 非 TDEF
        dec = CacheDecryptor(local_key)
        results = dict(dec.decrypt_all(tmp_path))
        assert list(results) == [tmp_path / "good"]
        assert results[tmp_path / "good"] == media
        # decrypt_file 异常消息带文件路径
        with pytest.raises(DecryptionError, match="bad"):
            dec.decrypt_file(tmp_path / "bad")

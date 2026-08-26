"""CTR 后端 byte-exact 对拍（C-12；依据 0827-0209 审查报告决策 B）。

新后端 = pycryptodome MODE_CTR；参考实现 = 测试内手写的旧语义
"ECB keystream + 逐块异或"循环（不依赖被替换的旧实现）。
最高红线：逐字节一致；公开契约（构造/校验/decrypt 语义/_finalized）不变。
"""

import hashlib
import os

import pytest

from tests.fixtures import make_tdef
from tests.test_streaming import _write_big_tdef
from tg_scoop.cache_decryptor import CacheDecryptor, CtrDecryptor
from tg_scoop.exceptions import DecryptionError

_KEY = os.urandom(32)
_IV = os.urandom(16)
_PNG = b"\x89PNG\r\n\x1a\n"
_LOCAL_KEY = os.urandom(256)


def _reference_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """旧语义参考实现（手写）：ECB keystream + 大端计数器 + zip 异或。"""
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        block = data[off : off + 16]
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        counter = (counter + 1) % (1 << 128)
        out[off : off + len(block)] = bytes(x ^ y for x, y in zip(block, keystream))
    return bytes(out)


def test_byte_exact_vs_reference():
    """byte-exact：多尺寸输入（含 0B/尾包/跨块）与参考循环逐字节一致。"""
    for size in (0, 1, 15, 16, 17, 1 << 20, (1 << 20) + 1):
        data = os.urandom(size)
        d = CtrDecryptor(_KEY, _IV)
        assert d.decrypt(data) == _reference_ctr(data, _KEY, _IV), f"size={size}"


def test_streaming_continuation(tmp_path):
    """流式续接：分块喂 == 一次性整段；decrypt_file_iter == decrypt_file。"""
    data = os.urandom((1 << 20) * 2 + 17)
    d1 = CtrDecryptor(_KEY, _IV)
    whole = d1.decrypt(data)
    d2 = CtrDecryptor(_KEY, _IV)
    chunked = (
        d2.decrypt(data[: 1 << 20])
        + d2.decrypt(data[1 << 20 : 2 << 20])
        + d2.decrypt(data[2 << 20 :])
    )
    assert chunked == whole == _reference_ctr(data, _KEY, _IV)

    # 集成路径：TDEF 流式 == 全量
    media = _PNG + os.urandom((1 << 20) * 3 + 100)
    p = tmp_path / "t"
    p.write_bytes(make_tdef(_LOCAL_KEY, media))
    dec = CacheDecryptor(_LOCAL_KEY)
    streamed = b"".join(dec.decrypt_file_iter(p, chunk_size=1 << 20))
    assert streamed == dec.decrypt_file(p) == media


def test_tdef_end_to_end_large(tmp_path):
    """TDEF 端到端：64 MiB 合成文件，流式产物哈希 == 全量路径哈希。"""
    big = tmp_path / "big"
    media_size = 64 << 20
    _write_big_tdef(big, _LOCAL_KEY, media_size, _PNG)

    dec = CacheDecryptor(_LOCAL_KEY)
    hasher_stream = hashlib.sha256()
    total = 0
    for chunk in dec.decrypt_file_iter(big):
        hasher_stream.update(chunk)
        total += len(chunk)
    assert total == media_size
    assert hasher_stream.hexdigest() == hashlib.sha256(dec.decrypt_file(big)).hexdigest()


def test_finalized_and_validation_semantics():
    """_finalized 语义与构造校验不变：尾包后再解密抛错；key/iv 长度错误照常抛。"""
    d = CtrDecryptor(_KEY, _IV)
    d.decrypt(os.urandom(16))  # 整块：流仍可继续
    d.decrypt(os.urandom(3))  # 尾包：置 finalized
    with pytest.raises(DecryptionError, match="finalized"):
        d.decrypt(os.urandom(16))

    with pytest.raises(DecryptionError, match="32 bytes"):
        CtrDecryptor(b"short", _IV)
    with pytest.raises(DecryptionError, match="16 bytes"):
        CtrDecryptor(_KEY, b"short")

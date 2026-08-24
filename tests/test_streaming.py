"""流式解密测试（C-01 / N-5）。

覆盖：内存峰值回归、与 decrypt_file 逐字节一致（含尾包/空数据边界）、
未识别早停（不读余量）、解密中途失败的临时文件清理与重跑幂等。
"""

import hashlib
import os
import tracemalloc
from pathlib import Path

import tg_scoop.cache_decryptor as cd
from tests.fixtures import ctr_encrypt, make_fake_tdata, make_tdef
from tg_scoop.cache_decryptor import CacheDecryptor, derive_storage_key_iv
from tg_scoop.exceptions import DecryptionError
from tg_scoop.extractor import Extractor

_LOCAL_KEY = os.urandom(256)
_PNG = b"\x89PNG\r\n\x1a\n"


def _write_big_tdef(path: Path, local_key: bytes, media_size: int, head: bytes) -> None:
    """流式构造大 TDEF（避免测试自身吃内存）：CTR 计数器按块偏移推进。"""
    salt = os.urandom(64)
    key, iv = derive_storage_key_iv(local_key, salt)
    header = os.urandom(16)
    checksum = hashlib.sha256(local_key + salt + header).digest()
    counter0 = int.from_bytes(iv, "big")
    chunk = 1 << 20
    with open(path, "wb") as f:
        f.write(b"TDEF" + salt)
        f.write(ctr_encrypt(header + checksum, key, iv))
        written = 0
        block_off = 48 // 16  # 校验块占 3 个 CTR 块
        first = True
        while written < media_size:
            n = min(chunk, media_size - written)
            data = (head if first else b"") + bytes(n - (len(head) if first else 0))
            first = False
            # 长度不足 16 的尾包按 CTR 流密码语义加密
            iv_n = ((counter0 + block_off) % (1 << 128)).to_bytes(16, "big")
            f.write(ctr_encrypt(data, key, iv_n))
            block_off += (n + 15) // 16
            written += n


def test_memory_peak(tmp_path):
    """内存回归：64 MiB TDEF 流式解密全流程峰值 < 32 MiB。"""
    big = tmp_path / "big"
    media_size = 64 << 20
    _write_big_tdef(big, _LOCAL_KEY, media_size, _PNG)

    tracemalloc.start()
    try:
        hasher = hashlib.sha256()
        total = 0
        for chunk in CacheDecryptor(_LOCAL_KEY).decrypt_file_iter(big):
            hasher.update(chunk)
            total += len(chunk)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert total == media_size
    assert peak < 32 << 20, f"peak {peak / (1 << 20):.1f} MiB"


def test_byte_identity(tmp_path):
    """逐字节一致：流式拼接 == decrypt_file（含尾部非整块、空数据边界）。"""
    decryptor = CacheDecryptor(_LOCAL_KEY)
    cases = {
        "normal": _PNG + os.urandom(5000),
        "tail": _PNG + os.urandom(100),  # 长度非 16 倍数
        "exact_block": _PNG + bytes(4096),  # 恰好整块
        "empty": b"",  # 空媒体数据
    }
    for name, media in cases.items():
        p = tmp_path / name
        p.write_bytes(make_tdef(_LOCAL_KEY, media))
        streamed = b"".join(decryptor.decrypt_file_iter(p, chunk_size=1024))
        assert streamed == decryptor.decrypt_file(p), name


def test_unrecognized_early_stop(tmp_path, monkeypatch):
    """未识别早停：skipped 计数正确、无临时文件残留、不读取文件余量。"""
    media_size = 8 << 20
    tdata = make_fake_tdata(tmp_path, _LOCAL_KEY, cache_files={})
    cache = tdata / "user_data" / "cache"
    _write_big_tdef(cache / "big_garbage", _LOCAL_KEY, media_size, b"\x00\x01\x02\x03")

    read_bytes = [0]
    real_open = open

    class CountingFile:
        def __init__(self, f):
            self._f = f

        def read(self, n=-1):
            data = self._f.read(n)
            read_bytes[0] += len(data)
            return data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self._f.close()

    def counting_open(*args, **kwargs):
        return CountingFile(real_open(*args, **kwargs))

    monkeypatch.setattr(
        "tg_scoop.cache_decryptor.open", counting_open, raising=False
    )
    out = tmp_path / "out"
    stats = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)

    assert stats.skipped == 1
    assert stats.succeeded == 0
    assert not list(out.glob(".tg-scoop-partial-*"))
    assert read_bytes[0] < (1 << 20) + 4096, f"read {read_bytes[0]} bytes"


def test_abort_cleanup_and_rerun(tmp_path, monkeypatch):
    """中断清理：解密中途失败 -> failed 计数且无残留；恢复后重跑幂等。"""
    tdata = make_fake_tdata(
        tmp_path, _LOCAL_KEY,
        # 媒体 > 1 MiB（默认 chunk_size），数据需两次以上解密调用，
        # 使注入失败发生在临时文件建立之后
        cache_files={"good": make_tdef(_LOCAL_KEY, _PNG + os.urandom(2 << 20))},
    )
    cache = tdata / "user_data" / "cache"
    out = tmp_path / "out"

    real_decrypt = cd.CtrDecryptor.decrypt
    calls = {"n": 0}

    def flaky(self, chunk):
        calls["n"] += 1
        if calls["n"] == 3:  # 校验块 + 首个数据块之后失败（临时文件已建）
            raise DecryptionError("injected mid-stream failure")
        return real_decrypt(self, chunk)

    monkeypatch.setattr(cd.CtrDecryptor, "decrypt", flaky)
    stats = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)
    assert stats.failed == 1
    assert stats.succeeded == 0
    assert not list(out.glob(".tg-scoop-partial-*"))

    monkeypatch.undo()
    stats2 = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)
    assert stats2.succeeded == 1
    stats3 = Extractor(CacheDecryptor(_LOCAL_KEY)).extract_all(cache, out)
    assert stats3.duplicates == 1 and stats3.succeeded == 0

"""TDEF 缓存文件解密。

对应 DEVELOPMENT.md §2.1 环节 ④⑤ 与 §3.5：

- 遍历 user_data/cache/ 下的候选媒体文件
- TDEF 容器解析（magic / 64B salt / 48B 校验块 / 媒体数据）
- AES-256-CTR 解密（校验块与媒体数据共用一条 CTR 流）
- SHA-256 密钥校验

实现严格对照 refs/telegram-cache-decryption 的 storage_file_read 与
decryptor 类。单文件解密失败是预期内的常态（缓存随时被清理、
写入中断），本模块抛 DecryptionError，由上层（Extractor/CLI）
逐文件容错。
"""

import hashlib
from collections.abc import Iterator
from pathlib import Path

from tg_scoop.exceptions import CacheNotFoundError, DecryptionError

TDEF_MAGIC = b"TDEF"
LOCAL_KEY_SIZE = 256  # 与 tdata_reader.LOCAL_KEY_SIZE 一致

# TDEF 容器布局（DEVELOPMENT.md §3.5）
TDEF_SALT_OFFSET = 4
TDEF_SALT_LEN = 64
TDEF_CHECK_OFFSET = TDEF_SALT_OFFSET + TDEF_SALT_LEN  # 68
TDEF_CHECK_LEN = 48  # 16B 随机头 + 32B checksum
TDEF_DATA_OFFSET = TDEF_CHECK_OFFSET + TDEF_CHECK_LEN  # 116

# 遍历时跳过的文件名：索引/元数据而非媒体
SKIP_FILENAMES = frozenset({"version", "binlog", "map0", "map1"})

_BLOCK = 16  # AES 块大小


def _xor(a: bytes, b: bytes) -> bytes:
    """逐字节异或（CTR keystream 操作用，输入等长）。"""
    return bytes(x ^ y for x, y in zip(a, b))


class CtrDecryptor:
    """跨调用维持计数器的 AES-256-CTR 解密器（TDEF 缓存文件用）。

    为什么做成类：CTR 的计数器必须跨 read 分块连续递增，无状态函数
    签名会诱使调用方用同一 IV 重复解密后续分块（keystream 复用）。
    计数器按 OpenSSL CRYPTO_ctr128_encrypt 惯例大端递增，每 16 字节
    块 +1（对照 refs 实现的 block_index 语义）。
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        """初始化解密器。

        Args:
            key: 32 字节 AES key。
            iv: 16 字节初始计数器。

        Raises:
            DecryptionError: key/iv 长度错误。
        """
        if len(key) != 32:
            raise DecryptionError(f"AES-256 key must be 32 bytes, got {len(key)}")
        if len(iv) != _BLOCK:
            raise DecryptionError(f"CTR IV must be 16 bytes, got {len(iv)}")

        from Crypto.Cipher import AES  # 延迟导入：无依赖环境下仍可 import 本模块

        self._cipher = AES.new(key, AES.MODE_ECB)
        self._counter = int.from_bytes(iv, "big")  # OpenSSL 惯例：大端计数器
        self._finalized = False  # 处理过非整块尾包后置位，禁止继续解密

    def decrypt(self, chunk: bytes) -> bytes:
        """解密一个分块并推进计数器。

        Args:
            chunk: 密文分块。除整条流的最后一个分块外，长度必须是
                16 的倍数；尾包可以不足一块（CTR 是流密码）。

        Returns:
            明文分块。

        Raises:
            DecryptionError: 中间分块未按块对齐，或尾包之后继续解密
                （计数器已不对齐，继续解密必然产生垃圾数据）。
        """
        if self._finalized:
            raise DecryptionError("CTR stream already finalized by a partial block")

        out = bytearray(len(chunk))
        full_len = len(chunk) - (len(chunk) % _BLOCK)
        for off in range(0, full_len, _BLOCK):
            out[off : off + _BLOCK] = _xor(chunk[off : off + _BLOCK], self._next_block())
        if full_len < len(chunk):
            # 尾包不足一块：取 keystream 前缀异或，此后流不可继续
            out[full_len:] = _xor(chunk[full_len:], self._next_block())
            self._finalized = True
        return bytes(out)

    def _next_block(self) -> bytes:
        """生成当前计数器对应的 keystream 块并大端递增。"""
        keystream = self._cipher.encrypt(self._counter.to_bytes(_BLOCK, "big"))
        self._counter = (self._counter + 1) % (1 << 128)
        return keystream


def derive_storage_key_iv(local_key: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """按 TDEF 规范派生 AES-256-CTR 的 key 与 iv（DEVELOPMENT.md §3.5）。

    real_key = SHA256(local_key[:128] + salt[:32])
    iv       = SHA256(local_key[128:] + salt[32:])[:16]

    Args:
        local_key: 256 字节 LocalKey。
        salt: TDEF 头部的 64 字节 salt。

    Returns:
        (key, iv)，分别 32 / 16 字节。

    Raises:
        DecryptionError: 输入长度不符。
    """
    if len(local_key) != LOCAL_KEY_SIZE or len(salt) != TDEF_SALT_LEN:
        raise DecryptionError(
            f"bad input sizes: local_key={len(local_key)}, salt={len(salt)}"
        )
    key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:]).digest()[:16]
    return key, iv


def decrypt_storage_file(raw: bytes, local_key: bytes) -> bytes:
    """解密一个完整的 TDEF 缓存文件（含 magic 与密钥校验）。

    关键约束：校验块（48B）与媒体数据必须共用同一条 CTR 流，
    媒体数据从计数器块 3 继续而非重置为 0，否则明文错误且可能
    静默表现为"全部无法识别"（DEVELOPMENT.md §3.5）。

    Args:
        raw: TDEF 文件完整字节。
        local_key: 256 字节 LocalKey。

    Returns:
        明文媒体字节流（可能是完整文件或缓存分片）。

    Raises:
        DecryptionError: 非 TDEF、文件过短、密钥校验失败或数据损坏。
    """
    if len(raw) < TDEF_DATA_OFFSET:
        raise DecryptionError(f"file too short to be TDEF: {len(raw)} bytes")
    if raw[:4] != TDEF_MAGIC:
        raise DecryptionError("wrong magic, not a TDEF file")

    salt = raw[TDEF_SALT_OFFSET:TDEF_CHECK_OFFSET]
    key, iv = derive_storage_key_iv(local_key, salt)
    d = CtrDecryptor(key, iv)

    # 校验块：16B 随机头 + 32B checksum（与媒体数据同一条 CTR 流）
    check = d.decrypt(raw[TDEF_CHECK_OFFSET:TDEF_DATA_OFFSET])
    header, checksum = check[:16], check[16:48]
    if hashlib.sha256(local_key + salt + header).digest() != checksum:
        raise DecryptionError("wrong key for storage file")

    # 媒体数据：计数器接着校验块（块 3）继续，不能重置
    return d.decrypt(raw[TDEF_DATA_OFFSET:])


def iter_cache_files(cache_dir: Path) -> Iterator[Path]:
    """递归产出 cache/ 下的候选媒体文件。

    跳过 version/binlog/map0/map1（索引而非媒体）。v0.1 暴力遍历
    而不解析 map：map 格式随 tdesktop 版本漂移，且解密失败项本来
    就会被后续环节过滤（DEVELOPMENT.md §2.3）。

    media_cache/ 等第二个缓存根目录由调用方作为另一次调用传入，
    本函数保持单目录职责。

    Args:
        cache_dir: tdata/user_data/cache 目录。

    Yields:
        候选文件路径（顺序稳定，按路径排序）。

    Raises:
        CacheNotFoundError: 目录不存在或没有任何候选文件。
    """
    cache_dir = Path(cache_dir)
    if not cache_dir.is_dir():
        raise CacheNotFoundError(f"cache directory not found: {cache_dir}")

    files = sorted(
        p
        for p in cache_dir.rglob("*")
        if p.is_file() and p.name not in SKIP_FILENAMES
    )
    if not files:
        raise CacheNotFoundError(
            f"cache directory is empty: {cache_dir} "
            "(play the target video in Telegram Desktop first)"
        )
    yield from files


class CacheDecryptor:
    """缓存解密器：持有一份 LocalKey，批量解密 cache 目录。"""

    def __init__(self, local_key: bytes) -> None:
        """初始化解密器。

        Args:
            local_key: TdataReader.read_local_key 返回的 256 字节密钥。

        Raises:
            DecryptionError: local_key 长度不为 256 字节。
        """
        if len(local_key) != LOCAL_KEY_SIZE:
            raise DecryptionError(
                f"local_key must be {LOCAL_KEY_SIZE} bytes, got {len(local_key)}"
            )
        self._local_key = local_key

    def decrypt_file(self, path: Path) -> bytes:
        """读取并解密单个 TDEF 缓存文件。

        Args:
            path: 缓存文件路径。

        Returns:
            明文媒体字节流。

        Raises:
            DecryptionError: 非 TDEF、密钥校验失败或数据损坏；
                异常信息附带文件路径。调用方应逐文件 try/except 并继续。
        """
        path = Path(path)
        try:
            return decrypt_storage_file(path.read_bytes(), self._local_key)
        except DecryptionError as exc:
            raise DecryptionError(f"{path}: {exc}") from exc

    def decrypt_all(self, cache_dir: Path) -> Iterator[tuple[Path, bytes]]:
        """遍历 cache 目录并逐个产出 (路径, 明文)。

        解密失败的文件不抛出，而是跳过——由 Extractor 负责统计
        失败数（成功 N / 跳过 M / 失败 K 的报告口径见
        DEVELOPMENT.md §2.1）。

        Args:
            cache_dir: tdata/user_data/cache 目录。

        Yields:
            (缓存文件路径, 解密后的明文)。

        Raises:
            CacheNotFoundError: 目录不存在或为空。
        """
        for path in iter_cache_files(cache_dir):
            try:
                yield path, self.decrypt_file(path)
            except DecryptionError:
                continue  # 逐文件容错：单个失败不中断整批

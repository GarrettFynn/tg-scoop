"""加密 fixture 构造函数（自 _selftest_common.py 迁入，P0-11）。

把各测试所需的逆运算加密函数集中在这里（DEVELOPMENT.md §9.1
的 fixture 生成器策略落地）。所有函数都是 src/tg_scoop 解密路径
的逆运算，用于把已知明文加密成合法的 TDF$/TDEF/key_datas 结构。
"""

import hashlib
import os
from pathlib import Path

from Crypto.Cipher import AES

from tg_scoop.cache_decryptor import derive_storage_key_iv
from tg_scoop.tdata_reader import create_local_key, prepare_aes_oldmtp


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ige_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-IGE 加密（aes_ige_decrypt 的逆运算）。"""
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev_c, prev_p = iv[:16], iv[16:]
    for off in range(0, len(data), 16):
        p = data[off : off + 16]
        c = xor(cipher.encrypt(xor(p, prev_c)), prev_p)
        out += c
        prev_c, prev_p = c, p
    return bytes(out)


def encrypt_local(data: bytes, key: bytes) -> bytes:
    """构造 local 加密块（decrypt_local 的逆运算）。"""
    length = (4 + len(data)).to_bytes(4, "little")  # 长度含自身 4 字节
    padded = length + data
    padded += os.urandom((-len(padded)) % 16)
    msg_key = hashlib.sha1(padded).digest()[:16]
    aes_key, aes_iv = prepare_aes_oldmtp(key, msg_key)
    return msg_key + ige_encrypt(padded, aes_key, aes_iv)


def qt_bytes(b: bytes) -> bytes:
    """QDataStream 的 QByteArray 序列化（大端长度前缀）。"""
    return len(b).to_bytes(4, "big") + b


def wrap_tdf(payload: bytes, version: int = 0) -> bytes:
    """把 payload 包装成合法 TDF$ 容器（含 MD5 尾校验）。"""
    tail = hashlib.md5(
        payload
        + len(payload).to_bytes(4, "little")
        + version.to_bytes(4, "little")
        + b"TDF$"
    ).digest()
    return b"TDF$" + version.to_bytes(4, "little") + payload + tail


def make_key_datas(
    local_key: bytes,
    salt: bytes,
    passcode: bytes = b"",
    account_indexes: tuple[int, ...] = (0,),
) -> bytes:
    """合成 key_datas 文件内容（TDF$ 容器）。"""
    passcode_key = create_local_key(passcode, salt)
    key_encrypted = encrypt_local(local_key, passcode_key)
    info = len(account_indexes).to_bytes(4, "big")
    for idx in account_indexes:
        info += idx.to_bytes(4, "big")
    info += (0).to_bytes(4, "big")  # 主账号索引
    info_encrypted = encrypt_local(info, local_key)
    return wrap_tdf(qt_bytes(salt) + qt_bytes(key_encrypted) + qt_bytes(info_encrypted))


def ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """与 CtrDecryptor 同语义的 CTR 加密（CTR 加解密对称）。"""
    cipher = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        block = data[off : off + 16]
        ks = cipher.encrypt(counter.to_bytes(16, "big"))
        counter = (counter + 1) % (1 << 128)
        out += bytes(x ^ y for x, y in zip(block, ks))
    return bytes(out)


def make_tdef(local_key: bytes, media: bytes) -> bytes:
    """构造合法 TDEF：magic + salt + 校验块 + 媒体密文（共用 CTR 流）。"""
    salt = os.urandom(64)
    key, iv = derive_storage_key_iv(local_key, salt)
    header = os.urandom(16)
    checksum = hashlib.sha256(local_key + salt + header).digest()
    blob = ctr_encrypt(header + checksum + media, key, iv)
    return b"TDEF" + salt + blob


def make_fake_tdata(
    root: Path,
    local_key: bytes,
    cache_files: dict[str, bytes],
    passcode: bytes = b"",
    media_cache_files: dict[str, bytes] | None = None,
) -> Path:
    """构造完整假 tdata 目录。

    Args:
        root: 父目录（tdata 在其下创建）。
        local_key: 256 字节 LocalKey。
        cache_files: user_data/cache/ 下的 {文件名: TDEF 原始字节}。
        passcode: 本地密码（b"" 表示无密码）。
        media_cache_files: 可选的 user_data/media_cache/ 内容。

    Returns:
        tdata 目录路径。
    """
    tdata = Path(root) / "tdata"
    tdata.mkdir(parents=True)
    (tdata / "key_datas").write_bytes(
        make_key_datas(local_key, os.urandom(32), passcode)
    )
    cache = tdata / "user_data" / "cache"
    cache.mkdir(parents=True)
    for name, raw in cache_files.items():
        (cache / name).write_bytes(raw)
    if media_cache_files is not None:
        media_cache = tdata / "user_data" / "media_cache"
        media_cache.mkdir(parents=True)
        for name, raw in media_cache_files.items():
            (media_cache / name).write_bytes(raw)
    return tdata


def _mtp_auth_stream(user_id: int, dc_id: int, auth_key: bytes, legacy: bool) -> bytes:
    """构造 MTP 授权 settings 块流（两个公开 fixture 共用）。

    结构：int32 BE 0x4B + qt_bytes(载荷)；载荷 = legacy 双 int32
    （legacy=True 时为真实 id，否则 -1/-1 后接 uint64 user_id +
    int32 dc_id）+ keys（count=1 + dc_id + 原始 256 字节 auth_key）
    + keys_to_destroy（count=0）。
    """
    if len(auth_key) != 256:
        raise ValueError("auth_key must be 256 bytes")
    if legacy:
        head = user_id.to_bytes(4, "big", signed=True) + dc_id.to_bytes(
            4, "big", signed=True
        )
    else:
        head = (
            (-1).to_bytes(4, "big", signed=True)
            + (-1).to_bytes(4, "big", signed=True)
            + user_id.to_bytes(8, "big")
            + dc_id.to_bytes(4, "big", signed=True)
        )
    keys = (1).to_bytes(4, "big") + dc_id.to_bytes(4, "big", signed=True) + auth_key
    destroy = (0).to_bytes(4, "big")
    payload = head + keys + destroy
    return (0x4B).to_bytes(4, "big") + qt_bytes(payload)


def make_mtp_auth_file(
    local_key: bytes,
    user_id: int,
    dc_id: int,
    auth_key: bytes,
    legacy: bool = False,
) -> bytes:
    """构造 MTP 数据文件内容（tdata/<data_name_key>，无 s 后缀）。

    结构（DEVELOPMENT.md §5.1，对照参考实现 decrypter.py/settings.py）：
    wrap_tdf(encrypt_local(块流, local_key))；块流构造见
    ``_mtp_auth_stream``。
    """
    stream = _mtp_auth_stream(user_id, dc_id, auth_key, legacy)
    return wrap_tdf(encrypt_local(stream, local_key))


def make_mtp_auth_file_s(
    local_key: bytes,
    user_id: int,
    dc_id: int,
    auth_key: bytes,
    legacy: bool = False,
) -> bytes:
    """构造 tdesktop 7.x 布局的 MTP 数据文件内容（tdata/<data_name_key>s）。

    与 ``make_mtp_auth_file`` 共用块流构造，差异仅在最外层多一层
    QByteArray 包裹：wrap_tdf(qt_bytes(encrypt_local(块流, local_key)))，
    复现漂移项 D-7.1.1-1 实测的 7.1.1 s 文件。
    """
    stream = _mtp_auth_stream(user_id, dc_id, auth_key, legacy)
    return wrap_tdf(qt_bytes(encrypt_local(stream, local_key)))

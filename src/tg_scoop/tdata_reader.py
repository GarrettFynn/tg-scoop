"""tdata 读取与密钥派生。

对应 DEVELOPMENT.md §2.1 环节 ①②③ 与 §3.1–§3.4、§3.6、§5.1：

- TDF$ 容器解析（MD5 尾校验）
- Qt QDataStream 序列化读取（纯 Python，替代 PyQt）
- PasscodeKey / LocalKey 派生（PBKDF2-HMAC-SHA512）
- local 加密块解密（AES-256-IGE + MTProto 旧式 KDF + SHA-1 校验）
- 【v0.2】cache map 解密与 MTP 授权数据（auth_key/user_id/dc_id）提取

实现严格对照 refs/telegram-cache-decryption（lilydjwg 上游）与
refs/tdesktop-decrypter（ntqbit）的真实源码。本模块只读 tdata，
绝不写入（DEVELOPMENT.md §8 硬性边界）。
"""

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from tg_scoop.exceptions import (
    CorruptedDataError,
    DecryptionError,
    PasswordRequiredError,
    TDataNotFoundError,
)

TDF_MAGIC = b"TDF$"
_TDF_TAIL_LEN = 16  # MD5 尾校验长度

# PBKDF2 迭代次数（DEVELOPMENT.md §3.4）：tdesktop 历史上升级过 KDF，
# 新式（key_datas）与旧式（settings 文件）参数不同，不可混用。
KDF_ITERATIONS_WITH_PASSWORD = 100000
KDF_ITERATIONS_NO_PASSWORD = 1
LOCAL_KEY_SIZE = 256  # 字节；tdesktop 复用 MTProto AuthKey 的 256 字节结构


def _xor(a: bytes, b: bytes) -> bytes:
    """逐字节异或（IGE 链接操作用，输入等长）。"""
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Qt 序列化读取（DEVELOPMENT.md §1.3 qt_stream）
# ---------------------------------------------------------------------------


class QtStreamReader:
    """QDataStream 格式的只读读取器（big-endian）。

    为什么自己写：PyQt5 只为 readBytes()/readInt32() 两个调用引入
    上百 MB 的 GUI 依赖，得不偿失。Qt 格式是公开的定长前缀格式，
    纯 Python 实现行为完全可测。

    注意：QDataStream 默认大端序（对照 refs/tdesktop-decrypter 的
    qt.py：`int.from_bytes(b, "big")`）。tdata 中仅有的两处
    little-endian 是 TDF version 字段与解密后明文内的长度字段，
    均不在本类职责内。
    """

    def __init__(self, data: bytes) -> None:
        """以完整字节串初始化读取器。

        Args:
            data: QDataStream 序列化的原始字节。
        """
        self._data = memoryview(data)
        self._pos = 0

    def _read(self, size: int) -> bytes:
        """读取定长字节并推进游标，不足即报错。"""
        if self._pos + size > len(self._data):
            raise CorruptedDataError(
                f"Qt stream truncated: need {size} bytes at offset "
                f"{self._pos}, only {len(self._data) - self._pos} left"
            )
        chunk = bytes(self._data[self._pos : self._pos + size])
        self._pos += size
        return chunk

    def read_int32(self) -> int:
        """读取 4 字节大端有符号整数。

        Raises:
            CorruptedDataError: 剩余字节不足。
        """
        return int.from_bytes(self._read(4), "big", signed=True)

    def read_int64(self) -> int:
        """读取 8 字节大端有符号整数。

        Raises:
            CorruptedDataError: 剩余字节不足。
        """
        return int.from_bytes(self._read(8), "big", signed=True)

    def read_uint64(self) -> int:
        """读取 8 字节大端无符号整数。

        Raises:
            CorruptedDataError: 剩余字节不足。
        """
        return int.from_bytes(self._read(8), "big", signed=False)

    def read_bytes(self) -> bytes:
        """读取 QByteArray：4 字节大端长度前缀 + 内容。

        长度 <= 0（含 0xFFFFFFFF 的 null 标记）返回 b""。

        Returns:
            QByteArray 内容。

        Raises:
            CorruptedDataError: 长度超过剩余字节数。不静默截断——
                截断会把损坏数据带入 SHA-1 校验，报错会误导为"密码错误"。
        """
        length = self.read_int32()
        if length <= 0:  # 0xFFFFFFFF 解析为有符号 -1，即 Qt 的 null 标记
            return b""
        return self._read(length)

    def read_raw(self, size: int) -> bytes:
        """读取原始定长字节（无长度前缀）。

        用于 settings 块内的定长字段（如 256 字节 auth_key，
        DEVELOPMENT.md §5.1）。

        Raises:
            CorruptedDataError: 剩余字节不足。
        """
        return self._read(size)

    def at_end(self) -> bool:
        """流是否已耗尽。settings 块流以 EOF 终止（§5.1）。"""
        return self._pos >= len(self._data)


# ---------------------------------------------------------------------------
# TDF$ 容器（DEVELOPMENT.md §3.1）
# ---------------------------------------------------------------------------


@dataclass
class RawTdfFile:
    """TDF$ 容器解析结果。"""

    version: int
    encrypted_data: bytes  # 已剥离 magic/version/尾校验


def parse_tdf(data: bytes) -> RawTdfFile:
    """解析并校验 TDF$ 容器。

    布局：magic(4B) + version(4B, LE) + data + md5_tail(16B)。
    MD5 尾校验输入为 data + len(data)(LE u32) + version(LE u32) + magic，
    包含 magic 与 version 自身——这是最容易写错的一点。

    Args:
        data: TDF$ 文件的完整字节。

    Returns:
        解析出的 RawTdfFile。

    Raises:
        CorruptedDataError: magic 错误、文件过短或 MD5 校验失败。
    """
    if len(data) < 8 + _TDF_TAIL_LEN:
        raise CorruptedDataError("file too short to be a TDF container")
    if data[:4] != TDF_MAGIC:
        raise CorruptedDataError("wrong magic, not a TDF$ file")

    version = int.from_bytes(data[4:8], "little")  # TDF version 是小端
    encrypted_data = data[8:-_TDF_TAIL_LEN]
    tail = data[-_TDF_TAIL_LEN:]

    digest = hashlib.md5(
        encrypted_data
        + len(encrypted_data).to_bytes(4, "little")
        + version.to_bytes(4, "little")
        + TDF_MAGIC
    ).digest()
    if digest != tail:
        raise CorruptedDataError("TDF checksum mismatch, corrupted file?")

    return RawTdfFile(version=version, encrypted_data=encrypted_data)


def read_tdf_file(path: Path) -> RawTdfFile:
    """以只读方式打开并解析 TDF$ 文件。

    Args:
        path: 文件路径。

    Returns:
        解析出的 RawTdfFile。

    Raises:
        TDataNotFoundError: 文件不存在。
        CorruptedDataError: 容器校验失败。
    """
    path = Path(path)
    if not path.is_file():
        raise TDataNotFoundError(f"tdata file not found: {path}")
    return parse_tdf(path.read_bytes())


# ---------------------------------------------------------------------------
# 密钥派生与 local 加密块（DEVELOPMENT.md §3.2、§3.3、§3.6）
# ---------------------------------------------------------------------------


def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    """由用户 passcode 派生 PasscodeKey（256 字节）。

    算法（与 tdesktop CreateLocalKey 一致）::

        password = SHA512(salt + passcode + salt)
        key      = PBKDF2-HMAC-SHA512(password, salt, iter, dklen=256)
        iter     = 100000（有密码）/ 1（无密码）

    Args:
        passcode: 本地密码，未设密码传 b""。
        salt: key_datas 中读出的 salt（永远来自文件，无密码时也不例外）。

    Returns:
        256 字节密钥。长度错误会在后续 SHA-1 校验处才暴露，勿改 dklen。
    """
    password = hashlib.sha512(salt + passcode + salt).digest()
    iterations = (
        KDF_ITERATIONS_WITH_PASSWORD if passcode else KDF_ITERATIONS_NO_PASSWORD
    )
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, LOCAL_KEY_SIZE)


def prepare_aes_oldmtp(local_key: bytes, msg_key: bytes) -> tuple[bytes, bytes]:
    """MTProto 旧式 KDF（接收方向 x=8）。

    由 256 字节 local_key 与 16 字节 msg_key 拼出 32 字节 AES key
    与 32 字节 IGE IV（切片布局见 DEVELOPMENT.md §3.2）。

    Args:
        local_key: 256 字节 LocalKey。
        msg_key: 密文前 16 字节。

    Returns:
        (aes_key, aes_iv)，分别 32 字节。

    Raises:
        DecryptionError: 输入长度不符。
    """
    if len(local_key) != LOCAL_KEY_SIZE or len(msg_key) != 16:
        raise DecryptionError(
            f"bad input sizes: local_key={len(local_key)}, msg_key={len(msg_key)}"
        )
    x = 8  # 接收方向偏移（对照 refs 实现的 prepareAES_oldmtp）
    sha1_a = hashlib.sha1(msg_key + local_key[x : x + 32]).digest()
    sha1_b = hashlib.sha1(
        local_key[x + 32 : x + 48] + msg_key + local_key[x + 48 : x + 64]
    ).digest()
    sha1_c = hashlib.sha1(local_key[x + 64 : x + 96] + msg_key).digest()
    sha1_d = hashlib.sha1(msg_key + local_key[x + 96 : x + 128]).digest()

    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]  # 32 B
    aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]  # 32 B（IGE 双链接块）
    return aes_key, aes_iv


def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE 解密。

    用 pycryptodome 的 ECB 原语手工组合 IGE（延迟导入），避免
    CFFI/OpenSSL 的跨平台编译问题（Windows 优先约束）。
    IGE 解密递推（对照 OpenSSL AES_ige_decrypt 语义）::

        P[i] = D(C[i] XOR P[i-1]) XOR C[i-1]
        C[-1] = iv[0:16], P[-1] = iv[16:32]

    Args:
        data: 密文，长度必须是 16 的倍数。
        key: 32 字节 AES key。
        iv: 32 字节（两个链接块 iv1, iv2）。

    Returns:
        明文。

    Raises:
        DecryptionError: 输入未按块对齐或 key/IV 长度错误。
    """
    if len(data) % 16 != 0:
        raise DecryptionError(f"IGE input not block-aligned: {len(data)} bytes")
    if len(iv) != 32:
        raise DecryptionError(f"IGE IV must be 32 bytes, got {len(iv)}")

    from Crypto.Cipher import AES  # 延迟导入：无依赖环境下仍可 import 本模块

    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray(len(data))
    prev_c, prev_p = iv[:16], iv[16:]
    for off in range(0, len(data), 16):
        block = data[off : off + 16]
        plain = _xor(cipher.decrypt(_xor(block, prev_p)), prev_c)
        out[off : off + 16] = plain
        prev_c, prev_p = block, plain
    return bytes(out)


def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    """解密 tdesktop 的 local 加密块（TDF 内嵌格式）。

    格式：[0:16] msg_key = SHA1(plaintext)[:16]，[16:] IGE 密文。

    Args:
        encrypted: local 加密块。
        local_key: PasscodeKey 或 LocalKey（视被解密对象而定）。

    Returns:
        明文数据段。

    Raises:
        DecryptionError: SHA-1 校验失败（密码错误或文件损坏），
            或长度字段越界。
    """
    if len(encrypted) < 16 or (len(encrypted) - 16) % 16 != 0:
        raise DecryptionError(f"malformed local-encrypted blob: {len(encrypted)} bytes")

    msg_key = encrypted[:16]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key)
    plain = aes_ige_decrypt(encrypted[16:], aes_key, aes_iv)

    if hashlib.sha1(plain).digest()[:16] != msg_key:
        raise DecryptionError("checksum failed: wrong passcode or corrupted data")

    length = int.from_bytes(plain[:4], "little")  # 明文内长度字段是小端
    if length < 4 or length > len(plain):
        raise DecryptionError(f"corrupted data: wrong length {length}")
    # 长度字段含自身 4 字节，因此切片终点是 length 而非 4 + length，
    # 与 tdesktop 的 mid(4, dataLen - 4) 等价（两个参考实现一致）
    return plain[4:length]


# ---------------------------------------------------------------------------
# MTP 授权数据（DEVELOPMENT.md §5.1，v0.2）
# ---------------------------------------------------------------------------

DBI_MTP_AUTHORIZATION = 0x4B
"""tdesktop SettingsBlock::dbiMtpAuthorization（对照参考实现 settings.py）。"""


@dataclass
class MtpAuthorization:
    """从 tdata 提取的 MTProto 授权数据，可直接构造 Telethon 会话。"""

    user_id: int
    dc_id: int
    auth_key: bytes  # 256 字节


def compute_data_name_key(dataname: str) -> str:
    """计算 MTP 数据文件名（已验证算法，见 DEVELOPMENT.md §5.1）。

    filekey = MD5(dataname)[:8]，每个字节的两位十六进制互换
    （如 0xAB -> "BA"），拼成 16 字符大写字符串。

    Args:
        dataname: "data"（首账号）或 "data#2"、"data#3"（多账号）。

    Returns:
        16 字符大写文件名 key。
    """
    filekey = hashlib.md5(dataname.encode("utf-8")).digest()[:8]
    return "".join(f"{b:02X}"[::-1] for b in filekey)


# ---------------------------------------------------------------------------
# TDataReader
# ---------------------------------------------------------------------------


class TdataReader:
    """封装对一个 tdata 目录的只读访问。"""

    DEFAULT_DATANAME = "data"

    def __init__(self, tdata_path: Path, dataname: str = DEFAULT_DATANAME) -> None:
        """初始化读取器（不立即读盘）。

        Args:
            tdata_path: tdata 目录路径。
            dataname: 数据名，首账号为 "data"，多账号为 "data#2" 等。

        Raises:
            TDataNotFoundError: 目录不存在。
        """
        self._tdata_path = Path(tdata_path)
        if not self._tdata_path.is_dir():
            raise TDataNotFoundError(f"tdata directory not found: {self._tdata_path}")
        self._dataname = dataname
        self._info_encrypted: bytes | None = None  # read_local_key 时缓存

    @staticmethod
    def default_tdata_path() -> Path:
        """按平台返回默认 tdata 路径（DEVELOPMENT.md §2.1）。

        Returns:
            Windows %APPDATA%/Telegram Desktop/tdata，
            macOS ~/Library/Application Support/Telegram Desktop/tdata，
            Linux ~/.local/share/TelegramDesktop/tdata。

        Raises:
            TDataNotFoundError: 默认路径不存在且无法推断。
        """
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            candidates = [
                (Path(appdata) if appdata else Path.home() / "AppData" / "Roaming")
                / "Telegram Desktop"
                / "tdata"
            ]
        elif sys.platform == "darwin":
            candidates = [
                Path.home()
                / "Library"
                / "Application Support"
                / "Telegram Desktop"
                / "tdata"
            ]
        else:
            candidates = [
                Path.home() / ".local" / "share" / "TelegramDesktop" / "tdata"
            ]
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
        raise TDataNotFoundError(
            "default tdata path not found; pass --tdata-path explicitly "
            f"(tried: {', '.join(str(c) for c in candidates)})"
        )

    @property
    def _key_file_path(self) -> Path:
        """key 文件路径：dataname 为 "data" 时即 key_datas。"""
        return self._tdata_path / f"key_{self._dataname}s"

    def _read_key_blobs(self) -> tuple[bytes, bytes, bytes]:
        """读取 key_datas 内的三个 QByteArray：(salt, key_encrypted, info_encrypted)。"""
        tdf = read_tdf_file(self._key_file_path)
        reader = QtStreamReader(tdf.encrypted_data)
        salt = reader.read_bytes()
        key_encrypted = reader.read_bytes()
        info_encrypted = reader.read_bytes()
        return salt, key_encrypted, info_encrypted

    def read_local_key(self, passcode: str = "") -> bytes:
        """读取 key_{dataname}s，派生并返回 256 字节 LocalKey。

        流程：parse_tdf -> QtStreamReader 读 salt/key_encrypted/info_encrypted
        -> create_local_key -> decrypt_local（SHA-1 校验）。
        此后所有缓存解密只用 LocalKey，passcode 即时丢弃。

        交互式密码输入由 CLI 层负责（getpass），本方法保持纯函数式
        接口以便测试。

        Args:
            passcode: 本地密码，未设密码传 ""。

        Returns:
            256 字节 LocalKey。

        Raises:
            TDataNotFoundError: key 文件不存在。
            PasswordRequiredError: 校验失败且 passcode 为空——最可能
                是账号设了本地密码，提示用户使用 --password。
            DecryptionError: 已提供 passcode 仍校验失败（密码错误或损坏）。
        """
        salt, key_encrypted, self._info_encrypted = self._read_key_blobs()
        passcode_key = create_local_key(passcode.encode("utf-8"), salt)
        try:
            return decrypt_local(key_encrypted, passcode_key)
        except DecryptionError as exc:
            if not passcode:
                raise PasswordRequiredError(
                    "this tdata is protected by a local passcode; "
                    "rerun with --password"
                ) from exc
            raise

    def read_account_indexes(self, local_key: bytes) -> list[int]:
        """从 info_encrypted 解密结果中读取账号索引列表（v0.2 用）。

        格式（对照 refs/tdesktop-decrypter 的 read_key_data_accounts）：
        int32 count + count 个 int32 索引 + int32 主账号。

        Args:
            local_key: read_local_key 的返回值。

        Returns:
            账号索引列表。

        Raises:
            DecryptionError: info_encrypted 解密失败。
        """
        if self._info_encrypted is None:
            # 允许未调用 read_local_key 的场景：重新读一次文件
            _, _, self._info_encrypted = self._read_key_blobs()
        info = decrypt_local(self._info_encrypted, local_key)
        reader = QtStreamReader(info)
        count = reader.read_int32()
        indexes = [reader.read_int32() for _ in range(count)]
        reader.read_int32()  # 主账号索引，v0.1 不使用
        return indexes

    def read_cache_map(self, local_key: bytes) -> dict[bytes, tuple[str, int]]:
        """【v0.1.x/v0.2】解密 cache/map0 或 map1 索引。

        v0.1 不调用本方法（暴力遍历替代，理由见 DEVELOPMENT.md §2.3）；
        v0.2 接入 MTProto 后用于 cache key ↔ document.id 关联。

        Args:
            local_key: read_local_key 的返回值。

        Raises:
            NotImplementedError: 依赖 map 二进制格式逆向（TODO P1-4）。
        """
        raise NotImplementedError("cache map parsing is planned for v0.2 (TODO P1-4)")

    def read_mtp_authorization(self, local_key: bytes) -> MtpAuthorization:
        """提取 MTProto 授权数据（DEVELOPMENT.md §5.1，TODO P1-2）。

        定位（与参考实现 file_io.py 对齐，漂移项 D-7.1.1-1）：候选路径为
        ``[tdata/<key>s, tdata/<key>]``（s 后缀优先，key =
        compute_data_name_key(dataname)），取首个存在的**文件**——
        tdesktop 7.x 中无 s 变体可能被同名目录占用，授权块位于 s 文件。
        TDF$ 解析后依次尝试两种解包：a) 直接 decrypt_local（旧布局）；
        b) 先按 QByteArray 解包再 decrypt_local（7.x s 文件，密文外层多
        一层 QByteArray 包裹）。只对首个存在的候选尝试，两变体均失败
        即抛 DecryptionError，不回退第二候选。

        块解析采取严格策略：遇到 0x4B 以外的块 id 立即抛
        CorruptedDataError——与参考实现的严格性一致，真实的格式漂移
        应在验证中显式暴露，而非静默跳过（载荷无统一长度前缀，
        无法安全 skip 未知块）。

        Args:
            local_key: read_local_key 的返回值。

        Returns:
            MtpAuthorization；auth_key 取 main_dc_id 对应的 256 字节密钥。

        Raises:
            TDataNotFoundError: 两个候选路径都不存在（或均被目录占用）。
            DecryptionError: LocalKey 错误（SHA-1 校验失败），或首个候选
                两种解包变体均失败。
            CorruptedDataError: 无 0x4B 块、遇到不支持的块 id、
                或 main_dc_id 无对应 auth_key。
        """
        key = compute_data_name_key(self._dataname)
        candidates = [self._tdata_path / f"{key}s", self._tdata_path / key]
        key_file = next((p for p in candidates if p.is_file()), None)
        if key_file is None:
            raise TDataNotFoundError(
                f"tdata file not found (tried: {candidates[0]}, {candidates[1]})"
            )
        tdf = read_tdf_file(key_file)
        try:
            settings = decrypt_local(tdf.encrypted_data, local_key)
        except DecryptionError:
            # 7.x s 文件变体：密文外层多一层 QByteArray 包裹，先解包再解密
            try:
                blob = QtStreamReader(tdf.encrypted_data).read_bytes()
                settings = decrypt_local(blob, local_key)
            except CorruptedDataError as exc:
                raise DecryptionError(
                    f"decrypt failed in both direct and QByteArray "
                    f"variants: {exc}"
                ) from exc

        reader = QtStreamReader(settings)
        payload: bytes | None = None
        while not reader.at_end():
            block_id = reader.read_int32()
            if block_id == DBI_MTP_AUTHORIZATION:
                payload = reader.read_bytes()
                break
            raise CorruptedDataError(
                f"unsupported settings block id: {block_id:#06x}; "
                "only dbiMtpAuthorization is parsed (§5.1)"
            )
        if payload is None:
            raise CorruptedDataError("dbiMtpAuthorization block not found")

        r = QtStreamReader(payload)
        legacy_user_id = r.read_int32()
        legacy_main_dc_id = r.read_int32()
        if legacy_user_id == -1 and legacy_main_dc_id == -1:
            user_id = r.read_uint64()  # 新版格式
            main_dc_id = r.read_int32()
        else:
            user_id, main_dc_id = legacy_user_id, legacy_main_dc_id

        keys: dict[int, bytes] = {}
        for _ in range(r.read_int32()):
            dc_id = r.read_int32()  # 必须先读键再读值：赋值语句先求值 RHS
            keys[dc_id] = r.read_raw(256)
        for _ in range(r.read_int32()):  # keys_to_destroy：同结构，读取后丢弃
            r.read_int32()
            r.read_raw(256)

        if main_dc_id not in keys:
            raise CorruptedDataError(
                f"no auth_key for main dc {main_dc_id} (have: {sorted(keys)})"
            )
        return MtpAuthorization(
            user_id=user_id, dc_id=main_dc_id, auth_key=keys[main_dc_id]
        )

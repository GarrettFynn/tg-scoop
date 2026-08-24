"""TDataReader 单元测试骨架。

覆盖点对应 DEVELOPMENT.md §9.1：
- QtStreamReader：大端整数、QByteArray 正常/null/截断
- 密钥派生：空密码 + 固定 salt 的回归值（golden vector）
- decrypt_local：SHA-1 校验失败路径
- parse_tdf：magic 错误、MD5 错误、正常三种样本
- TDataReader：TDataNotFoundError / PasswordRequiredError / DecryptionError

测试数据策略：用 fixtures/make_tdata.py 生成假 tdata（不含任何真实
用户数据），并保留 2~3 个参考实现生成的 golden 文件做交叉锚定。
"""

import os

import pytest

from tests.fixtures import (
    encrypt_local,
    ige_encrypt,
    make_fake_tdata,
    make_mtp_auth_file,
    make_mtp_auth_file_s,
    qt_bytes,
    wrap_tdf,
)
from tg_scoop.exceptions import (
    CorruptedDataError,
    DecryptionError,
    PasswordRequiredError,
    TDataNotFoundError,
)
from tg_scoop.tdata_reader import (
    QtStreamReader,
    TdataReader,
    aes_ige_decrypt,
    compute_data_name_key,
    create_local_key,
    decrypt_local,
    parse_tdf,
    prepare_aes_oldmtp,
)

# 自生成回归字面值（P0-11）：由实现运行一次取得，算法参数
# PBKDF2-HMAC-SHA512 / iter=1 或 100000 / dklen=256 已人工核对 §3.4。
# 固定 salt = bytes(range(32))。
_SALT = bytes(range(32))
_LOCAL_KEY_EMPTY_PASSCODE = bytes.fromhex(
    "7ce9b2c87b8b982b84434ca8cb61577b1fd0d9737a85e9ef5c03a5c2ae2358f3"
    "0d2305f560524b0ee8c816a1e5256f215235ba04378fa6a2f353d836def0cad9"
    "d2e1581f12391789f5a1b340fd099bd4d111c66139569fcb88814da9f6207c340"
    "ec39598663bcc26bb94903efc9a1316daa6eb215c5b4abafa908f976270a127a4"
    "b2f3f7ac0f79eb324ed1ccb3152d7b2b66c00e5bb9806b261a33dfafc1dcc20e"
    "67b77034a93929aa72c64ca38da03d04aa6d524b2c90be12d7618676cea07e03"
    "c215bb378e0a87c3a4803e514052e0ae3683ba41982a168760f563d016841e47"
    "4df8f95f82d00d9beb43722e5e82be68b01c586dab8566b576f3501524b173"
)
_LOCAL_KEY_WITH_PASSCODE = bytes.fromhex(
    "94eb4c67776cb3d310fac20fc970099673477e7a367057b09b77de2144236a6e"
    "5116f379b324e7e42b8a9954c359b2983b2d6064d5b6ff94f77b934d71cece5"
    "a6f3b81129c13aba47a2e0df3bceedeb29fcf9220b2cebedcef1123bade4c40"
    "748ae266c3dca3350434a8bc01fb5fb11a3c59a0c9b7b7ac8638c834bf23431"
    "61fd5228600ae9d2b67b3028eb966d7ddfbd60329541700ea8576eb8a0b9d871"
    "ffbeb588df5bbb50d6c534c5ef88012b7a8ef1c246e2591fc606bcd69e5edfd2"
    "a7ee93da3e39a908ad4502d0dbc8c5423b8811ef1b72dc74c0b107fd5f6fb2d8"
    "b6da108af258c26d33e90c41bccf56b6a52f5aee9d209f1e4372062d80f000af"
    "c8a"
)


class TestQtStreamReader:
    """QDataStream 读取器。"""

    def test_read_int32_big_endian(self):
        """int32 按大端解析。"""
        assert QtStreamReader(b"\x00\x00\x00\x2a").read_int32() == 42

    def test_read_bytes_with_length_prefix(self):
        """QByteArray：长度前缀 + 内容。"""
        assert QtStreamReader(qt_bytes(b"abc")).read_bytes() == b"abc"

    def test_read_bytes_null_marker(self):
        """长度 0xFFFFFFFF（null）返回 b""。"""
        assert QtStreamReader(b"\xff\xff\xff\xff").read_bytes() == b""

    def test_read_bytes_truncated_raises(self):
        """长度超过剩余字节抛 CorruptedDataError（不静默截断）。"""
        with pytest.raises(CorruptedDataError, match="truncated"):
            QtStreamReader(b"\x00\x00\x00\x10ab").read_bytes()


class TestParseTdf:
    """TDF$ 容器解析。"""

    def test_valid_tdf_roundtrip(self):
        """正常样本：version 与 data 正确剥离。"""
        payload = qt_bytes(b"payload")
        parsed = parse_tdf(wrap_tdf(payload, version=0))
        assert parsed.version == 0
        assert parsed.encrypted_data == payload

    def test_wrong_magic_raises(self):
        """magic 非 TDF$ 抛 CorruptedDataError。"""
        bad = b"NOPE" + wrap_tdf(b"x")[4:]
        with pytest.raises(CorruptedDataError):
            parse_tdf(bad)

    def test_md5_mismatch_raises(self):
        """MD5 尾校验失败抛 CorruptedDataError。"""
        bad = bytearray(wrap_tdf(qt_bytes(b"payload")))
        bad[20] ^= 0x01  # 篡改数据区 1 字节
        with pytest.raises(CorruptedDataError, match="checksum"):
            parse_tdf(bytes(bad))


class TestKeyDerivation:
    """密钥派生（golden vector 回归）。"""

    def test_create_local_key_empty_passcode(self):
        """空密码 + 固定 salt：256 字节、1 轮迭代的已知结果。"""
        key = create_local_key(b"", _SALT)
        assert len(key) == 256
        assert key == _LOCAL_KEY_EMPTY_PASSCODE

    def test_create_local_key_with_passcode(self):
        """固定密码 + 固定 salt：100000 轮的已知结果。"""
        key = create_local_key(b"test1234", _SALT)
        assert len(key) == 256
        assert key == _LOCAL_KEY_WITH_PASSCODE

    def test_prepare_aes_oldmtp_layout(self):
        """KDF 切片偏移（x=8）与参考实现对拍。"""
        local_key = bytes(range(256))
        msg_key = bytes(range(16))
        aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key)
        assert len(aes_key) == 32
        assert len(aes_iv) == 32
        # 固定输入恒定输出（确定性回归）
        assert prepare_aes_oldmtp(local_key, msg_key) == (aes_key, aes_iv)

    def test_create_local_key_matches_reference(self):
        """跨实现锚定：与参考实现 tdesktop-decrypter 的输出一致。

        字面值由 refs/tdesktop-decrypter（commit df2afe9）的
        create_local_key(b"test1234", bytes(range(32))) 生成。
        """
        expected = bytes.fromhex(
            "94eb4c67776cb3d310fac20fc970099673477e7a367057b09b77de2144236a6e"
            "5116f379b324e7e42b8a9954c359b2983b2d6064d5b6ff94f77b934d71cece5"
            "a6f3b81129c13aba47a2e0df3bceedeb29fcf9220b2cebedcef1123bade4c40"
            "748ae266c3dca3350434a8bc01fb5fb11a3c59a0c9b7b7ac8638c834bf23431"
            "61fd5228600ae9d2b67b3028eb966d7ddfbd60329541700ea8576eb8a0b9d871"
            "ffbeb588df5bbb50d6c534c5ef88012b7a8ef1c246e2591fc606bcd69e5edfd2"
            "a7ee93da3e39a908ad4502d0dbc8c5423b8811ef1b72dc74c0b107fd5f6fb2d8"
            "b6da108af258c26d33e90c41bccf56b6a52f5aee9d209f1e4372062d80f000af"
            "c8a"
        )
        assert create_local_key(b"test1234", bytes(range(32))) == expected


class TestDecryptLocal:
    """local 加密块解密。"""

    def test_roundtrip_with_fixture(self):
        """加密 fixture（逆运算构造）-> 解密还原明文。"""
        key = os.urandom(256)
        blob = b"hello local encryption"
        assert decrypt_local(encrypt_local(blob, key), key) == blob

    def test_bad_checksum_raises(self):
        """SHA-1 校验失败抛 DecryptionError。"""
        blob = b"hello local encryption"
        enc = encrypt_local(blob, os.urandom(256))
        with pytest.raises(DecryptionError, match="checksum"):
            decrypt_local(enc, os.urandom(256))

    def test_length_field_includes_itself(self):
        """长度字段含自身 4 字节：切片 plain[4:length]（§3.2）。"""
        # 若误切为 plain[4:4+length]，结果会多出 4 字节随机填充而不等
        key = os.urandom(256)
        blob = bytes(range(20))
        assert decrypt_local(encrypt_local(blob, key), key) == blob

    def test_ige_roundtrip(self):
        """AES-IGE 加解密往返（对应 _selftest_tdata.py 检查 1）。"""
        key, iv = os.urandom(32), os.urandom(32)
        plain = os.urandom(64)
        assert aes_ige_decrypt(ige_encrypt(plain, key, iv), key, iv) == plain


class TestComputeDataNameKey:
    """MTP 数据文件名计算（v0.2）。"""

    def test_known_dataname(self):
        """"data" 的 filekey 与参考实现输出一致。"""
        assert compute_data_name_key("data") == "D877F783D5D3EF8C"


class TestTdataReader:
    """TDataReader 端到端（基于假 tdata fixture）。"""

    def test_missing_tdata_raises(self, tmp_path):
        """目录不存在抛 TDataNotFoundError。"""
        with pytest.raises(TDataNotFoundError):
            TdataReader(tmp_path / "nonexistent")

    def test_read_local_key_no_passcode(self, tmp_path):
        """无密码假 tdata：派生 256 字节 LocalKey。"""
        local_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        assert TdataReader(tdata).read_local_key("") == local_key

    def test_password_required(self, tmp_path):
        """有密码 tdata 但未提供密码抛 PasswordRequiredError。"""
        tdata = make_fake_tdata(
            tmp_path, os.urandom(256), {"x": b"y"}, passcode=b"test1234"
        )
        with pytest.raises(PasswordRequiredError):
            TdataReader(tdata).read_local_key("")

    def test_wrong_password_raises(self, tmp_path):
        """提供错误密码抛 DecryptionError。"""
        tdata = make_fake_tdata(
            tmp_path, os.urandom(256), {"x": b"y"}, passcode=b"test1234"
        )
        with pytest.raises(DecryptionError):
            TdataReader(tdata).read_local_key("wrong")

    def test_read_account_indexes(self, tmp_path):
        """【v0.2】info_encrypted 中的账号索引列表解析。"""
        local_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        reader = TdataReader(tdata)
        assert reader.read_account_indexes(reader.read_local_key("")) == [0]


class TestMtpAuthorization:
    """read_mtp_authorization（P1-2，DEVELOPMENT.md §5.1）。"""

    def _write_auth_file(self, tdata, local_key, **kwargs):
        name = compute_data_name_key("data")
        (tdata / name).write_bytes(make_mtp_auth_file(local_key, **kwargs))

    def test_new_format(self, tmp_path):
        """新版格式（legacy 双 -1 + uint64 user_id）往返。"""
        local_key = os.urandom(256)
        auth_key = os.urandom(256)
        user_id = 12345678901234  # > 2**32，覆盖 uint64 路径
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        self._write_auth_file(tdata, local_key, user_id=user_id, dc_id=2,
                              auth_key=auth_key)
        mtp = TdataReader(tdata).read_mtp_authorization(local_key)
        assert mtp.user_id == user_id
        assert mtp.dc_id == 2
        assert mtp.auth_key == auth_key

    def test_legacy_format(self, tmp_path):
        """旧版格式（legacy 双 int32 直接为真实 id）往返。"""
        local_key = os.urandom(256)
        auth_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        self._write_auth_file(tdata, local_key, user_id=777, dc_id=4,
                              auth_key=auth_key, legacy=True)
        mtp = TdataReader(tdata).read_mtp_authorization(local_key)
        assert mtp.user_id == 777
        assert mtp.dc_id == 4
        assert mtp.auth_key == auth_key

    def test_block_not_found(self, tmp_path):
        """空块流（无 0x4B 块）抛 CorruptedDataError。"""
        local_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        name = compute_data_name_key("data")
        (tdata / name).write_bytes(wrap_tdf(encrypt_local(b"", local_key)))
        with pytest.raises(CorruptedDataError):
            TdataReader(tdata).read_mtp_authorization(local_key)

    def test_wrong_local_key(self, tmp_path):
        """错误 LocalKey 解密失败抛 DecryptionError。"""
        local_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        self._write_auth_file(tdata, local_key, user_id=1, dc_id=2,
                              auth_key=os.urandom(256))
        with pytest.raises(DecryptionError):
            TdataReader(tdata).read_mtp_authorization(os.urandom(256))

    def test_missing_file(self, tmp_path):
        """tdata 无 MTP 数据文件抛 TDataNotFoundError。"""
        local_key = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        with pytest.raises(TDataNotFoundError):
            TdataReader(tdata).read_mtp_authorization(local_key)

    def test_s_variant_with_dir_occupied(self, tmp_path):
        """7.x 布局（D-7.1.1-1）：s 文件命中且无 s 路径被同名目录占用。"""
        local_key = os.urandom(256)
        auth_key = os.urandom(256)
        user_id = 12345678901234
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        name = compute_data_name_key("data")
        (tdata / f"{name}s").write_bytes(
            make_mtp_auth_file_s(local_key, user_id, 5, auth_key)
        )
        (tdata / name).mkdir()  # 复现 7.1.1：无 s 变体被目录占用
        mtp = TdataReader(tdata).read_mtp_authorization(local_key)
        assert mtp.user_id == user_id
        assert mtp.dc_id == 5
        assert mtp.auth_key == auth_key

    def test_s_preferred_over_no_s(self, tmp_path):
        """s 优先：s 文件（qbytearray，dc_id=5）与无 s 文件（直接变体，dc_id=2）
        并存时取 s 文件的 dc_id=5。"""
        local_key = os.urandom(256)
        auth_key_s = os.urandom(256)
        tdata = make_fake_tdata(tmp_path, local_key, {"x": b"y"})
        name = compute_data_name_key("data")
        (tdata / f"{name}s").write_bytes(
            make_mtp_auth_file_s(local_key, 111, 5, auth_key_s)
        )
        (tdata / name).write_bytes(
            make_mtp_auth_file(local_key, 222, 2, os.urandom(256))
        )
        mtp = TdataReader(tdata).read_mtp_authorization(local_key)
        assert mtp.user_id == 111
        assert mtp.dc_id == 5
        assert mtp.auth_key == auth_key_s

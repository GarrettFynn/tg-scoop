"""golden 文件交叉锚定（P0-11 收尾，DEVELOPMENT.md §9.1 末段）。

tests/fixtures/ 的加密 fixture 走"自有加密逆运算"路线，加解密可能犯
同一个错误而相互掩盖。本文件的 golden 向量由**参考实现**生成
（scripts/generate_golden.py，冻结于 tests/golden/golden_vectors.json）：

- local 链（无密码 / 有密码两条）：refs/tdesktop-decrypter 的实际代码
  + tgcrypto 真实 IGE 加密，我们这边逐层断言回解。
- TDEF 链：派生公式转录自 refs/telegram-cache-decryption；CTR 密钥流
  由 tgcrypto 生成并经 pycryptodome MODE_CTR 交叉断言（生成时）。

pytest 只消费 frozen JSON，运行不需要 tgcrypto；重新生成才需要
（见 scripts/generate_golden.py docstring）。
"""

import json
from pathlib import Path

import pytest

from tg_scoop.cache_decryptor import decrypt_storage_file, derive_storage_key_iv
from tg_scoop.tdata_reader import (
    aes_ige_decrypt,
    create_local_key,
    decrypt_local,
    prepare_aes_oldmtp,
)

GOLDEN = json.loads(
    (Path(__file__).resolve().parent / "golden" / "golden_vectors.json").read_text(
        encoding="utf-8"
    )
)

LOCAL_CHAINS = GOLDEN["local_chains"]
assert len(LOCAL_CHAINS) == 2  # 无密码 + 有密码，缺一则生成器契约被破坏


def _h(chain: dict, field: str) -> bytes:
    return bytes.fromhex(chain[field])


class TestLocalChain:
    """local 解密链逐层锚定：KDF → MTProto 旧式 KDF → IGE → 完整帧。"""

    @pytest.mark.parametrize("chain", LOCAL_CHAINS, ids=lambda c: c["name"])
    def test_create_local_key(self, chain):
        """PBKDF2 派生与参考实现逐字节一致（无密码 1 轮 / 有密码 10 万轮）。"""
        key = create_local_key(_h(chain, "passcode_hex"), _h(chain, "salt_hex"))
        assert key.hex() == chain["expected_passcode_key_hex"]

    @pytest.mark.parametrize("chain", LOCAL_CHAINS, ids=lambda c: c["name"])
    def test_prepare_aes_oldmtp(self, chain):
        """旧式 KDF 的 key/iv 切片布局与参考实现一致。"""
        key, iv = prepare_aes_oldmtp(
            _h(chain, "expected_passcode_key_hex"), _h(chain, "msg_key_hex")
        )
        assert key.hex() == chain["aes_key_hex"]
        assert iv.hex() == chain["aes_iv_hex"]

    @pytest.mark.parametrize("chain", LOCAL_CHAINS, ids=lambda c: c["name"])
    def test_aes_ige_decrypt(self, chain):
        """纯 Python IGE 与 tgcrypto（C 实现）对拍：密文解回参考明文。"""
        plain = aes_ige_decrypt(
            _h(chain, "encrypted_hex")[16:],  # 去掉 msg_key 前缀
            _h(chain, "aes_key_hex"),
            _h(chain, "aes_iv_hex"),
        )
        assert plain.hex() == chain["plain_padded_hex"]

    @pytest.mark.parametrize("chain", LOCAL_CHAINS, ids=lambda c: c["name"])
    def test_decrypt_local_end_to_end(self, chain):
        """完整 local 加密块：SHA-1 校验 + 长度帧切片后还原 payload。"""
        plain = decrypt_local(
            _h(chain, "encrypted_hex"), _h(chain, "expected_passcode_key_hex")
        )
        assert plain.hex() == chain["payload_hex"]


class TestTdefChain:
    """TDEF 缓存文件锚定：派生 → CTR 流连续性（校验块+媒体同一条流）。"""

    def test_derive_storage_key_iv(self):
        chain = GOLDEN["tdef_chain"]
        key, iv = derive_storage_key_iv(
            _h(chain, "local_key_hex"), _h(chain, "salt_hex")
        )
        assert key.hex() == chain["expected_real_key_hex"]
        assert iv.hex() == chain["expected_iv_hex"]

    def test_decrypt_storage_file_end_to_end(self):
        """参考 CTR 密钥流生成的整文件，我们的解密器还原媒体字节。

        媒体明文长度非 16 对齐且带真实 PNG 头：同时锚定尾块处理与
        计数器跨"校验块→媒体"的连续性（若媒体段错误地从块 0 重置，
        本用例必然失败）。
        """
        chain = GOLDEN["tdef_chain"]
        media = decrypt_storage_file(_h(chain, "tdef_hex"), _h(chain, "local_key_hex"))
        assert media.hex() == chain["media_hex"]
        assert media.startswith(b"\x89PNG\r\n\x1a\n")
        assert len(media) % 16 != 0

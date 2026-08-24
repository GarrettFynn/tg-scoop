#!/usr/bin/env python
"""golden 测试向量生成器（P0-11 收尾，DEVELOPMENT.md §9.1 交叉锚定策略）。

用途
----
tests/ 的加密 fixture 走"自有加密逆运算"路线，存在加解密犯同一个错误
而相互掩盖的风险。本脚本用 refs/ 下的**参考实现**生成 golden 向量，
冻结进 tests/golden/golden_vectors.json，pytest 用例再以我们的实现
对 frozen 值逐字节锚定：

- local 解密链（key_datas / 设密码与无密码两条）：
  create_local_key / prepare_aes_oldmtp / aes_ige_decrypt / decrypt_local
  全部由 refs/tdesktop-decrypter 的实际代码 + tgcrypto 的真实 IGE 生成。
- TDEF 缓存文件链：
  derive_storage_key_iv / decrypt_storage_file
  派生公式逐字转录自 refs/telegram-cache-decryption 的 storage_file_read
  （其 OpenSSL FFI 在 Windows 不可运行）；CTR 密钥流由 tgcrypto.ctr256
  生成，并与 pycryptodome AES.MODE_CTR 交叉断言一致——两个相互独立的
  CTR 实现认同同一份密文，计数器端序/进位错误无处藏身。

重新生成（仅在算法或参考实现变更后，需主脑指令）::

    .venv/Scripts/python scripts/generate_golden.py

依赖：tgcrypto（dev 依赖，仅本脚本需要；pytest 用例只消费 frozen JSON，
运行时不需要 tgcrypto）。输出确定性：全部字节由 sha256 计数器流从固定
种子派生，重复运行产物逐字节相同。
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REF_CRYPTO = (
    REPO_ROOT / "refs" / "tdesktop-decrypter" / "tdesktop_decrypter" / "crypto.py"
)
GOLDEN_PATH = REPO_ROOT / "tests" / "golden" / "golden_vectors.json"

PASSCODE_WITH = b"tg-scoop-golden-passcode"


def det_bytes(seed: str, n: int) -> bytes:
    """确定性字节流：sha256(seed || counter_le) 链接，保证可复现。"""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed.encode() + counter.to_bytes(4, "little")).digest()
        counter += 1
    return bytes(out[:n])


def load_reference_crypto():
    """按文件路径加载 refs/tdesktop-decrypter 的 crypto.py（绕开包 __init__）。"""
    spec = importlib.util.spec_from_file_location("ref_crypto", REF_CRYPTO)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load reference crypto from {REF_CRYPTO}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_local_chain(ref, name: str, passcode: bytes, salt: bytes) -> dict:
    """用参考实现构建一条 local 解密链 golden（明文→密文全留档）。"""
    import tgcrypto

    passcode_key = ref.create_local_key(passcode, salt)
    payload = (
        f"tg-scoop golden anchor payload ({name}): ".encode()
        + det_bytes(f"golden:payload:{name}", 48)
    )
    # tdesktop 帧格式：4B 小端长度（含自身）+ payload + 随机填充至 16 对齐
    length = 4 + len(payload)
    pad_len = (-length) % 16
    plain = length.to_bytes(4, "little") + payload + det_bytes(
        f"golden:pad:{name}", pad_len
    )

    msg_key = hashlib.sha1(plain).digest()[:16]
    aes_key, aes_iv = ref.prepare_aes_old_mtp(passcode_key, msg_key)
    # 先冻结留档再加密：tgcrypto 会原地改写传入的 key/iv 缓冲区
    aes_key_hex, aes_iv_hex = aes_key.hex(), aes_iv.hex()
    ciphertext = tgcrypto.ige256_encrypt(plain, bytearray(aes_key), bytearray(aes_iv))
    encrypted = msg_key + ciphertext

    # 参考实现自校验：golden 必须能被参考实现自己解回
    assert ref.decrypt_local(encrypted, passcode_key) == payload

    return {
        "name": name,
        "passcode_hex": passcode.hex(),
        "salt_hex": salt.hex(),
        "expected_passcode_key_hex": passcode_key.hex(),
        "payload_hex": payload.hex(),
        "plain_padded_hex": plain.hex(),
        "msg_key_hex": msg_key.hex(),
        "aes_key_hex": aes_key_hex,
        "aes_iv_hex": aes_iv_hex,
        "encrypted_hex": encrypted.hex(),
    }


def build_tdef_chain() -> dict:
    """构建 TDEF 缓存文件 golden（CTR 流连续性是锚定重点）。"""
    import tgcrypto
    from Crypto.Cipher import AES

    local_key = det_bytes("golden:tdef:local-key", 256)
    salt = det_bytes("golden:tdef:salt", 64)
    # 派生公式逐字转录自 refs/telegram-cache-decryption storage_file_read
    real_key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:]).digest()[:16]

    header = det_bytes("golden:tdef:header", 16)
    checksum = hashlib.sha256(local_key + salt + header).digest()
    check_block = header + checksum  # 48B，恰好 3 个 CTR 块

    # 媒体明文：真实 PNG 头 + 确定性内容，长度刻意非 16 对齐（尾块锚定）
    media = b"\x89PNG\r\n\x1a\n" + det_bytes("golden:tdef:media", 243)
    assert len(media) % 16 != 0

    blob = check_block + media  # 校验块与媒体共用一条 CTR 流（单次调用天然连续）
    # 传 iv 副本：tgcrypto 会原地改写 iv 缓冲区，副本保证留档与交叉断言用原值
    encrypted = tgcrypto.ctr256_encrypt(blob, real_key, bytearray(iv), bytearray(1))

    # 交叉断言：pycryptodome MODE_CTR（大端计数器）与 tgcrypto 密文一致
    pyc_ctr = AES.new(
        real_key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big")
    )
    assert pyc_ctr.encrypt(blob) == encrypted, "tgcrypto 与 pycryptodome CTR 不一致"

    tdef = b"TDEF" + salt + encrypted

    return {
        "local_key_hex": local_key.hex(),
        "salt_hex": salt.hex(),
        "expected_real_key_hex": real_key.hex(),
        "expected_iv_hex": iv.hex(),
        "header_hex": header.hex(),
        "media_hex": media.hex(),
        "tdef_hex": tdef.hex(),
    }


def self_check_with_ours(golden: dict) -> None:
    """生成后立刻用我们的实现回解全部 golden，失配则生成失败。"""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from tg_scoop.cache_decryptor import decrypt_storage_file
    from tg_scoop.tdata_reader import create_local_key, decrypt_local

    for chain in golden["local_chains"]:
        key = create_local_key(
            bytes.fromhex(chain["passcode_hex"]), bytes.fromhex(chain["salt_hex"])
        )
        assert key.hex() == chain["expected_passcode_key_hex"], chain["name"]
        plain = decrypt_local(bytes.fromhex(chain["encrypted_hex"]), key)
        assert plain.hex() == chain["payload_hex"], chain["name"]

    tdef = golden["tdef_chain"]
    media = decrypt_storage_file(
        bytes.fromhex(tdef["tdef_hex"]), bytes.fromhex(tdef["local_key_hex"])
    )
    assert media.hex() == tdef["media_hex"], "tdef_chain"


def main() -> None:
    ref = load_reference_crypto()
    salt = det_bytes("golden:kdf-salt", 64)

    golden = {
        "meta": {
            "generator": "scripts/generate_golden.py（确定性，可重复运行）",
            "references": [
                "refs/tdesktop-decrypter/tdesktop_decrypter/crypto.py"
                "（local 链：KDF/prepare_aes_old_mtp/IGE 均为参考实现实际代码）",
                "refs/telegram-cache-decryption storage_file_read"
                "（TDEF 链：派生公式转录；CTR 由 tgcrypto 生成并经"
                " pycryptodome MODE_CTR 交叉断言）",
            ],
        },
        "local_chains": [
            build_local_chain(ref, "no_passcode", b"", salt),
            build_local_chain(ref, "with_passcode", PASSCODE_WITH, salt),
        ],
        "tdef_chain": build_tdef_chain(),
    }

    self_check_with_ours(golden)

    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(
        json.dumps(golden, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"golden written: {GOLDEN_PATH} ({GOLDEN_PATH.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

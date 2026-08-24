"""extractor 自测：命名净化、去重、mtime、extract_all 统计与幂等。

运行：
    .venv/Scripts/python _selftest_extract.py
"""

import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "src")

from _selftest_common import make_tdef

from tg_scoop.cache_decryptor import CacheDecryptor
from tg_scoop.exceptions import ExtractionError
from tg_scoop.extractor import (
    MAX_NAME_ATTEMPTS,
    Extractor,
    build_fallback_name,
    sanitize_filename,
    save_media,
    unique_path,
)
from tg_scoop.media_detector import PNG_MAGIC

LOCAL_KEY = os.urandom(256)
PNG_DATA = PNG_MAGIC + os.urandom(500)
MP4_DATA = b"\x00\x00\x00\x18ftypisom" + os.urandom(500)
GARBAGE_DATA = os.urandom(300)  # 能解密但不可识别 -> skipped


def main():
    # 1. sanitize_filename
    assert sanitize_filename('a<b>:"c/\\d|e?f*g') == "a_b___c__d_e_f_g"
    assert sanitize_filename("bad\x00name\x1f") == "bad_name_"
    assert sanitize_filename("trailing. . .") == "trailing"
    assert sanitize_filename("x" * 300) == "x" * 200
    assert sanitize_filename("") == "unnamed"
    assert sanitize_filename('<>:"/\\|?*') == "_________"
    print("1. sanitize_filename OK")

    # 2. build_fallback_name：格式 + 确定性（幂等前提）
    mtime = datetime(2026, 3, 14, 15, 30, 22)
    digest = bytes.fromhex("a1b2c3d4" + "00" * 28)
    from tg_scoop.media_detector import MediaType

    name1 = build_fallback_name(mtime, digest, MediaType.MP4, sender="Alice")
    assert name1 == "Alice_20260314_153022_a1b2c3d4.mp4", name1
    name2 = build_fallback_name(mtime, digest, MediaType.MP4, sender="Alice")
    assert name1 == name2  # 同一输入恒定同名
    print("2. build_fallback_name OK")

    # 3. unique_path：序号后缀 + 绝不覆盖
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        (out / "video.mp4").write_bytes(b"a")
        (out / "video (1).mp4").write_bytes(b"b")
        assert unique_path(out, "video.mp4").name == "video (2).mp4"
        assert unique_path(out, "new.png").name == "new.png"
        # 内容不被触碰
        assert (out / "video.mp4").read_bytes() == b"a"
    print("3. unique_path OK")

    # 4. save_media：落盘 + mtime 恢复
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out"
        ts = datetime(2026, 1, 2, 3, 4, 5)
        saved = save_media(b"payload", out, "f.bin", mtime=ts)
        assert saved.read_bytes() == b"payload"
        assert abs(saved.stat().st_mtime - ts.timestamp()) < 1e-6
    print("4. save_media OK")

    # 5. extract_all：混合缓存目录的统计正确性
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        (cache / "good_png").write_bytes(make_tdef(LOCAL_KEY, PNG_DATA))
        (cache / "good_mp4").write_bytes(make_tdef(LOCAL_KEY, MP4_DATA))
        (cache / "corrupted").write_bytes(os.urandom(200))  # 解密失败
        (cache / "unreadable").write_bytes(make_tdef(LOCAL_KEY, GARBAGE_DATA))
        (cache / "map0").write_bytes(b"index")  # 被遍历过滤

        out = Path(tmp) / "out"
        stats = Extractor(CacheDecryptor(LOCAL_KEY)).extract_all(cache, out)
        assert stats.succeeded == 2, stats
        assert stats.failed == 1, stats
        assert stats.skipped == 1, stats
        assert stats.duplicates == 0, stats
        outputs = sorted(p.name for p in out.iterdir())
        assert len(outputs) == 2
        assert any(n.endswith(".png") for n in outputs)
        assert any(n.endswith(".mp4") for n in outputs)
        # 内容还原正确
        contents = {p.read_bytes() for p in out.iterdir()}
        assert PNG_DATA in contents and MP4_DATA in contents

        # 6. 幂等：同一 Extractor 再跑 -> 本次运行内查重
        extractor = Extractor(CacheDecryptor(LOCAL_KEY))
        extractor.extract_all(cache, out)
        stats2 = extractor.extract_all(cache, out)
        assert stats2.duplicates == 2 and stats2.succeeded == 0, stats2

        # 7. 跨运行幂等：新 Extractor（无 _seen）靠"同名同内容"判定重复
        stats3 = Extractor(CacheDecryptor(LOCAL_KEY)).extract_all(cache, out)
        assert stats3.duplicates == 2 and stats3.succeeded == 0, stats3
        assert len(list(out.iterdir())) == 2  # 没有产生 (1) 后缀文件
    print("5-7. extract_all stats + idempotency OK")

    # 8. 序号耗尽保护
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        import tg_scoop.extractor as ext_mod

        original = ext_mod.MAX_NAME_ATTEMPTS
        ext_mod.MAX_NAME_ATTEMPTS = 3
        try:
            for i in range(4):
                suffix = "" if i == 0 else f" ({i})"
                (out / f"f{suffix}.bin").write_bytes(b"x")
            try:
                unique_path(out, "f.bin")
                raise AssertionError("exhaustion not detected")
            except ExtractionError:
                pass
        finally:
            ext_mod.MAX_NAME_ATTEMPTS = original
    print("8. naming exhaustion guard OK")

    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

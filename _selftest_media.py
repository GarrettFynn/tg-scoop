"""media_detector 自测：9 种类型 + 全部边界条件（DEVELOPMENT.md §4）。

运行：
    .venv/Scripts/python _selftest_media.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from tg_scoop.media_detector import (
    MIN_SNIFF_LEN,
    EBML_MAGIC,
    JPEG_MAGIC,
    PNG_MAGIC,
    MediaDetector,
    MediaType,
    sniff_media_type,
)

detector = MediaDetector()


def h(body: bytes, pad: int = 64) -> bytes:
    """把构造的签名填充到可靠长度（默认 64 字节）。"""
    return body + bytes(pad)


def main():
    # 1. 图片格式
    assert detector.sniff(h(PNG_MAGIC)) is MediaType.PNG
    assert detector.sniff(h(JPEG_MAGIC + b"\xe0")) is MediaType.JPEG
    assert detector.sniff(h(JPEG_MAGIC + b"\xdb")) is MediaType.JPEG  # 第 4 字节任意
    assert detector.sniff(h(b"GIF87a")) is MediaType.GIF
    assert detector.sniff(h(b"GIF89a")) is MediaType.GIF
    assert detector.sniff(h(b"RIFF\x24\x00\x00\x00WEBP")) is MediaType.WEBP
    print("1. image formats OK")

    # 2. 视频格式
    assert detector.sniff(h(b"RIFF\x00\x00\x00\x00AVI ")) is MediaType.AVI
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypisom")) is MediaType.MP4
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypmp42")) is MediaType.MP4
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypM4V ")) is MediaType.MP4
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypqt  ")) is MediaType.MOV
    print("2. video formats OK")

    # 3. EBML：DocType 子串查找 + 默认 MKV
    assert detector.sniff(h(EBML_MAGIC + b"\x9f\x42\x86\x81\x01") + b"...webm...") is MediaType.WEBM
    assert detector.sniff(h(EBML_MAGIC) + b"matroska") is MediaType.MKV
    assert detector.sniff(h(EBML_MAGIC)) is MediaType.MKV  # 无 DocType 默认 MKV
    print("3. EBML variants OK")

    # 4. 防误判：ftyp 非白名单 brand、RIFF 非媒体 form type
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypM4A ")) is None  # m4a 音频
    assert detector.sniff(h(b"\x00\x00\x00\x18ftypheic")) is None  # heic 图片
    assert detector.sniff(h(b"RIFF\x00\x00\x00\x00WAVE")) is None  # wav 音频
    print("4. false-positive guards OK")

    # 5. 边界：空输入、过短、随机字节——全部 None 且不抛异常
    assert detector.sniff(b"") is None
    assert detector.sniff(PNG_MAGIC[: MIN_SNIFF_LEN - 1]) is None  # 11 字节
    assert detector.sniff(bytes(range(100))) is None
    print("5. boundary conditions OK")

    # 6. sniff_file 与模块级函数
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "sample.bin"
        p.write_bytes(h(PNG_MAGIC))
        assert detector.sniff_file(p) is MediaType.PNG
    assert sniff_media_type(h(PNG_MAGIC)) is MediaType.PNG
    assert sniff_media_type(b"") is None
    print("6. sniff_file + module-level function OK")

    print("\nALL SELF-TESTS PASSED")


if __name__ == "__main__":
    main()

"""MediaDetector 单元测试骨架。

覆盖点对应 DEVELOPMENT.md §9.1：每种类型 1 个真实文件头样本 +
边界条件（<12 字节、空输入、ftyp 无 brand、EBML 无 DocType）。
"""

import pytest

from tg_scoop.media_detector import (
    MIN_SNIFF_LEN,
    MediaDetector,
    MediaType,
    sniff_media_type,
)

# magic 常量以字面值嵌入（回归锚定，语义见 DEVELOPMENT.md §4.1）
_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff"
_EBML = b"\x1a\x45\xdf\xa3"


def h(body: bytes, pad: int = 64) -> bytes:
    """把构造的签名填充到可靠长度（默认 64 字节）。"""
    return body + bytes(pad)


@pytest.fixture
def detector() -> MediaDetector:
    """默认嗅探器实例。"""
    return MediaDetector()


class TestImageFormats:
    """图片格式识别。"""

    def test_png(self, detector):
        """89 50 4E 47 0D 0A 1A 0A -> PNG。"""
        assert detector.sniff(h(_PNG)) is MediaType.PNG

    def test_jpeg(self, detector):
        """FF D8 FF -> JPEG（第 4 字节任意）。"""
        assert detector.sniff(h(_JPEG + b"\xe0")) is MediaType.JPEG
        assert detector.sniff(h(_JPEG + b"\xdb")) is MediaType.JPEG

    def test_gif87a_and_89a(self, detector):
        """GIF87a / GIF89a -> GIF。"""
        assert detector.sniff(h(b"GIF87a")) is MediaType.GIF
        assert detector.sniff(h(b"GIF89a")) is MediaType.GIF

    def test_webp(self, detector):
        """RIFF....WEBP -> WEBP。"""
        assert detector.sniff(h(b"RIFF\x24\x00\x00\x00WEBP")) is MediaType.WEBP


class TestVideoFormats:
    """视频格式识别。"""

    def test_avi(self, detector):
        """RIFF....'AVI '（含空格）-> AVI。"""
        assert detector.sniff(h(b"RIFF\x00\x00\x00\x00AVI ")) is MediaType.AVI

    def test_mp4_brand_whitelist(self, detector):
        """ftyp + isom/mp42 等白名单 brand -> MP4。"""
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypisom")) is MediaType.MP4
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypmp42")) is MediaType.MP4
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypM4V ")) is MediaType.MP4

    def test_mov_brand(self, detector):
        """ftyp + 'qt  ' brand -> MOV。"""
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypqt  ")) is MediaType.MOV

    def test_ftyp_unknown_brand_returns_none(self, detector):
        """ftyp 但 brand 不在白名单（如 m4a/heic）-> None（§4.2）。"""
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypM4A ")) is None
        assert detector.sniff(h(b"\x00\x00\x00\x18ftypheic")) is None
        assert detector.sniff(h(b"RIFF\x00\x00\x00\x00WAVE")) is None

    def test_webm_doctype(self, detector):
        """EBML 头 + DocType webm -> WEBM。"""
        assert detector.sniff(h(_EBML + b"\x9f\x42\x86\x81\x01") + b"...webm...") is MediaType.WEBM

    def test_mkv_doctype(self, detector):
        """EBML 头 + DocType matroska -> MKV。"""
        assert detector.sniff(h(_EBML) + b"matroska") is MediaType.MKV

    def test_ebml_without_doctype_defaults_mkv(self, detector):
        """EBML 头但前 4096 字节无 DocType -> 默认 MKV。"""
        assert detector.sniff(h(_EBML)) is MediaType.MKV


class TestBoundaryConditions:
    """边界条件（§4.2）。"""

    def test_empty_input_returns_none(self, detector):
        """b"" -> None，不抛异常。"""
        assert detector.sniff(b"") is None

    def test_shorter_than_min_returns_none(self, detector):
        """不足 MIN_SNIFF_LEN(12) 字节 -> None。"""
        assert detector.sniff(_PNG[: MIN_SNIFF_LEN - 1]) is None

    def test_unrecognized_returns_none(self, detector):
        """随机字节 -> None（计入 skipped 而非失败）。"""
        assert detector.sniff(bytes(range(100))) is None

    def test_module_level_function(self):
        """sniff_media_type 与 MediaDetector().sniff 行为一致。"""
        assert sniff_media_type(h(_PNG)) is MediaType.PNG
        assert sniff_media_type(b"") is None


def test_sniff_file(detector, tmp_path):
    """sniff_file 读取文件头判定（对应 _selftest_media.py 检查 6）。"""
    p = tmp_path / "sample.bin"
    p.write_bytes(h(_PNG))
    assert detector.sniff_file(p) is MediaType.PNG

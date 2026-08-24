"""媒体类型识别（magic bytes 嗅探）。

对应 DEVELOPMENT.md §4：先解密后识别，本模块对加密无感知，
输入输出都是明文字节。嗅探只保证"扩展名大致正确"，不做
内容级校验（不验证可播放性，理由见 §4.3）。
"""

from enum import Enum
from pathlib import Path

SNIFF_LEN = 4096
"""嗅探读取长度：RIFF/ftyp 判定 12 字节足够，但 EBML 的 DocType
实践中都在前几百字节；4096 是可靠识别与 IO 开销的平衡点。"""

MIN_SNIFF_LEN = 12
"""最小长度门限：RIFF/ftyp 判定至少需要 12 字节，更短的输入
任何结论都不可靠，直接返回 None。"""


class MediaType(Enum):
    """支持的媒体类型（值为扩展名，不含点）。"""

    MP4 = "mp4"
    WEBM = "webm"
    AVI = "avi"
    MKV = "mkv"
    MOV = "mov"
    JPEG = "jpg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"


# ISO BMFF (ftyp) brand 白名单：只查 ftyp 前缀会把 .m4a/.heic
# 误判为 MP4（DEVELOPMENT.md §4.2），本项目只管视频/图片。
MP4_BRANDS = frozenset({"isom", "iso2", "mp41", "mp42", "avc1", "M4V ", "dash"})
MOV_BRAND = "qt  "

# magic bytes 映射表（DEVELOPMENT.md §4.1）。
# 判定规则实现在 MediaDetector.sniff 中：
#   PNG  89 50 4E 47 0D 0A 1A 0A（全匹配 8 字节）
#   JPEG FF D8 FF（前 3 字节）
#   GIF  "GIF87a" / "GIF89a"
#   WEBP [0:4]=="RIFF" 且 [8:12]=="WEBP"
#   AVI  [0:4]=="RIFF" 且 [8:12]=="AVI "（含空格）
#   MP4  [4:8]=="ftyp" 且 brand ∈ MP4_BRANDS
#   MOV  [4:8]=="ftyp" 且 brand == "qt  "
#   MKV/WEBM [0:4]==1A 45 DF A3（EBML）；前 4096 字节内找 DocType：
#            含 b"webm" -> WEBM，含 b"matroska" -> MKV，都没有默认 MKV
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGICS = (b"GIF87a", b"GIF89a")
RIFF_MAGIC = b"RIFF"
EBML_MAGIC = b"\x1a\x45\xdf\xa3"


class MediaDetector:
    """无状态媒体类型嗅探器。"""

    def sniff(self, header: bytes) -> MediaType | None:
        """根据文件头判定媒体类型。

        必须接受任意长度输入（含 b""）而不抛异常——损坏的缓存
        条目可能不足 16 字节；不足 MIN_SNIFF_LEN 直接返回 None。

        判定顺序：定长前缀 -> RIFF 容器 -> ISO BMFF(brand 白名单)
        -> EBML(DocType 子串)，前缀唯一性高的优先。

        Args:
            header: 文件头字节（建议至少 12 字节，最多 SNIFF_LEN）。

        Returns:
            识别出的 MediaType；无法识别返回 None。
            无法识别 != 失败：大概率是缓存元数据等非媒体内容，
            由调用方计入 skipped 统计（DEVELOPMENT.md §4.2）。
        """
        if len(header) < MIN_SNIFF_LEN:
            return None

        # 定长前缀：签名唯一，直接匹配
        if header.startswith(PNG_MAGIC):
            return MediaType.PNG
        if header.startswith(JPEG_MAGIC):
            return MediaType.JPEG
        if header[:6] in GIF_MAGICS:
            return MediaType.GIF

        # RIFF 容器：由 [8:12] 的 form type 区分，其余（WAV 等）不识别
        if header[:4] == RIFF_MAGIC:
            form_type = header[8:12]
            if form_type == b"WEBP":
                return MediaType.WEBP
            if form_type == b"AVI ":  # 含尾随空格
                return MediaType.AVI
            return None

        # ISO BMFF：必须校验 brand，否则 m4a/heic 会误判为 MP4（§4.2）
        if header[4:8] == b"ftyp":
            brand = header[8:12]
            if brand == MOV_BRAND.encode("latin-1"):  # "qt  "
                return MediaType.MOV
            if brand.decode("latin-1") in MP4_BRANDS:
                return MediaType.MP4
            return None

        # EBML：不做完整解析（§4.2），子串查找 DocType
        if header[:4] == EBML_MAGIC:
            window = header[:SNIFF_LEN]
            if b"webm" in window:
                return MediaType.WEBM
            if b"matroska" in window:
                return MediaType.MKV
            return MediaType.MKV  # DocType 缺失时默认 MKV

        return None

    def sniff_file(self, path: Path) -> MediaType | None:
        """读取文件前 SNIFF_LEN 字节并判定媒体类型。

        Args:
            path: 文件路径。

        Returns:
            识别出的 MediaType；无法识别返回 None。
        """
        with Path(path).open("rb") as f:
            return self.sniff(f.read(SNIFF_LEN))


_DEFAULT_DETECTOR = MediaDetector()


def sniff_media_type(header: bytes) -> MediaType | None:
    """模块级便捷函数，等价于 ``MediaDetector().sniff(header)``。

    保留此函数以兼容 DEVELOPMENT.md §1.3 的接口定义。
    """
    return _DEFAULT_DETECTOR.sniff(header)

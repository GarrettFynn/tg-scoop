"""tg-scoop（tg缓存捞）—— 从 Telegram Desktop 本地缓存提取受限媒体。

CLI + 简洁 GUI 双入口工具：读取 tdata/key_datas 派生密钥 → 解密
TDEF 缓存文件 → 通过 magic bytes 识别媒体类型 → 输出到指定目录。

包结构对应 DEVELOPMENT.md §1.2。第三方依赖（pycryptodome、telethon）
一律在函数体内延迟导入，保证 ``import tg_scoop`` 在未安装依赖的
环境下也能成功（便于运行 --help、读取元数据等场景）。
"""

from tg_scoop.exceptions import (
    APIRateLimitError,
    CacheNotFoundError,
    CorruptedDataError,
    DecryptionError,
    ExtractionError,
    MediaTypeError,
    PasswordRequiredError,
    TDataNotFoundError,
    TgScoopError,
)

__version__ = "0.1.0"

__all__ = [
    "APIRateLimitError",
    "CacheNotFoundError",
    "CorruptedDataError",
    "DecryptionError",
    "ExtractionError",
    "MediaTypeError",
    "PasswordRequiredError",
    "TDataNotFoundError",
    "TgScoopError",
    "__version__",
]

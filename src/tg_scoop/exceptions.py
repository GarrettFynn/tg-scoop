"""tg-scoop 自定义异常体系。

对应 DEVELOPMENT.md §7：CLI 层只捕获 ``TgScoopError`` 与 ``OSError``，
各场景的用户提示与退出码由异常类型驱动。
"""


class TgScoopError(Exception):
    """所有 tg-scoop 异常的基类。CLI 只捕获它 + OSError。"""


class TDataNotFoundError(TgScoopError):
    """tdata 目录或 key_datas 文件不存在。"""


class CacheNotFoundError(TgScoopError):
    """user_data/cache 目录不存在或为空。"""


class PasswordRequiredError(TgScoopError):
    """账号设有本地密码，需要提供 --password。"""


class DecryptionError(TgScoopError):
    """解密/校验失败（密码错误、文件损坏、格式不符）。"""


class CorruptedDataError(DecryptionError):
    """TDF 容器级损坏（magic 或 MD5 校验失败）。"""


class MediaTypeError(TgScoopError):
    """媒体类型识别失败。

    注意：按 DEVELOPMENT.md §4.2 的设计，常规嗅探无法识别时返回
    ``None`` 而非抛出本异常；本异常保留给未来的严格模式
    （如显式要求必须识别时）使用。
    """


class APIRateLimitError(TgScoopError):
    """【v0.2】触发 Telegram FloodWait，需要等待后重试。"""


class ExtractionError(TgScoopError):
    """输出阶段错误（如命名序号耗尽）。"""

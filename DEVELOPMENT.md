# tg-scoop 开发指导文档（Development Guide）

> 版本：v0.1（MVP 规划）
> 适用读者：本项目贡献者
> 参考实现：`refs/tgdesktop-cache-decryptor`（上游：[lilydjwg/telegram-cache-decryption](https://github.com/lilydjwg/telegram-cache-decryption)、[Zwylair/tgdesktop-cache-decryptor](https://github.com/Zwylair/tgdesktop-cache-decryptor)），tdata 解析参考 [ntqbit/tdesktop-decrypter](https://github.com/ntqbit/tdesktop-decrypter)

tg-scoop（tg缓存捞）是一个开源工具（CLI + 简洁 GUI 双入口），从 Telegram Desktop 的本地加密缓存（`tdata/user_data/cache/`）中提取被"限制保存内容"（Restrict Saving Content）的视频和图片。本文档是开发的唯一权威依据：所有模块划分、接口、加密细节、命名规则以本文为准，代码实现必须能回溯到本文的某一节。

---

## 目录

1. [项目架构总览](#1-项目架构总览)
2. [数据流详细设计](#2-数据流详细设计)
3. [TDEF 解密规范](#3-tdef-解密规范)
4. [媒体识别策略](#4-媒体识别策略)
5. [MTProto 集成方案（v0.2 规划）](#5-mtproto-集成方案v02-规划)
6. [命名与去重规则](#6-命名与去重规则)
7. [错误处理规范](#7-错误处理规范)
8. [MVP 功能边界](#8-mvp-功能边界)
9. [测试策略](#9-测试策略)
10. [版本里程碑与发布策略](#10-版本里程碑与发布策略)
11. [GUI 设计（CustomTkinter）](#11-gui-设计customtkinter)
12. [附录：TODO.md 草稿](#12-附录-todomd-草稿)

---

## 1. 项目架构总览

### 1.1 设计原则

- **CLI + 简洁 GUI 双入口**：GUI 用 CustomTkinter（轻量纯 Python，见 §11），禁止 PyQt6/PySide 等重型框架。GUI 是核心逻辑之上的薄层，core 模块保持零 GUI 依赖、可独立自测。参考实现用 `QtCore.QDataStream` 读取 Qt 序列化格式，我们用 30 行纯 Python 等价实现（见 §3.4）——这不因引入 GUI 而改变。
- **分层单向依赖**：加密原语（位于 `tdata_reader` / `cache_decryptor`）不知道文件系统，`extractor` 不知道 Telegram。每层可独立测试。
- **先解密后识别**：解密层对媒体类型无感知，识别层对加密无感知。两者通过 `bytes` 交接，便于替换。

### 1.2 模块划分

```
src/tg_scoop/
├── __init__.py          # 包入口：版本号、异常导出
├── cli.py               # 入口：参数解析、流程编排、进度输出
├── exceptions.py        # 全部自定义异常（见 §7）
├── tdata_reader.py      # Qt 流读取、TDF$ 解析、密钥派生、AES-IGE、TDataReader
├── cache_decryptor.py   # TDEF 解析、AES-CTR、缓存遍历、CacheDecryptor
├── media_detector.py    # magic bytes 嗅探、扩展名判定
├── extractor.py         # 命名、去重、落盘、mtime 恢复
└── gui.py               # 【P0-14】CustomTkinter 简洁 GUI（核心薄层，见 §11）
```

**模块归并说明**：初版规划中的 `qt_stream.py` / `crypto.py` / `tdf.py`
三个细粒度模块，已按确认过的文件清单并入 `tdata_reader.py`
（key 链路）与 `cache_decryptor.py`（缓存链路）；`mtproto_client.py`
留待 v0.2 创建。所有函数名与签名保持本文档定义不变，未来如需
拆分是函数级平移、无接口变更。

### 1.3 各模块职责与接口

#### Qt 序列化读取器 — 位于 `tdata_reader.py`

Telegram Desktop 用 `QDataStream`（默认大端）写 tdata 文件。只需实现子集：

```python
from io import BytesIO

class QtStreamReader:
    """QDataStream 格式的只读读取器（big-endian）。

    为什么自己写：PyQt5 只为 `readBytes()`/`readInt32()` 两个调用引入
    上百 MB 的 GUI 依赖，得不偿失。Qt 格式是公开的定长前缀格式，
    纯 Python 实现不足 40 行且行为完全可测。
    """

    def __init__(self, data: bytes) -> None: ...

    def read_int32(self) -> int:
        """读取 4 字节大端有符号整数。"""

    def read_int64(self) -> int:
        """读取 8 字节大端有符号整数。"""

    def read_uint64(self) -> int:
        """读取 8 字节大端无符号整数。"""

    def read_bytes(self) -> bytes:
        """读取 QByteArray：4 字节大端长度前缀 + 内容。

        长度 <= 0（含 0xFFFFFFFF 的 null 标记）返回 b""。
        长度超过剩余字节数时抛 CorruptedDataError，而非静默截断——
        截断会把损坏数据带入 SHA-1 校验，报错信息会误导到"密码错误"。
        """
```

#### 加密原语 — IGE/local 部分位于 `tdata_reader.py`，CTR/TDEF 部分位于 `cache_decryptor.py`

```python
def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    """由用户 passcode 派生 PasscodeKey（256 字节）。

    算法（与 tdesktop `CreateLocalKey` 一致）：
      password = SHA512(salt + passcode + salt)
      key      = PBKDF2-HMAC-SHA512(password, salt, iter, dklen=256)
      iter     = 100000（有密码）/ 1（无密码）

    为什么 dklen=256：Telegram Desktop 复用 MTProto AuthKey 的 256 字节
    结构作为本地密钥，这不是笔误。派生结果直接作为后续
    prepare_aes_oldmtp 的输入，长度错误会在 SHA-1 校验处才暴露。
    """

def prepare_aes_oldmtp(local_key: bytes, msg_key: bytes) -> tuple[bytes, bytes]:
    """MTProto 旧式 KDF：由 256 字节 local_key 与 16 字节 msg_key
    拼出 32 字节 AES key 与 32 字节 IGE IV。详见 §3.2。"""

def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE 解密。data 长度必须是 16 的倍数，iv 为 32 字节。

    实现选型见 §3.3：纯 Python（pycryptodome 的 ECB 原语组合）。
    """

def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    """解密 tdesktop 的 local 加密块（TDF 内嵌格式），详见 §3.2。

    Raises:
        DecryptionError: SHA-1 校验失败（密码错误或文件损坏）。
    """

class CtrDecryptor:
    """跨调用维持计数器的 AES-256-CTR 解密器（TDEF 缓存文件用）。

    为什么做成类：CTR 的计数器必须跨 read 分块连续递增，
    无状态函数签名会诱使调用方重复用同一 IV 解密后续分块，
    这是流密码的致命误用（keystream 复用）。状态封装在类里
    可以从接口层面杜绝这种错误。
    """

    def __init__(self, key: bytes, iv: bytes) -> None: ...
    def decrypt(self, chunk: bytes) -> bytes: ...

def decrypt_storage_file(raw: bytes, local_key: bytes) -> bytes:
    """解密一个完整的 TDEF 缓存文件（含 magic/密钥校验），详见 §3.5。"""
```

#### TDF$ 容器解析 — 位于 `tdata_reader.py`

```python
from dataclasses import dataclass

TDF_MAGIC = b"TDF$"
TDEF_MAGIC = b"TDEF"

@dataclass
class RawTdfFile:
    version: int
    encrypted_data: bytes  # 已剥离 magic/version/尾校验

def parse_tdf(data: bytes) -> RawTdfFile:
    """解析并校验 TDF$ 容器（MD5 尾校验见 §3.1）。

    Raises:
        CorruptedDataError: magic 错误或 MD5 校验失败。
    """
```

#### TDataReader — 位于 `tdata_reader.py`

```python
from pathlib import Path

class TdataReader:
    """封装对一个 tdata 目录的只读访问。"""

    def __init__(self, tdata_path: Path, dataname: str = "data") -> None: ...

    @staticmethod
    def default_tdata_path() -> Path:
        """按平台返回默认 tdata 路径（见 §2.1）。

        Raises:
            TDataNotFoundError: 默认路径不存在且无法推断。
        """

    def read_local_key(self, passcode: str = "") -> bytes:
        """读取 key_{dataname}s，派生并返回 256 字节 LocalKey。

        Raises:
            TDataNotFoundError: key 文件不存在。
            PasswordRequiredError: SHA-1 校验失败且 passcode 为空——
                最可能的原因是账号设了本地密码，提示用户用 --password。
            DecryptionError: 校验失败但已提供 passcode（密码错误或损坏）。
        """

    def read_account_indexes(self, local_key: bytes) -> list[int]:
        """从 info_encrypted 解密结果中读取账号索引列表（v0.2 用）。"""

    def read_mtp_authorization(self, local_key: bytes) -> MtpAuthorization:
        """提取 MTProto 授权数据（user_id/dc_id/auth_key，§5.1）。

        Raises: TDataNotFoundError / DecryptionError / CorruptedDataError。
        """
```

#### 缓存遍历与解密 — 位于 `cache_decryptor.py`

```python
from pathlib import Path
from typing import Iterator

def iter_cache_files(cache_dir: Path) -> Iterator[Path]:
    """递归产出 cache/ 下的候选媒体文件。

    跳过：version、binlog、map0/map1（索引而非媒体）。
    为什么暴力遍历而不解析 map：map 的二进制格式随 tdesktop 版本
    漂移，而 MVP 的目标是"把能解的都解出来"。map 解析留作
    v0.1.x 增强（见 §2.3 与 TODO）。
    """

class CacheDecryptor:
    """缓存解密器：持有一份 LocalKey，批量解密 cache 目录。"""

    def __init__(self, local_key: bytes) -> None:
        """local_key 必须为 256 字节，否则抛 DecryptionError。"""

    def decrypt_file(self, path: Path) -> bytes:
        """读取并解密单个 TDEF 缓存文件，返回明文字节。

        Raises:
            DecryptionError: 非 TDEF、密钥校验失败或数据损坏，
                异常信息附带文件路径。调用方应逐文件 try/except
                并继续——缓存目录里混入非媒体文件是常态，单个失败
                不应中断整批提取。
        """

    def decrypt_all(self, cache_dir: Path) -> Iterator[tuple[Path, bytes]]:
        """遍历产出 (路径, 明文)；解密失败的文件跳过不抛出。"""
```

另有 `derive_storage_key_iv(local_key, salt)` 与
`decrypt_storage_file(raw, local_key)` 两个模块级函数，规范见 §3.5。

#### 媒体识别 — 位于 `media_detector.py`

```python
from enum import Enum

class MediaType(Enum):
    MP4 = "mp4"
    WEBM = "webm"
    AVI = "avi"
    MKV = "mkv"
    MOV = "mov"
    JPEG = "jpg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"

SNIFF_LEN = 4096  # 嗅探读取长度，理由见 §4.2

def sniff_media_type(header: bytes) -> MediaType | None:
    """根据文件头判定媒体类型；无法识别返回 None。

    纯函数、无副作用，必须接受任意长度输入（含 b""）而不抛异常——
    损坏的缓存条目可能不足 16 字节。等价于 MediaDetector().sniff()。
    """
```

实现另有 `MediaDetector` 类（`sniff` / `sniff_file`）与
`MIN_SNIFF_LEN = 12` 门限常量，边界条件见 §4.2。

#### 输出与去重 — 位于 `extractor.py`

```python
from pathlib import Path
from datetime import datetime

def unique_path(out_dir: Path, filename: str) -> Path:
    """返回不冲突的输出路径；冲突时追加 (1) (2) ... 后缀。

    绝不覆盖已有文件（硬性规则，见 §6）。
    """

def save_media(
    data: bytes,
    out_dir: Path,
    filename: str,
    mtime: datetime | None = None,
) -> Path:
    """落盘并按需恢复修改时间，返回实际写入路径。

    mtime 来自缓存文件自身的修改时间——这是"按时间排序找回
    已删除图片"场景的关键元数据，参考实现同样保留它。
    """
```

实现另有 `Extractor` 编排类（`extract_all`）、`ExtractionStats`
统计与 `sanitize_filename` / `build_fallback_name` 命名辅助，
规则见 §6。

#### 命令行入口 — 位于 `cli.py`

```python
def build_parser() -> argparse.ArgumentParser:
    """参数：--tdata-path（缺省自动探测）、--output-dir
    （缺省 ./tg-scoop-output）、--password、--chat-id（v0.2 预留，
    传入时警告并忽略）。"""

def main(argv: list[str] | None = None) -> int:
    """流程：解析参数 -> 定位/读取 tdata -> 派生 LocalKey ->
    Extractor.extract_all -> 打印统计报告。返回退出码。"""
```

行为契约（均已由 `_selftest_cli.py` 验证）：

- **退出码**：`EXIT_OK=0` / `EXIT_ERROR=1`（磁盘等系统性故障）/
  `EXIT_NOT_FOUND=2`（tdata 或缓存目录不存在）/ `EXIT_PASSWORD=3`
  （需要密码或密码错误）/ `EXIT_RATE_LIMIT=4`（v0.2 FloodWait）。
  场景映射见 §7.2。
- **密码交互**：`read_local_key` 抛 `PasswordRequiredError` 时，
  CLI 用 `getpass` 交互询问一次后重试；再失败按退出码 3 处理。
  交互逻辑在 CLI 层而非 `TdataReader`，保持后者可测。
- **双缓存目录**：`user_data/cache/` 与 `user_data/media_cache/`
  中存在的都处理，用同一个 `Extractor` 实例跑两轮并合并统计
  （`ExtractionStats.merge`）——共享实例使跨目录内容去重生效。
- **只捕获 `TgScoopError` 与 `OSError`**，其余异常视为 bug 上抛。

#### GUI — 位于 `gui.py`【P0-14 待实现】

```python
class ScoopApp(customtkinter.CTk):
    """单窗口 GUI：路径/密码输入 + 开始按钮 + 只读日志 + 统计行。

    是核心逻辑之上的薄层，不含任何解密/命名规则。"""

def main() -> None:
    """GUI 入口（pyproject 的 tg-scoop-gui 指向这里）。"""
```

行为契约：

- **共享管道**：GUI 与 CLI 共用同一装配函数
  `run_pipeline(tdata_path, output_dir, password, progress_cb=None) -> ExtractionStats`
  （P0-14 时从 cli.main 中提取），避免两套编排逻辑漂移。
- **线程模型（硬性约束）**：提取在 worker 线程执行；UI 更新一律
  经 `queue.Queue` + `root.after()` 泵回主线程；worker 线程禁止
  直接触碰任何控件（Tkinter 非线程安全）。详见 §11。
- **错误映射**：core 异常 → `messagebox` 提示，文案复用 §7.2 表格。

#### `mtproto_client.py` — 【v0.2，文件尚未创建】

设计契约见 §5；`tdata_reader.py` 中的 `MtpAuthorization` 数据类、
`compute_data_name_key` 与 `read_mtp_authorization`（P1-2）已实现
并有 pytest 覆盖（真实数据验证待 P0-12；Telethon 会话复用 P1-3
在其后启动）。

### 1.4 实现状态

| 模块 | 状态 | 验证 |
|------|------|------|
| `exceptions.py` / `__init__.py` | ✅ 完成 | import 冒烟 |
| `tdata_reader.py` | ✅ 已实现 | `_selftest_tdata.py` 6 项全绿（IGE 往返、key_datas 全链路、TDF 校验、错误密钥拒绝） |
| `cache_decryptor.py` | ✅ 已实现 | `_selftest_cache.py` 6 项全绿（CTR 连续性、TDEF 往返、篡改/错误密钥拒绝、遍历过滤） |
| `media_detector.py` | ✅ 已实现 | `_selftest_media.py` 6 项全绿（9 种类型、防误判 brand 白名单、边界输入） |
| `extractor.py` | ✅ 已实现 | `_selftest_extract.py` 8 项全绿（净化、序号、mtime、统计、连跑幂等） |
| `cli.py` | ✅ 已实现 | `_selftest_cli.py` 4 项全绿（端到端、密码路径、退出码、--chat-id 预留） |
| `gui.py` | ✅ 已实现 | `_selftest_gui.py` 3 项全绿（run_pipeline 契约、异常路径、worker→queue→UI 泵冒烟）；人工运行验证待 P0-12 |
| `mtproto_client.py` | 📋 v0.2 规划，文件未创建 | — |

自测运行方式（`.venv` 已建，含 pycryptodome 3.23，已入 .gitignore）：

```bash
.venv/Scripts/python _selftest_tdata.py
.venv/Scripts/python _selftest_cache.py
.venv/Scripts/python _selftest_media.py
.venv/Scripts/python _selftest_extract.py
.venv/Scripts/python _selftest_cli.py
.venv/Scripts/python _selftest_gui.py
```

共享 fixture 构造函数在 `_selftest_common.py`（§9.1 加密 fixture
生成器策略的落地）。

`tests/` 下的 pytest 用例已填充并全绿（P0-11）；fixture 构造函数
已迁移至 `tests/fixtures/`（`_selftest_common.py` 为兼容再导出层）。
golden 文件锚定已补做：`tests/golden/golden_vectors.json`（由
`scripts/generate_golden.py` 经 refs 参考实现生成，确定性可重现），
`tests/test_golden_anchor.py` 逐层锚定 KDF / 旧式 KDF / IGE / local 帧
与 TDEF 整文件（78 用例全绿）。

---

## 2. 数据流详细设计

### 2.1 完整链路

```
[输入] tdata 目录（默认或 --tdata 指定）
  Windows: %APPDATA%/Telegram Desktop/tdata
  macOS:   ~/Library/Application Support/Telegram Desktop/tdata
  Linux:   ~/.local/share/TelegramDesktop/tdata
        │
        ▼
① tdata_reader: 读取 tdata/key_datas（TDF$ 容器）
   输出: salt (bytes), key_encrypted (bytes), info_encrypted (bytes)
        │
        ▼
② crypto.create_local_key: passcode + salt → PasscodeKey (256 B)
        │
        ▼
③ crypto.decrypt_local: key_encrypted → LocalKey (256 B，SHA-1 校验)
   ★ 此后所有缓存解密都只用 LocalKey，passcode 即时丢弃
        │
        ▼
④ cache_decryptor: 遍历 tdata/user_data/cache/ 得到文件路径列表
   （可选 v0.1.x：先解密 map0/map1 索引，按索引精确取文件；
   CLI 层额外处理第二个缓存根目录 media_cache/，见 §1.3 cli 小节）
        │
        ▼
⑤ crypto.decrypt_storage_file: 逐文件 TDEF → 明文 bytes
   输出: 明文媒体字节流（可能是完整文件，也可能是缓存分片）
        │
        ▼
⑥ media_detector: 取前 4096 字节嗅探 → MediaType | None
   None → 记入 skipped 列表，不写盘
        │
        ▼
⑦ extractor: 按 §6 命名规则生成不冲突路径 → 写盘 + 恢复 mtime
        │
        ▼
[输出] out_dir/ 下的媒体文件 + 终端统计报告
       （成功 N / 跳过 M / 失败 K / 重复 D，失败原因分布）
```

### 2.2 各环节输入输出格式约定

| 环节 | 输入 | 输出 | 失败信号 |
|---|---|---|---|
| ① TDF 解析 | 文件 bytes | `RawTdfFile` | `CorruptedDataError` |
| ② 密钥派生 | passcode, salt | 256 B key | 不失败（纯计算） |
| ③ LocalKey 解密 | key_encrypted | 256 B LocalKey | `DecryptionError` / `PasswordRequiredError` |
| ④ 遍历 | cache 目录 | `Iterator[Path]` | `CacheNotFoundError` |
| ⑤ TDEF 解密 | 文件 bytes + LocalKey | 明文 bytes | `DecryptionError`（逐文件容错） |
| ⑥ 嗅探 | ≥ 0 字节头部 | `MediaType \| None` | 不抛异常，None 即跳过 |
| ⑦ 落盘 | bytes + 命名上下文 | `Path` | `OSError` 上抛（磁盘满等应中止） |

**为什么 ⑤ 容错而 ⑦ 不容错**：缓存文件损坏是预期内的常态（Telegram
会随时清缓存、写入中断），批处理必须继续；而写盘失败（磁盘满、
权限不足）意味着后续所有文件都会失败，继续跑只是浪费时间的
假进度，应立即中止并给出非零退出码。

### 2.3 缓存索引：binlog 定案（B-03，v0.2）

> 旧版假设（`cache/map0`、`cache/map1` 为索引文件）已被真机探测
> 证伪，登记为漂移项 **D-7.1.1-2**：tdesktop 7.1.1 的
> cache/media_cache 下不存在 map0/map1（旧版"map 格式随版本漂移"
> 预判以极端形式应验）。

7.x 缓存索引真身 = `<cache目录>/<version>/binlog`（lib_storage 子
模块，`storage_cache_types.h` / `storage_cache_binlog_reader.h` /
`storage_cache_database_object.cpp`）：`version` 文件（4B 小端
int32）记录版本号目录名；binlog 为 TDEF 加密容器（与媒体文件同族，
`decrypt_file` 可解）；内容 = BasicHeader(16B) + 记录流
（Store 0x01 / MultiStore 0x02 / MultiRemove 0x03 / MultiAccess 0x04）。
数据文件按 placeId（7 字节 → 14 位十六进制，低 4 位在前高 4 位
在后，首字节两字符后插 `/`）命名，如 `cache/1/A5/5B40637E62FA`。

`cache_index.py`（B-03 落地）提供只读 `read_cache_index()`：
解析出 `Key(16B) → {place 路径, tag, size, checksum, use_time}`
映射，供 B-04 三级匹配的 P1 级（document.id 精确匹配）使用；
未知记录类型/版本显式失败（漂移暴露原则）。v0.1 的暴力遍历路径
不受影响（索引只服务 v0.2 的匹配增强，不参与提取主流程）。

---

## 3. TDEF 解密规范

本节整理自 `refs/tgdesktop-cache-decryptor` 及其上游
[lilydjwg/telegram-cache-decryption](https://github.com/lilydjwg/telegram-cache-decryption)
的已验证实现（实测兼容 Telegram Desktop 4.2.4），并与
[ntqbit/tdesktop-decrypter](https://github.com/ntqbit/tdesktop-decrypter)
的纯 Python 实现交叉核对。两处在细节上一致的部分视为可信规范。

### 3.1 TDF$ 容器格式

`key_datas` 及 tdesktop 的大部分本地文件都是 TDF$ 容器：

```
偏移      长度        内容
0         4           magic = "TDF$"
4         4           version (little-endian int32)
8         N-16        data（QDataStream 序列化内容，通常已加密）
N-16      16          MD5 校验和
```

MD5 校验算法（顺序敏感）：

```python
import hashlib

def verify_tdf(raw: bytes) -> tuple[int, bytes]:
    assert raw[:4] == b"TDF$"
    version = int.from_bytes(raw[4:8], "little")
    data = raw[8:-16]
    digest = hashlib.md5(
        data
        + len(data).to_bytes(4, "little")
        + version.to_bytes(4, "little")
        + b"TDF$"
    ).digest()
    if digest != raw[-16:]:
        raise CorruptedDataError("TDF checksum mismatch")
    return version, data
```

注意 MD5 的输入**包含 magic 与 version 自身**——这是最容易写错的
一点，漏掉任何一段都会校验失败。

### 3.2 local 加密块与 AES-256-IGE

TDF 的 `data` 段内，加密载荷按以下格式存放：

```
[0:16]   msg_key = SHA1(plaintext)[:16]      （完整性校验）
[16:]    AES-256-IGE 加密的密文，长度为 16 的倍数
```

解密流程：

```python
def decrypt_local(encrypted: bytes, local_key: bytes) -> bytes:
    msg_key, ciphertext = encrypted[:16], encrypted[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key)
    plain = aes_ige_decrypt(ciphertext, aes_key, aes_iv)

    if hashlib.sha1(plain).digest()[:16] != msg_key:
        raise DecryptionError("checksum failed: wrong passcode or corrupted data")

    # 长度字段包含自身的 4 字节，因此切片终点是 length 而非 4 + length。
    # 两个参考实现都是 plain[4:length]，与 tdesktop 的 mid(4, dataLen - 4) 等价。
    length = int.from_bytes(plain[:4], "little")
    if length > len(plain):
        raise DecryptionError(f"corrupted data: wrong length {length}")
    return plain[4:length]
```

`prepare_aes_oldmtp`（MTProto 旧式 KDF，x=8 为接收方向）：

```python
def prepare_aes_oldmtp(local_key: bytes, msg_key: bytes) -> tuple[bytes, bytes]:
    x = 8
    sha1_a = hashlib.sha1(msg_key + local_key[x : x + 32]).digest()
    sha1_b = hashlib.sha1(
        local_key[x + 32 : x + 48] + msg_key + local_key[x + 48 : x + 64]
    ).digest()
    sha1_c = hashlib.sha1(local_key[x + 64 : x + 96] + msg_key).digest()
    sha1_d = hashlib.sha1(msg_key + local_key[x + 96 : x + 128]).digest()

    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]          # 32 B
    aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]  # 32 B
    return aes_key, aes_iv
```

**为什么 SHA-1 校验不是安全隐患**：这里 SHA-1 只作本地完整性校验
（等价于 CRC 的角色），密钥强度来自 PBKDF2-SHA512，不依赖 SHA-1 的
抗碰撞性。沿用原格式是为了与 tdesktop 生成的文件兼容。

### 3.3 AES-IGE 的纯 Python 实现

pycryptodome / cryptography 均不直接提供 IGE 模式。参考实现中
lilydjwg 用 CFFI 调 OpenSSL，Zwylair 改为纯 Python。我们采用
**pycryptodome 的 ECB 原语手工组合 IGE**（约 25 行），理由：

- 避免 CFFI/OpenSSL 的跨平台编译问题（Windows 优先的硬性约束）；
- IGE 只是 ECB 的双向链接，用 ECB 原语组合逻辑清晰、可单测；
- 解密对象是本地文件，性能瓶颈在磁盘而非 AES 软件实现。

IGE 定义（IV 为 32 字节 = 两个链接块 `iv1, iv2`）：

```python
from Crypto.Cipher import AES

def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 or len(iv) != 32:
        raise DecryptionError("IGE input must be block-aligned with 32-byte IV")
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray(len(data))
    prev_c, prev_p = iv[:16], iv[16:]
    for off in range(0, len(data), 16):
        block = data[off : off + 16]
        dec = cipher.decrypt(xor(block, prev_p))
        plain = xor(dec, prev_c)
        out[off : off + 16] = plain
        prev_c, prev_p = block, plain
    return bytes(out)
```

### 3.4 key_datas 内部结构

TDF 的 data 段解密前是三个连续的 QByteArray（QtStreamReader 读取）：

```
1. salt            — 派生 PasscodeKey 的盐
2. key_encrypted   — 用 PasscodeKey 经 decrypt_local 解密 → LocalKey
3. info_encrypted  — 用 LocalKey 经 decrypt_local 解密 → 账号索引列表
                     （int32 count + count 个 int32 索引 + int32 主账号）
```

`settings` 系列文件用的是**旧式派生**（不要与新式混用）：

```python
# 旧式（settings 文件）：PBKDF2-HMAC-SHA1，无密码 4 轮 / 有密码 400 轮
# 新式（key_datas）    ：PBKDF2-HMAC-SHA512，无密码 1 轮 / 有密码 100000 轮
# 为什么迭代次数差异巨大：tdesktop 历史上升级过 KDF，
# 旧文件保持旧参数以兼容。读错 KDF 会在 SHA-1 校验处失败。
```

### 3.5 TDEF 缓存文件格式（核心）

`user_data/cache/` 下的媒体文件是 TDEF 容器，使用 **AES-256-CTR**
（不是 IGE），且密钥派生方式完全不同：

```
偏移   长度    内容
0      4       magic = "TDEF"
4      64      salt
68     48      加密的校验块 = 16 B 随机头 + 32 B checksum
116    ...     加密的媒体数据（与校验块同一条 CTR 流，计数器连续）
```

密钥派生与校验：

```python
real_key = sha256(local_key[:128] + salt[:32])         # 32 B
iv       = sha256(local_key[128:] + salt[32:])[:16]    # 16 B

# 解密前 48 字节校验块后：
header   = plain[:16]                                   # 随机头
checksum = plain[16:48]
assert sha256(local_key + salt + header) == checksum    # 密钥正确性校验
```

完整实现要点：

```python
def decrypt_storage_file(raw: bytes, local_key: bytes) -> bytes:
    if raw[:4] != b"TDEF":
        raise DecryptionError("not a TDEF file")
    salt = raw[4:68]
    d = CtrDecryptor(
        key=hashlib.sha256(local_key[:128] + salt[:32]).digest(),
        iv=hashlib.sha256(local_key[128:] + salt[32:]).digest()[:16],
    )
    check = d.decrypt(raw[68:116])
    if hashlib.sha256(local_key + salt + check[:16]).digest() != check[16:48]:
        raise DecryptionError("wrong key for storage file")
    return d.decrypt(raw[116:])   # 计数器必须接着校验块继续，不能重置
```

**为什么校验块与媒体数据必须共用一条 CTR 流**：lilydjwg 的实现里
`decryptor.block_index` 跨两次 `decrypt()` 调用递增。若媒体数据从
计数器 0 重新解密，得到的是错误明文但 magic bytes 可能恰好不可识别，
表现为"全部跳过"的静默失败。`CtrDecryptor` 类（§1.3）从接口上
强制了这一点。CTR 计数器按 OpenSSL 惯例**大端递增**，每 16 字节
块 +1（`block_index += len(chunk) // 16`）。

流式解密（N-5，v0.1.3 落地）：`decrypt_file_iter` 分块解密（默认
1 MiB），校验块与媒体数据仍共用一条 CTR 流；Extractor 管线为
"首块嗅探→临时文件+流式哈希→查重→改名"，内存峰值与文件大小脱钩；
输出与旧全量路径逐字节一致。

CTR 后端（C-12，v0.1.4 落地；依据 0827-0209 审查报告决策 B）：
`CtrDecryptor` 内部改用 pycryptodome `AES.MODE_CTR`（`nonce=b""` +
`initial_value`=iv 大端整型），与 OpenSSL ctr128 语义原生对齐；
公开契约与 `_finalized` 语义不变，输出与旧"ECB 原语+逐块异或"
路径逐字节一致（byte-exact 对拍 + golden 向量 + 真机基准核验）。
IGE（key_datas/MTP 授权小文件）保持纯 Python 不动（冷路径）。

并行解密（C-02，v0.1.3 落地）：`--jobs N > 1` 时
`multiprocessing.Pool` worker 各自持有 LocalKey（仅进程内存，不落盘）
只做解密并写池内临时文件（`输出目录/.tg-scoop-pool/<pid>/`），主进程
按 `iter_cache_files` 排序序经 `imap` 保序消费（sniff/哈希/查重/改名
与串行同一管线）——输出与串行逐字节一致是确定性红线。临时文件清理
契约：`.tg-scoop-partial-*` 与 `.tg-scoop-pool/` 均在运行开始与结束
整体清理；取消置位停止领取新结果，统计为已消费部分。

### 3.6 密码场景的处理

- 未设本地密码：`passcode = b""`，PBKDF2 仅 1 轮——`key_datas` 的
  保密性完全依赖操作系统账户隔离，工具无需用户交互即可解密。
- 设了本地密码：SHA-1 校验失败时，若未提供 passcode 抛
  `PasswordRequiredError`；提供了仍失败抛 `DecryptionError`。
  PBKDF2 100000 轮约几十毫秒，CLI 交互式询问密码是可接受的开销。

---

## 4. 媒体识别策略

### 4.1 magic bytes 映射表

| 类型 | 签名（偏移 0 起） | 判定规则 | 扩展名 |
|---|---|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 全匹配 8 字节 | `.png` |
| JPEG | `FF D8 FF` | 前 3 字节匹配（第 4 字节 E0/E1/DB 等均可） | `.jpg` |
| GIF | `47 49 46 38 (37|39) 61` | `GIF87a` 或 `GIF89a` | `.gif` |
| WEBP | `RIFF????WEBP` | [0:4]==RIFF 且 [8:12]==WEBP | `.webp` |
| AVI | `RIFF????AVI ` | [0:4]==RIFF 且 [8:12]==`AVI `（含空格） | `.avi` |
| MP4 | `????ftyp` | [4:8]==ftyp 且 brand ∈ {isom, iso2, mp41, mp42, avc1, M4V , dash…} | `.mp4` |
| MOV | `????ftyp` | [4:8]==ftyp 且 brand == `qt  ` | `.mov` |
| MKV/WEBM | `1A 45 DF A3` | EBML 头；在前 4096 字节内找 DocType：`webm`→WEBM，`matroska`→MKV，都找不到默认 MKV | `.mkv`/`.webm` |

### 4.2 边界条件与可靠长度

- **嗅探长度 4096 字节**：RIFF/ftyp 判定 12 字节足够，但 EBML 的
  DocType 元素理论上可出现在头部任意偏移（实践中都在前几百字节）。
  4096 是"可靠识别"与"IO 开销"的平衡点；不足 4096 的文件按实际
  长度嗅探。
- **最小长度门限**：文件 < 12 字节直接返回 None——RIFF/ftyp 判定
  至少需要 12 字节，更短的输入任何结论都不可靠。
- **ftyp 必须校验 brand**：只查 `ftyp` 前缀会把 `.m4a`、`.heic`
  （同为 ISO BMFF 容器）误判为 MP4。本项目只管视频/图片，brand
  白名单外的 ftyp 文件返回 None。
- **MKV/WEBM 兜底**：EBML 解析不引入第三方库，只做子串查找
  （`b"webm"` / `b"matroska"`）。完整 EBML 解析对"识别扩展名"
  这个目标属于过度工程。
- **无法识别 ≠ 失败**：返回 None 的文件计入 skipped 统计（大概率是
  缓存元数据、贴纸描述文件等非媒体内容），不进失败列表。

### 4.3 为什么不做内容级校验

嗅探只保证"扩展名大致正确"，不保证文件可播放（缓存可能只有文件的
一部分）。深度校验（如 ffprobe）属于 v1.0 之后的事，理由见 §8。

---

## 5. MTProto 集成方案（v0.2 规划）

> 本节为设计契约，v0.1 只预留接口不实现。目标：把缓存文件与原始
> 消息关联，恢复原始文件名与发送者信息。

### 5.1 从 tdata 复用会话

Telegram Desktop 的 MTProto 授权数据存在 tdata 下以哈希命名的文件
中。定位算法（来自 tdesktop-decrypter，已验证）：

```python
def compute_data_name_key(dataname: str) -> str:
    """dataname 为 "data"（首账号）或 "data#2"、"data#3"（多账号）。

    filekey = MD5(dataname)[:8]，然后每个字节的两上十六进制位互换
    （如 0xAB → "BA"），拼成 16 字符大写字符串。
    """
    filekey = hashlib.md5(dataname.encode()).digest()[:8]
    return "".join(f"{b:02X}"[::-1] for b in filekey)
```

`tdata/<key>` 与 `tdata/<key>s` 两个文件（TDF$ + LocalKey 解密）
内含 settings 块序列，其中 `dbiMtpAuthorization` 块结构：

> 实测漂移（D-7.1.1-1，tdesktop 7.1.1）：`tdata/<key>` 的无 s 变体可能被同名目录占用，MTP 授权块位于 `tdata/<key>s`，且密文外层多一层 QByteArray 包裹。读取策略与参考实现 `file_io.py` 对齐：候选 `[<key>s, <key>]`（s 优先），解包先直接后 QByteArray 变体。

```
int32   legacy_user_id
int32   legacy_main_dc_id
        —— 若两者均为 -1（新版格式）：
uint64  user_id
int32   main_dc_id
int32   keys_count
  重复 keys_count 次:  int32 dc_id + 256 字节 auth_key
int32   keys_to_destroy_count（同上结构，丢弃不用）
```

提取出的 `(user_id, dc_id, auth_key)` 可直接构造 Telethon/Pyrogram
会话，**无需扫码或短信验证**——这是复用本地会话而非新建登录，
不触发新设备通知。

> B-02 已落地 `mtproto_client.py`（MemorySession 复用 + DC 地址表 +
> chat 解析/实体解析，telethon 延迟 import）；真实会话验证归 H-04。接口：

```python
@dataclass
class MtpAuthorization:
    user_id: int
    dc_id: int
    auth_key: bytes  # 256 字节

class TdataReader:
    def read_mtp_authorization(self, local_key: bytes) -> MtpAuthorization: ...
        # 方法形式（dataname 取自实例）。目标文件：
        # tdata/<compute_data_name_key(dataname)>（无 s 后缀）；
        # 块 id dbiMtpAuthorization = 0x4B（对照参考实现 settings.py）。
```

### 5.2 消息历史拉取与三级匹配

缓存文件与消息的匹配按置信度分三级，逐级降级：

| 优先级 | 匹配策略 | 置信度 |
|--------|---------|--------|
| P1 | `document.id` 精确匹配 | 高 |
| P2 | 文件大小 + 前 1KB 内容哈希联合匹配 | 中 |
| P3 | 仅文件大小匹配 | 低（需人工核对） |

1. **`document.id` 精确匹配**：消息中的 `document.id` 与缓存 map 中
   的 cache key 存在确定的映射关系（v0.2 需先实现 map 解析，§2.3）。
   命中即采用，置信度最高。
2. **文件大小 + 前 1KB 内容哈希联合匹配**：同一聊天内先按
   `document.size == len(plaintext)` 筛候选，再只拉取候选媒体的
   前 1KB 与本地明文前 1KB 比对哈希。命中即采用。
3. **仅文件大小匹配**：无法拉取内容（或限速预算耗尽）时的兜底，
   输出到 `out_dir/needs-review/` 子目录并在报告中标注"需人工核对"。

**为什么按这个顺序**：P1 是 O(1) 查表；P2 只下载 1KB 而非完整
媒体（Telegram API 支持 range 下载），把网络成本压到最低的同时
保持高置信度；P3 完全不碰网络。逐级降级保证绝大多数文件在前
两级解决，API 调用量最小化——这直接决定了限速预算够不够用。

> 落地注（B-04，v0.2 施工中）：`message_matcher.py` 提供
> `DocumentInfo`/`MatchResult`/`document_cache_key`（+
> `document_bigfile_cache_key`，media_cache 大文件基准键，取证自
> `image_location.cpp`）/`fetch_chat_documents`/`match_documents`/
> `match_with_content`；cache key 公式来自 data_types.cpp
> （`Key{0x100 | (dcId & 0xFF), id}`）；binlog 索引见 §2.3
> （`read_cache_index`）；匹配结果写入 manifest v2（§6.3），
> 命名不变（B-07 才生效）。真实连接验证归 H-04。

### 5.3 API 限速策略

硬性约束：**≤ 30 条消息/分钟**（远高于官方 FloodWait 触发阈值，
留出安全边际，避免账号被限制）。

```python
class RateLimiter:
    """令牌桶：容量 30，每 2.0 秒补 1 个令牌。

    为什么固定 2 秒间隔而非突发后等待：稳定低速比"冲 30 条然后
    干等"更容易被 Telegram 的反滥用系统接受，行为模式更接近
    正常客户端的滚动浏览。
    """

    def __init__(self, per_minute: int = 30) -> None: ...
    async def acquire(self) -> None: ...
```

- 捕获 `FloodWaitError` 时**必须**按其指定的秒数暂停，并抛
  `APIRateLimitError` 让 CLI 层决定是否断点续跑。
- 拉取状态（已扫描的 chat_id + 最大 message_id）持久化到
  `out_dir/.tg-scoop-state.json`，支持中断后续跑。

---

## 6. 命名与去重规则

### 6.1 命名（按信息可用性降级）

**API 可用（v0.2）**：

```
{原始文件名}.{扩展名}
```

- 原始文件名来自 `document.attributes` 的 `DocumentAttributeFilename`；
- 同名冲突：追加 ` (1)`、` (2)` … ` (n)`（后缀在扩展名之前：
  `video (1).mp4`）；
- 文件名经过净化：剔除 `<>:"/\|?*` 与控制字符（Windows 非法字符），
  长度截断到 200 字符。

**API 不可用（v0.1 默认路径）**：

```
{发送者名}_{时间戳}_{哈希前8位}.{扩展名}
例如： Alice_20260314_153022_a1b2c3d4.mp4
```

- v0.1 拿不到发送者名时退化为 `unknown_...`；
- 时间戳取缓存文件的 mtime（`%Y%m%d_%H%M%S`，本地时区）；
- 哈希取明文 SHA-256 的前 8 个十六进制位。

**为什么降级名要带哈希**：时间戳精度只有秒，同一秒缓存多文件是
常态；8 位哈希把同秒冲突概率降到可忽略，同时保证**幂等**——
重复运行工具，同一文件算出同一名字，配合 §6.2 的不覆盖规则
天然实现增量提取。

> 落地注（B-07，v0.2）：三件套齐备时编排改为**匹配前置**——
> `_match_prephase`（提取前产出 name_map/sender_map/needs_review）
> → `run_pipeline` 消费映射命名 → `_match_postphase`（sha256 链接
> 重写 manifest）。P3 落 `输出目录/needs-review/` 子目录（文件名
> 照旧、查重作用域随目录、manifest file_name 记相对路径）。
> 幂等依赖命名确定性：同凭据同聊天同缓存 → 同名，重跑全重复
> 无覆盖。`--chat-id` 同步转正（缺凭据仍忽略并警告）。

### 6.2 去重与不覆盖（硬性规则）

1. **绝不覆盖已有文件**。目标路径已存在且内容不同 → 按 §6.1 加
   序号后缀；内容相同（SHA-256 一致）→ 跳过并计入 `duplicates`。
2. 同一次运行内维护 `set[sha256]`，解密后先查重再写盘，避免
   缓存里本来就重复的条目重复落盘。
3. `unique_path()` 的序号探测上限 9999，耗尽抛 `ExtractionError`
   ——无限循环比报错更难排查。

### 6.3 manifest（N-1，B-01 落地）

每次提取运行结束，在输出目录写 `manifest.json`（结构版本
`version: 2`），含 `tdata_path`/`generated_at`/`stats` 与三段条目：

- `entries`：落盘记录（file_name、明文 sha256 hex、size、mtime
  （本地朴素 ISO 秒级）、media_type、source_cache_dir）；
  B-04 匹配运行时命中条目增 `match` 子对象
  （`{"level", "document_id", "original_name"}`）
- `skipped_entries`：未落盘记录（cache_file、source_cache_dir、
  reason ∈ `unrecognized_media_type` / `duplicate` /
  `filtered_by_type:{type}`（C-13，v0.1.4））
- `failed_entries`：解密失败记录（cache_file、source_cache_dir、
  reason = 异常类型名）

口径契约：`len(entries) == stats.succeeded`；
`len(skipped_entries) == stats.skipped + stats.duplicates`；
`len(failed_entries) == stats.failed`。

v2 增量（B-04）：带 `matches` 写盘时顶层增 `match_summary`
（`{"P1": n, "P2": n, "P3": n}`）；不带 matches 的旧路径结构不变。
版本 1 → 2 为纯新增字段，旧读取方兼容。

幂等语义：manifest.json 是工具自身的报告，每轮**覆盖重写**，内容
反映本轮事实——"绝不覆盖"红线针对提取出的媒体文件，不含报告自身。

---

## 7. 错误处理规范

### 7.1 异常类型（`exceptions.py`）

```python
class TgScoopError(Exception):
    """所有 tg-scoop 异常的基类。CLI 只捕获它 + OSError。"""

class TDataNotFoundError(TgScoopError):
    """tdata 目录或 key_datas 文件不存在。"""

class CacheNotFoundError(TgScoopError):
    """user_data/cache 目录不存在或为空。"""

class PasswordRequiredError(TgScoopError):
    """账号设有本地密码，需要 --password。"""

class DecryptionError(TgScoopError):
    """解密/校验失败（密码错误、文件损坏、格式不符）。"""

class CorruptedDataError(DecryptionError):
    """TDF 容器级损坏（magic/MD5 校验失败）。"""

class APIRateLimitError(TgScoopError):
    """触发 Telegram API 限速（FloodWait）（B-05，v0.2）。"""

class ExtractionError(TgScoopError):
    """命名序号耗尽等输出阶段错误。"""
```

### 7.2 各场景的提示与降级行为

| 场景 | 异常 | 用户提示 | 行为 |
|---|---|---|---|
| 找不到 tdata | `TDataNotFoundError` | 列出各平台默认路径，提示 `--tdata` | 退出码 2 |
| 找不到 cache | `CacheNotFoundError` | 提示在 Telegram 设置中确认缓存未清空 | 退出码 2 |
| 有本地密码未提供 | `PasswordRequiredError` | "该 tdata 设有本地密码，请用 --password" | 退出码 3 |
| 密码错误 | `DecryptionError` | "密码校验失败，请确认 --password" | 退出码 3 |
| 单个缓存文件解密失败 | `DecryptionError` | 计入 failed，末尾汇总 | **继续处理其余文件** |
| 无法识别媒体类型 | —（None） | 计入 skipped | 继续 |
| 磁盘写失败 | `OSError` | 系统错误信息 | **立即中止**，退出码 1 |
| FloodWait | `APIRateLimitError` | 需等待秒数 + 续跑提示 | 保存断点，退出码 4 |

**为什么区分"继续"与"中止"**：见 §2.2——可预期的局部损坏
（缓存文件）批处理跳过，系统性故障（磁盘、密钥）立即中止。
退出码按场景区分，方便脚本化调用方做重试决策。

---

## 8. MVP 功能边界（v0.1 不做什么）

明确排除项，防止范围蔓延。**以下功能在 v0.1 的 PR 中一律拒绝**：

1. **GUI 仅限 CustomTkinter 简洁单窗口**（§11）：v0.1 包含 GUI，
   但禁止 PyQt6/PySide 等重型框架；core 模块零 GUI 依赖的约束
   不变——GUI 只能调用，不得内嵌业务逻辑。
2. **不解析本地消息数据库**：不碰 tdata 里的聊天历史/binlog，
   文件名恢复等 v0.2 走 MTProto 而非本地库逆向。
3. **不支持多账号并发**：只处理 `key_datas`（首账号）。多账号
   （`key_data#2` 等）的文件命名规则已验证可行（§5.1），留待 v0.3。
4. **不处理云端文件**：不下载任何 Telegram 服务器上的内容，
   只解密本地已有缓存。
5. **不做深度媒体校验**：不用 ffprobe 验证可播放性（§4.3）。
6. **不解析 cache map**：暴力遍历替代（§2.3）。
7. **不做加密回写**：工具只读 tdata，绝不修改 tdata 内任何字节。
   所有代码路径以只读模式打开 tdata 文件，code review 时作为
   检查项。

**为什么把"只读 tdata"写进边界**：用户对工具的最低信任预期是
"不会搞坏我的 Telegram"。只读约束让这个承诺可以逐行审查验证，
而不是依赖"我们不会写 bug"。

---

## 9. 测试策略

### 9.1 单元测试覆盖点（pytest，全量可离线运行）

| 模块 | 覆盖点 |
|---|---|
| `tdata_reader` | QtStreamReader 大端 int32/64 与 QByteArray 正常/null(0xFFFFFFFF)/截断；PBKDF2 派生对已知向量（空密码 + 固定 salt 回归值）；`prepare_aes_oldmtp` 切片偏移；`decrypt_local` 的 SHA-1 校验失败路径；IGE 与 tgcrypto 对拍（dev 依赖交叉验证）；TDF$ 的 magic 错误/MD5 错误/正常三种样本 |
| `cache_decryptor` | TDEF 往返测试：用本模块的逆过程**加密**已知明文构造 fixture，再解密断言相等；CTR 计数器跨分块连续性 |
| `media_detector` | 每种类型 1 个真实文件头 + 边界（<12 字节、空输入、ftyp 无 brand、EBML 无 DocType） |
| `extractor` | 序号后缀（1)(2)(n）、同名同内容跳过、非法字符净化、序号耗尽异常 |
| `cli`（集成编排） | 跳过/失败/成功/重复的统计数字正确；退出码 0/2/3 路径 |

> 注：以上覆盖点当前由 `_selftest_*.py` 先行验证（见 §1.4），
> 本表是 P0-11 填充 pytest 用例时的核对清单。

**关键的测试设计决策——加密 fixture 生成器**：测试数据的正确姿势
是用我们自己的加密路径（解密的逆运算）把已知明文加密成 TDF/TDEF，
再走解密断言还原。这样 fixture 可以提交进仓库（不含任何真实用户
数据），且天然覆盖"格式写对了吗"。风险是加解密可能犯同一个错误
而相互掩盖——因此必须额外保留 **2~3 个由参考实现生成的 golden
文件**（从 `refs/` 工具跑出，含已知明文与期望输出）做交叉锚定。

> 当前状态：pytest 用例已填充并全绿（P0-11）；6 套 `_selftest_*.py`
> 保留为冒烟入口。golden 锚定已落地（P0-11 收尾）：2 条 local 链
> （无密码/有密码）+ 1 条 TDEF 链，由 `scripts/generate_golden.py`
> 用 refs 参考实现生成；TDEF 的 CTR 密钥流经 tgcrypto 与
> pycryptodome MODE_CTR 双实现交叉断言。

### 9.2 tdata 模拟数据方案

`tests/fixtures/make_tdata.py` 生成完整假 tdata：

```
fake_tdata/
├── key_datas                 # 由固定 salt + 空密码真实派生
├── user_data/
│   └── cache/
│       ├── map0              # 占位内容
│       ├── 0a3f...（TDEF 加密的测试 MP4 头）
│       ├── 1b7e...（TDEF 加密的测试 JPEG）
│       └── 9zzz...（故意损坏的 TDEF，校验应失败）
```

- 测试媒体内容用程序生成的最小合法文件头 + 随机填充，**不提交
  任何真实 Telegram 内容**到仓库（法律与隐私双重原因）；
- 设密码的变体单独生成一份（passcode = `test1234`），覆盖
  `PasswordRequiredError` 路径。

### 9.3 真实环境验证流程（发布前手动清单）

自动化测试不能替代真实 tdesktop 数据，每次发版前执行：

1. 在测试机上登录 Telegram Desktop，进入一个开启"限制保存内容"
   的频道，播放若干视频、查看若干图片（确保写入缓存）；
2. **完全退出** Telegram Desktop（避免文件锁与缓存写入中状态）；
3. 复制 `tdata` 到临时目录，对**副本**运行 tg-scoop；并运行`scripts/diagnose_tdata.py` 生成格式兼容性报告（覆盖 key 链 / MTP 授权 / TDEF 抽样，报告随验证结果一并提交）；
4. 验证：输出文件可正常播放/查看；mtime 与缓存文件一致；重复
   运行无覆盖、无重复；
5. 在有本地密码的账号上重复 1–4，验证 `--password` 路径；
6. 记录 tdesktop 版本号到发布说明（缓存格式随版本漂移，§2.3）。

---

## 10. 版本里程碑与发布策略

### 10.1 里程碑

| 版本 | 目标 | 功能边界 | 预估工时 |
|------|------|---------|---------|
| **v0.1 MVP** | 本地缓存提取闭环 | 解密 TDEF → 识别媒体类型 → CLI + 简洁 GUI（CustomTkinter，§11）双入口输出；不做 MTProto、不解析本地消息数据库、不支持多账号 | ~53h |
| **v0.2** | 原始文件名恢复 | MTProto 会话复用 + API 拉取消息 + 三级匹配算法（§5.2）+ 限速策略（§5.3） | ~39h |
| **v0.3** | 体验优化 | GUI 增强（进度条、取消、导出报告）、多账号选择 | ~25h |
| **v1.0** | 稳定发布 | 完整测试覆盖、文档完善、GitHub Release 打包、单文件 exe 分发 | ~20h |

### 10.2 发布与开源策略

- **License**：MIT + README 明确免责声明与使用边界（工具本身中立，
  只做本地数据提取，不破解服务器、不预置代理、不托管内容）。
- **平台**：GitHub 首发，华为云 CodeHub 内部同步；`master` 为主
  分支，功能开发用 feature 分支。
- **分发**：PyInstaller 打包单文件 exe，GitHub Releases 托管。
  含 CustomTkinter 后需 `--collect-all customtkinter`（其主题/资源
  文件不在纯 Python 字节码内，缺省会启动即崩）；打包验证加入
  v1.0 检查清单。
- **签名**：首发不购买代码签名证书（零成本），用户需点
  "更多信息 → 仍要运行"；下载量上来后再评估。
- **变现**：开源免费；后续可考虑 Pro 闭源 GUI 版或技术支持服务。

### 10.3 工具链

`ruff`（格式化 + lint）+ `mypy`（静态类型检查）+ `pytest`（测试）。
mypy 在 P2 阶段接入（存量代码需补类型标注评审），新代码从 v0.2
起要求通过 `mypy --strict` 的模块级检查。

---

## 11. GUI 设计（CustomTkinter）

> v0.1 交付（TODO P0-14/P0-15）。GUI 是核心逻辑之上的薄层：
> 不含解密、识别、命名任何业务规则，core 模块保持零 GUI 依赖。

### 11.1 界面布局（简洁明了，单屏）

```
┌────────────────────────────────────┐
│  tdata 路径: [____________] [浏览]  │  ← 缺省自动探测填入
│  （未自动找到时的便携版提示行）      │  ← 仅探测失败时显示
│  输出目录:   [____________] [浏览]  │
│  本地密码:   [____________] (掩码)  │  ← 可选，无密码留空
│  （“本地密码”=锁定密码说明小字）     │
│  [开始提取] [取消] [打开目录] [导出报告] │
│  [========== 进度条 ==========]     │
│  日志: ┌────────────────────────┐  │
│        │ 滚动文本（只读）        │  │
│        └────────────────────────┘  │
│  成功 N / 跳过 M / 失败 K / 重复 D  │
└────────────────────────────────────┘
```

刻意不做：菜单栏、多标签页、文件列表预览——GUI 的目标是
"不会敲命令行的用户也能一次点成功"，任何超出这个目标的元素
都在制造维护成本。进度条、取消按钮、打开目录、导出报告与
新手引导文案已于 v0.1.2 落地（C-06/C-10）。

### 11.2 线程模型（硬性约束）

Tkinter 非线程安全。违反本节的 PR 一律拒绝：

1. 点击"开始提取"后，提取逻辑在 **worker 线程**执行，主线程
   保持事件循环响应。
2. worker 线程**禁止**直接读写任何控件；进度/日志通过
   `queue.Queue` 投递，主线程用 `root.after(100, poll)` 泵取更新。
3. 提取期间"开始"按钮置灰，防止重入。
4. worker 抛出的异常捕获后同样经 Queue 泵回，映射为
   `messagebox` 错误提示（文案复用 §7.2）。
5. 取消为协作式：cancel_event 仅由 worker 读取 is_set()，GUI 主线程
   只写 set()；进度经 _MSG_PROGRESS 队列消息投递。

### 11.3 共享管道契约

CLI 与 GUI 不得各写一套编排逻辑。P0-14 时从 `cli.main()` 提取：

```python
def run_pipeline(
    tdata_path: Path | None,
    output_dir: Path,
    password: str | None,
    progress_cb: Callable[[str], None] | None = None,
) -> ExtractionStats:
    """定位 tdata -> 派生 LocalKey -> 双缓存目录提取 -> 返回统计。

    progress_cb 接收日志行（CLI 传 print，GUI 传 Queue.put）。
    异常按 §7.2 类型上抛，由调用方（CLI/GUI）各自映射为
    退出码或 messagebox。
    """
```

`cli.main()` 改为 `run_pipeline` 的薄包装；GUI 同理。

### 11.4 依赖与打包

- `customtkinter` 加入 `requirements.txt` 与 pyproject `dependencies`；
  Tkinter 本身为 Python 标准库（Windows/macOS 官方安装器自带）。
- pyproject 新增入口 `tg-scoop-gui = tg_scoop.gui:main`。
- PyInstaller 打包需 `--collect-all customtkinter`（§10.2）。

---

## 12. 附录：TODO.md 草稿

> 以下内容为 `TODO.md` 的**历史草稿**（含初版模块名，如 qt_stream.py /
> crypto.py / tdf.py）。**权威任务清单以仓库根目录 `TODO.md` 为准**——
> 模块归并关系见 §1.2，最新进度状态也在其中维护。

```markdown
# tg-scoop TODO

## P0 — MVP（v0.1）
- [ ] 项目骨架：src layout、pyproject.toml、pytest、ruff
- [ ] qt_stream.py：QDataStream 读取器 + 单测
- [ ] crypto.py：PBKDF2-SHA512 派生、prepare_aes_oldmtp、纯 Python AES-IGE、decrypt_local
- [ ] tdf.py：TDF$ 解析与 MD5 校验
- [ ] tdata_reader.py：平台默认路径探测、key_datas 读取、LocalKey 派生
- [ ] crypto.py：CtrDecryptor + decrypt_storage_file（TDEF）
- [ ] cache_decryptor.py：cache 目录遍历（跳过 version/binlog/map*）
- [ ] media_detector.py：magic bytes 嗅探（8 种类型 + 边界条件）
- [ ] extractor.py：降级命名、序号去重、mtime 恢复、绝不覆盖
- [ ] cli.py：--tdata / --cache / --out / --passcode 参数，统计报告，退出码
- [ ] tests/fixtures/make_tdata.py：假 tdata 生成器 + golden 文件锚定
- [ ] 真实 tdesktop 环境手动验证（含设密码账号）
- [ ] README：安装、用法、FAQ、免责声明

## P1 — v0.2（MTProto 集成）
- [ ] tdata_reader.py：info_encrypted 解析、多账号索引
- [ ] mtproto_client.py：data name key 计算、dbiMtpAuthorization 提取（user_id/dc_id/auth_key）
- [ ] Telethon 会话复用（从 auth_key 构造 session，免登录）
- [ ] cache map0/map1 解析（cache key ↔ document.id）
- [ ] 三级匹配：document.id → 文件大小 → 内容哈希
- [ ] RateLimiter（≤30 msg/min）+ FloodWait 处理
- [ ] 断点续跑状态文件 .tg-scoop-state.json
- [ ] 原始文件名命名路径（API 可用时）

## P2 — v0.3 ~ v1.0
- [ ] 多账号支持（key_data#2 ...，--account 参数）
- [ ] 贴纸/语音/文件等其他媒体类型扩展
- [ ] 可选深度校验（ffprobe 存在时启用，不存在则跳过）
- [ ] 并行解密（multiprocessing，参考 Zwylair 实现）
- [ ] 增量提取模式（只处理新增缓存文件）
- [ ] 打包发布：pipx 安装、PyInstaller 单文件 Windows 版
- [ ] 兼容性矩阵：跟踪 tdesktop 版本与缓存格式漂移
```

---

## 参考链接

- [Zwylair/tgdesktop-cache-decryptor](https://github.com/Zwylair/tgdesktop-cache-decryptor) — 本项目 `refs/` 的参考实现（纯 Python、自动扩展名、mtime、多进程）
- [lilydjwg/telegram-cache-decryption](https://github.com/lilydjwg/telegram-cache-decryption) — 上游原始实现，本文 §3 的算法依据（实测兼容 tdesktop 4.2.4）
- [ntqbit/tdesktop-decrypter](https://github.com/ntqbit/tdesktop-decrypter) — tdata/MTP 授权数据的纯 Python 解析，本文 §5.1 的依据
- [atilaromero/telegram-desktop-decrypt](https://github.com/atilaromero/telegram-desktop-decrypt) — Go 实现的 tdata 解密，交叉参考

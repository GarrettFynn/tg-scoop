# tg-scoop (tg缓存捞)

从 Telegram Desktop 本地缓存中提取"限制保存内容"（Restrict Saving Content）的视频与图片的开源工具（CLI + 简洁 GUI 双入口）。

Telegram 私密群组/频道开启"限制保存"后，另存为与转发被禁用，但播放过的媒体仍会加密缓存在本地（`tdata/user_data/cache/`）。tg-scoop 把这些**已经缓存在你自己硬盘上**的文件解密出来。

## 核心原则

- 只做本地数据提取：不破解 Telegram 服务器、不预置代理、不托管内容
- **只读 tdata**：绝不修改 tdata 目录内的任何字节
- **绝不覆盖已有文件**：输出冲突时自动加序号后缀；重复运行幂等（不重复、不覆盖）

## 功能（v0.1）

- **CLI + 简洁图形界面双入口**（GUI 基于 CustomTkinter，不会命令行也能用）
- 解密 `tdata` 本地密钥并还原 TDEF 加密缓存（AES-256-IGE/CTR，纯 Python 实现，无 PyQt/OpenSSL 依赖）
- 通过 magic bytes 识别 9 种媒体类型：MP4 / WEBM / AVI / MKV / MOV / JPEG / PNG / GIF / WEBP
- 同时处理 `user_data/cache/` 与 `user_data/media_cache/` 两个缓存目录
- 确定性命名 `{sender}_{时间戳}_{哈希前8位}.{扩展名}`，支持安全地重复运行（增量提取）
- 保留缓存文件的修改时间（mtime），便于按时间排序找回内容
- 支持设有本地密码（Local Passcode）的 tdata

> 规划中（v0.2）：复用本地 MTProto 会话拉取消息历史，恢复原始文件名。设计见 [DEVELOPMENT.md](DEVELOPMENT.md) §5。

## 安装

需要 Python 3.11+（Windows / macOS / Linux）：

```bash
git clone <repo-url> && cd tg-scoop
python -m venv .venv
.venv/Scripts/pip install .        # Windows；Unix 用 .venv/bin/pip
```

安装后提供 `tg-scoop` 命令；也可以不安装，用 `PYTHONPATH=src python -m tg_scoop.cli` 直接运行。

## 用法

### 图形界面

```bash
tg-scoop-gui
```

单窗口操作：tdata 路径已自动探测填入，选输出目录、（如有）填本地密码，点"开始提取"即可。

### 命令行

```bash
# 最常用：自动探测 tdata 路径，输出到 ./tg-scoop-output
tg-scoop

# 指定 tdata 与输出目录
tg-scoop --tdata-path "D:\path\to\tdata" --output-dir "D:\recovered"

# tdata 设有本地密码（也可以省略，程序会交互式询问）
tg-scoop --password "your-passcode"
```

| 参数 | 说明 |
|---|---|
| `--tdata-path` | tdata 目录；缺省按平台自动探测（Windows: `%APPDATA%/Telegram Desktop/tdata`） |
| `--output-dir` | 输出目录；缺省 `./tg-scoop-output` |
| `--password` | tdata 本地密码；未提供且需要时会交互询问 |
| `--jobs` | 并行解密进程数；缺省 `1`（串行，保守）；推荐档位见下表 |
| `--types` | 只输出指定类型（逗号分隔，如 `mp4,jpg`）；可选 mp4,webm,avi,mkv,mov,jpg,png,gif,webp；缺省全选。GUI 用法：类型复选框勾选，全不勾不允许开始 |
| `--analyze` | 只读分析缓存占用（Top/最旧各 20 + 清理建议），不提取、不写盘 |
| `--chat-id` | 【v0.2 预留】按聊天过滤；当前版本忽略并给出警告 |

性能档位（GUI 下拉同义；并行输出与串行逐字节一致，只影响速度）：

| 档位 | 含义 |
|---|---|
| 保守 | `--jobs 1` 串行，内存占用最低 |
| 均衡（推荐） | `--jobs N`，N = min(核数-1, 8)（RAM < 4GB 时收敛到 2），GUI 缺省 |
| 极速 | `--jobs` = CPU 核数，适合大缓存且内存充裕的机器 |

**使用前提**：先在 Telegram Desktop 中完整播放/查看目标媒体（确保写入本地缓存），然后**完全退出** Telegram Desktop 再运行本工具。

**v0.2 前置条件（MTProto 功能，规划中）**：会话复用类功能需要 `pip install .[mtproto]` 安装可选依赖，并在 https://my.telegram.org 注册应用获得 api_id/api_hash（真实会话验证用；本轮功能为基础设施，不涉及消息拉取）。

## 输出与退出码

运行结束打印统计：`成功 N，跳过 M（非媒体），失败 K，重复 D`。

每次运行还会在输出目录生成 `manifest.json`：落盘/跳过/失败条目的完整清单（文件名、明文 SHA-256、大小、mtime、媒体类型、来源缓存目录），供审计"捞出了什么"。该文件是工具自身的报告，每轮覆盖重写；提取出的媒体文件仍绝不覆盖。

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 系统性故障（如磁盘写失败），已中止 |
| 2 | 找不到 tdata 目录或缓存目录 |
| 3 | 需要密码或密码错误 |
| 4 | 【v0.2】API 限速 |

## FAQ

**提示找不到缓存目录？**
先在 Telegram Desktop 里播放目标视频/查看目标图片，确认设置中没有禁用磁盘缓存，然后完全退出 Telegram 再运行。

**我的 tdata 设了本地密码？**
加 `--password`，或直接运行等待交互式密码提示。密码只用于本地派生解密密钥，不会上传或保存。
注意：`--password` 会留在 shell 历史与进程列表中，共享/公用机器上建议省略该参数，改用交互式输入。

**"本地密码"到底是哪个密码？**
指 Telegram Desktop 设置 → 隐私与安全 → **锁定密码**（锁住本机应用的那个）。
不是登录验证码，也不是两步验证密码。没设过就留空，工具按无密码路径工作。

**便携版 Telegram / 工具找不到 tdata？**
自动探测只覆盖系统默认安装路径。便携版的 tdata 在 Telegram.exe 旁边，
用 `--tdata-path` 显式指定（GUI 里手动填写或点"浏览"）。

**重复运行会覆盖已有文件吗？**
不会。相同内容的文件靠确定性命名与哈希比对识别为"重复"并跳过；同名不同内容的文件自动加 ` (1)`、` (2)` 后缀。工具绝不覆盖已有文件，因此可以随时重跑做增量提取。

**解密出来的文件无法播放？**
缓存可能只包含文件的一部分（Telegram 按需缓存分片）。确保目标媒体已完整播放后再运行。v0.1 不做可播放性深度校验（见 DEVELOPMENT.md §4.3）。

**支持第三方客户端（64Gram 等）的 tdata 吗？**
格式相同即可，用 `--tdata-path` 指向其 tdata 目录。

## 开发

设计文档：[DEVELOPMENT.md](DEVELOPMENT.md)；任务清单：[TODO.md](TODO.md)。

```bash
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python _selftest_tdata.py     # 及 _selftest_cache/media/extract/cli.py
```

## License

MIT，见 [LICENSE](LICENSE)。本工具只做本地数据提取，不破解 Telegram 服务器、不预置代理、不托管内容；请仅用于提取你自己账号已缓存的数据。使用者须遵守所在司法辖区的法律以及相关内容所有者设定的规则；作者不提供任何担保，不承担任何滥用责任。

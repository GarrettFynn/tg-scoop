# tg-scoop TODO

> 依据 `DEVELOPMENT.md` §10 草稿落地。优先级：P0 = MVP（v0.1）必须，P1 = v0.2（MTProto 集成），P2 = v0.3 ~ v1.0。
> 工时为单人预估（小时），依赖列给出阻塞关系。
> 状态标注：`[x]` = 完全完成；`[~]` = 实现完成、自测通过，pytest 单测待补；`[ ]` = 未开始。

## P0 — MVP（v0.1）

| # | 状态 | 任务 | 预估工时 | 依赖 |
|---|------|------|---------|------|
| P0-1 | [x] | 项目骨架：src layout、pyproject.toml、pytest、ruff | 2h | — |
| P0-2 | [x] | `tdata_reader.py`：QtStreamReader（QDataStream 读取器）——`_selftest_tdata.py` 已验证，pytest 单测待补 | 3h | P0-1 |
| P0-3 | [x] | `tdata_reader.py`：PBKDF2-SHA512 派生、prepare_aes_oldmtp、纯 Python AES-IGE、decrypt_local——自测全绿 | 6h | P0-2 |
| P0-4 | [x] | `tdata_reader.py`：TDF$ 解析与 MD5 尾校验（parse_tdf）——自测全绿 | 2h | P0-2 |
| P0-5 | [x] | `tdata_reader.py`：TDataReader —— 平台默认路径探测、key_datas 读取、LocalKey 派生——合成 key_datas 全链路自测通过 | 4h | P0-3, P0-4 |
| P0-6 | [x] | `cache_decryptor.py`：CtrDecryptor + decrypt_storage_file（TDEF）——`_selftest_cache.py` 已验证 | 4h | P0-3 |
| P0-7 | [x] | `cache_decryptor.py`：cache 目录遍历（跳过 version/binlog/map*）——自测全绿 | 2h | P0-6 |
| P0-8 | [x] | `media_detector.py`：magic bytes 嗅探（8 种类型 + 边界条件）——`_selftest_media.py` 已验证 | 4h | P0-1 |
| P0-9 | [x] | `extractor.py`：降级命名、序号去重、mtime 恢复、绝不覆盖——`_selftest_extract.py` 已验证（含幂等连跑） | 4h | P0-8 |
| P0-10 | [x] | `cli.py`：--tdata-path / --output-dir / --password 参数，统计报告，退出码——`_selftest_cli.py` 端到端已验证 | 3h | P0-5, P0-7, P0-9 |
| P0-11 | [x] | pytest 用例填充 + golden 文件锚定（tests/golden/：2 条 local 链 + 1 条 TDEF 链，由 refs 参考实现生成；78 用例全绿） | 6h | P0-3, P0-6 |
| P0-12 | [x] | 真实 tdesktop 环境手动验证（含设密码账号；配合 `scripts/diagnose_tdata.py` 输出兼容性报告）——2026-08-24 H-01 通过：tdesktop 7.1.1 x64 便携模式，轮次 A/B + GUI 全绿（提取 24587、失败 0、幂等 ✓、退出码 2/3 ✓），漂移项 D-7.1.1-1 已登记转 A-07 | 4h | P0-10, P0-11 |
| P0-13 | [x] | README：功能、安装、用法、退出码、FAQ、免责声明 | 2h | P0-10 |
| P0-14 | [x] | `gui.py`：CustomTkinter 单窗口（§11 布局）+ worker 线程模型 + `run_pipeline` 从 cli.main 提取重构——`_selftest_gui.py` 已验证；2026-08-24 H-01 人工验证通过（窗口/手填路径/统计与 CLI 一致/无警告） | 6h | P0-10 |
| P0-15 | [x] | 依赖与入口：customtkinter 入 requirements/pyproject、`tg-scoop-gui` entry point、PyInstaller 打包注记验证 | 1h | P0-14 |

**MVP 关键路径**：P0-1 → P0-2 → P0-3 → P0-5/P0-6 → P0-10 → P0-14 → P0-12。合计约 53h。

## P1 — v0.2（MTProto 集成）

| # | 任务 | 预估工时 | 依赖 |
|---|------|---------|------|
| P1-1 | `tdata_reader.py`：info_encrypted 解析、多账号索引（read_account_indexes）（✅ 已实现并有 pytest 覆盖） | 3h | P0-5 |
| P1-2 | `tdata_reader.py`：data name key 计算、dbiMtpAuthorization 提取（user_id/dc_id/auth_key）（✅ 实现+单测完成；真实数据验证待 P0-12） | 5h | P1-1 |
| P1-3 | Telethon 会话复用（从 auth_key 构造 session，免登录） | 6h | P1-2 |
| P1-4 | cache map0/map1 解析（cache key ↔ document.id） | 8h | P0-6 |
| P1-5 | 三级匹配：document.id → 文件大小+前1KB哈希 → 仅文件大小（人工核对） | 8h | P1-3, P1-4 |
| P1-6 | RateLimiter（≤30 msg/min）+ FloodWait 处理 | 3h | P1-3 |
| P1-7 | 断点续跑状态文件 .tg-scoop-state.json | 3h | P1-6 |
| P1-8 | 原始文件名命名路径（API 可用时，接 --chat-id 过滤） | 3h | P1-5 |

**v0.2 关键路径**：P1-1 → P1-2 → P1-3 → P1-5（并行 P1-4）→ P1-8。合计约 39h。

## P2 — v0.3 ~ v1.0

| # | 任务 | 预估工时 | 依赖 |
|---|------|---------|------|
| P2-1 | 多账号支持（key_data#2 ...，--account 参数） | 4h | P1-2 |
| P2-2 | 贴纸/语音/文件等其他媒体类型扩展 | 4h | P0-8 |
| P2-3 | 可选深度校验（ffprobe 存在时启用，不存在则跳过） | 3h | P0-8 |
| P2-4 | 并行解密（multiprocessing，参考 Zwylair 实现） | 5h | P0-7 |
| P2-5 | 增量提取模式（只处理新增缓存文件） | 3h | P1-7 |
| P2-6 | GUI 增强：进度条、取消按钮、导出报告（基于 v0.1 的 CustomTkinter 单窗口，DEVELOPMENT.md §11） | 8h | P0-14 |
| P2-7 | mypy 接入（存量补标注，新代码过模块级检查） | 3h | P0-1 |
| P2-8 | 打包发布：PyInstaller 单文件 exe、pipx 安装、GitHub Releases 流程 | 6h | P0-13 |
| P2-9 | ✅ README 完善：MIT License 文件 + 免责声明 + 使用边界（A-03 落地：LICENSE 已建，免责声明与使用边界在 README License 小节） | 2h | P0-13 |
| P2-10 | 兼容性矩阵：跟踪 tdesktop 版本与缓存格式漂移 | 持续 | P0-12 |

合计约 45h（不含持续项），对齐 v0.3（~25h）+ v1.0（~20h）里程碑。

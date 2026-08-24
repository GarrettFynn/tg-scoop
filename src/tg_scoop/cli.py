"""命令行入口与共享提取管道。

对应 DEVELOPMENT.md §7.2 的退出码约定、§8 的 MVP 边界与 §11.3 的
共享管道契约。CLI 与 GUI 共用 ``run_pipeline``，不得各写一套编排。

使用方式：``tg-scoop --tdata-path <tdata目录> --output-dir <输出目录>``
"""

import argparse
import getpass
import sys
from collections.abc import Callable
from pathlib import Path

from tg_scoop import process_check
from tg_scoop.cache_decryptor import CacheDecryptor
from tg_scoop.exceptions import (
    CacheNotFoundError,
    DecryptionError,
    PasswordRequiredError,
    TDataNotFoundError,
    TgScoopError,
)
from tg_scoop.extractor import ExtractionStats, Extractor
from tg_scoop.manifest import write_manifest
from tg_scoop.tdata_reader import TdataReader

# 退出码（DEVELOPMENT.md §7.2）
EXIT_OK = 0
EXIT_ERROR = 1  # 系统性故障（磁盘写失败等）
EXIT_NOT_FOUND = 2  # tdata / cache 不存在
EXIT_PASSWORD = 3  # 需要密码或密码错误
EXIT_RATE_LIMIT = 4  # 【v0.2】FloodWait

# 候选缓存根目录（user_data 下，存在才处理）
CACHE_DIR_NAMES = ("cache", "media_cache")


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。

    Returns:
        配置完成的 ArgumentParser，包含以下参数：

        - ``--tdata-path``：tdata 目录；缺省按平台自动探测。
        - ``--output-dir``：输出目录；缺省 ``./tg-scoop-output``。
        - ``--password``：tdata 本地密码（未设密码可省略）。
        - ``--chat-id``：【v0.2 预留】只处理指定聊天的媒体；
          v0.1 传入时给出警告并忽略。
    """
    parser = argparse.ArgumentParser(
        prog="tg-scoop",
        description="从 Telegram Desktop 本地缓存中提取受限保存的视频与图片",
    )
    parser.add_argument(
        "--tdata-path",
        type=Path,
        default=None,
        help="tdata 目录路径；缺省按平台自动探测",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tg-scoop-output"),
        help="输出目录（缺省 ./tg-scoop-output）",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="tdata 本地密码（未设密码可省略；不设密码的 tdata 无需提供）",
    )
    parser.add_argument(
        "--chat-id",
        default=None,
        help="【v0.2 预留】只处理指定聊天的媒体；当前版本忽略",
    )
    return parser


def run_pipeline(
    tdata_path: Path | None,
    output_dir: Path,
    password: str | None,
    progress_cb: Callable[[str], None] | None = None,
) -> ExtractionStats:
    """共享提取管道：定位 tdata -> 派生 LocalKey -> 双缓存目录提取。

    CLI 与 GUI 的唯一编排入口（DEVELOPMENT.md §11.3）。定位 tdata 后、
    派生 LocalKey 前检测 Telegram Desktop 进程，命中时经 ``progress_cb``
    输出一行醒目警告（不阻断，是否继续由用户承担）。本函数不做
    任何打印、退出码映射或密码交互——异常原样上抛，由调用方
    （CLI 映射退出码 / GUI 映射 messagebox，文案见 §7.2）。

    Args:
        tdata_path: tdata 目录；None 时按平台自动探测。
        output_dir: 输出目录。
        password: tdata 本地密码；None/空串表示无密码。
        progress_cb: 日志行回调（CLI 传 print，GUI 传 Queue.put）。

    Returns:
        合并后的提取统计。

    Raises:
        TDataNotFoundError: tdata 目录或 key 文件不存在。
        CacheNotFoundError: 两个候选缓存目录都不存在。
        PasswordRequiredError: 设有本地密码但未提供。
        DecryptionError: 密码错误或数据损坏。
        OSError: 写盘失败（系统性故障，调用方应中止）。
    """
    log = progress_cb or (lambda _msg: None)

    tdata_path = Path(tdata_path) if tdata_path else TdataReader.default_tdata_path()
    log(f"tdata 目录：{tdata_path}")
    proc = process_check.find_running_telegram()
    if proc is not None:
        log(
            f"警告：检测到 Telegram Desktop 正在运行（进程 {proc}）。"
            "缓存可能处于写入中状态，建议完全退出后重跑；本次仍将继续。"
        )
    reader = TdataReader(tdata_path)
    local_key = reader.read_local_key(password or "")
    log("LocalKey 派生成功")

    user_data = tdata_path / "user_data"
    cache_dirs = [
        d for d in (user_data / name for name in CACHE_DIR_NAMES) if d.is_dir()
    ]
    if not cache_dirs:
        raise CacheNotFoundError(
            f"未找到缓存目录（{user_data} 下无 "
            f"{'/'.join(CACHE_DIR_NAMES)}）；请先在 Telegram Desktop 中"
            "播放目标视频"
        )

    # 共享一个 Extractor 实例：跨目录内容去重因此生效
    extractor = Extractor(CacheDecryptor(local_key))
    total = ExtractionStats()
    for cache_dir in cache_dirs:
        try:
            log(f"处理缓存目录：{cache_dir}")
            total.merge(extractor.extract_all(cache_dir, output_dir))
        except CacheNotFoundError as exc:
            log(f"跳过：{exc}")
    manifest_path = write_manifest(
        output_dir,
        tdata_path=tdata_path,
        stats=total,
        extracted=extractor.extracted_entries,
        skipped=extractor.skipped_entries,
        failed=extractor.failed_entries,
    )
    log(f"manifest 已写入：{manifest_path}")
    return total


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口：run_pipeline 的薄包装。

    只捕获 TgScoopError 与 OSError，按异常类型映射退出码
    （DEVELOPMENT.md §7.2）。

    Args:
        argv: 参数列表；None 时使用 sys.argv。

    Returns:
        退出码（EXIT_* 常量）。
    """
    args = build_parser().parse_args(argv)

    if args.chat_id is not None:
        print("警告：--chat-id 是 v0.2 预留参数，当前版本忽略", file=sys.stderr)

    try:
        try:
            total = run_pipeline(
                args.tdata_path, args.output_dir, args.password, progress_cb=print
            )
        except PasswordRequiredError:
            # 未提供密码但 tdata 设有本地密码：交互询问一次后重试
            entered = getpass.getpass("该 tdata 设有本地密码，请输入: ")
            if not entered:
                raise PasswordRequiredError("passcode input cancelled")
            total = run_pipeline(
                args.tdata_path, args.output_dir, entered, progress_cb=print
            )
    except (PasswordRequiredError, DecryptionError) as exc:
        print(f"错误：密钥派生失败（{exc}）", file=sys.stderr)
        return EXIT_PASSWORD
    except (TDataNotFoundError, CacheNotFoundError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except OSError as exc:
        print(f"错误：写盘失败，已中止（{exc}）", file=sys.stderr)
        return EXIT_ERROR
    except TgScoopError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_ERROR

    print(
        f"完成：成功 {total.succeeded}，跳过 {total.skipped}（非媒体），"
        f"失败 {total.failed}，重复 {total.duplicates}"
    )
    if total.failed_reasons:
        reasons = ", ".join(
            f"{k}×{v}" for k, v in sorted(total.failed_reasons.items())
        )
        print(f"失败原因分布：{reasons}")
    print(f"输出目录：{args.output_dir}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

"""命令行入口与共享提取管道。

对应 DEVELOPMENT.md §7.2 的退出码约定、§8 的 MVP 边界与 §11.3 的
共享管道契约。CLI 与 GUI 共用 ``run_pipeline``，不得各写一套编排。

使用方式：``tg-scoop --tdata-path <tdata目录> --output-dir <输出目录>``
"""

import argparse
import getpass
import multiprocessing
import shutil
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from tg_scoop import process_check
from tg_scoop.cache_decryptor import (
    SKIP_FILENAMES,
    CacheDecryptor,
    iter_cache_files,
)
from tg_scoop.exceptions import (
    CacheNotFoundError,
    DecryptionError,
    PasswordRequiredError,
    TDataNotFoundError,
    TgScoopError,
)
from tg_scoop.extractor import (
    ExtractionStats,
    Extractor,
    _pool_decrypt_one,
    _pool_worker_init,
)
from tg_scoop.manifest import write_manifest
from tg_scoop.media_detector import MediaType
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
        help="Telegram 锁定密码（设置→隐私与安全→锁定密码）；未设置可省略。注意：会留在 shell 历史，共享机器建议省略改用交互式输入",
    )
    parser.add_argument(
        "--chat-id",
        default=None,
        help="【v0.2 预留】只处理指定聊天的媒体；当前版本忽略",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="并行解密进程数；1=串行（保守）；auto 见 GUI/文档推荐档位",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="只读分析缓存占用（Top/最旧各 20），不提取；与提取互斥",
    )
    parser.add_argument(
        "--types",
        default=None,
        help="只输出指定类型（逗号分隔，如 mp4,jpg）；可选值："
        + ",".join(t.value for t in MediaType)
        + "；缺省全选",
    )
    return parser


def run_pipeline(
    tdata_path: Path | None,
    output_dir: Path,
    password: str | None,
    progress_cb: Callable[[str], None] | None = None,
    file_progress_cb: Callable[[int, int], None] | None = None,
    cancel_event: object | None = None,
    jobs: int = 1,
    allowed_types: set[MediaType] | None = None,
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
        file_progress_cb: 可选逐文件进度回调，参数为
            ``(已完成数, 总文件数)``，每个文件处理完恰好一次（GUI 进度条用）。
        cancel_event: 可选协作式取消事件（threading.Event 风格鸭子
            类型）；置位后本轮剩余文件跳过，manifest 与统计照常落盘
            （记录实际完成部分），并输出一行取消日志。
        jobs: 并行解密进程数（C-02）；1=串行（默认，行为与旧版一致）。
            >1 时 worker 进程只解密写池内临时文件，主进程按排序序
            保序消费——输出与串行逐字节一致（确定性红线）。
        allowed_types: 可选输出类型过滤集合（C-13）；None=全选
            （现状行为），集合外类型计入 skipped 并记
            ``filtered_by_type:{类型}``。

    Returns:
        合并后的提取统计；取消时为部分统计。

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
    extractor = Extractor(CacheDecryptor(local_key), allowed_types=allowed_types)
    total = ExtractionStats()
    # 预数总文件数（空缓存目录与提取循环同语义：跳过不计）
    total_files = 0
    for d in cache_dirs:
        try:
            total_files += sum(1 for _ in iter_cache_files(d))
        except CacheNotFoundError:
            pass
    done = 0

    def _file_cb() -> None:
        nonlocal done
        done += 1
        if file_progress_cb is not None:
            file_progress_cb(done, total_files)

    if jobs > 1:
        _run_pipeline_parallel(
            extractor, cache_dirs, output_dir, local_key, total,
            jobs, _file_cb, cancel_event, log,
        )
    else:
        for cache_dir in cache_dirs:
            try:
                log(f"处理缓存目录：{cache_dir}")
                total.merge(
                    extractor.extract_all(
                        cache_dir, output_dir,
                        file_cb=_file_cb, cancel_event=cancel_event,
                    )
                )
            except CacheNotFoundError as exc:
                log(f"跳过：{exc}")
    if cancel_event is not None and cancel_event.is_set():
        log("已按用户要求取消：本轮剩余文件已跳过（部分完成）")
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


def _run_pipeline_parallel(
    extractor: Extractor,
    cache_dirs: list[Path],
    output_dir: Path,
    local_key: bytes,
    total: ExtractionStats,
    jobs: int,
    file_cb: Callable[[], None],
    cancel_event: object | None,
    log: Callable[[str], None],
) -> None:
    """并行提取路径（C-02，run_pipeline 的 jobs>1 分支）。

    worker 进程只解密写池内临时文件（``输出目录/.tg-scoop-pool/<pid>/``），
    主进程按 ``iter_cache_files`` 排序序经 ``imap`` 保序消费——命名/去重/
    manifest 与串行逐字节一致（确定性红线）。池目录开始与结束整体清理。
    取消置位时停止领取新结果，统计为已消费部分。
    """
    pool_root = Path(output_dir) / ".tg-scoop-pool"
    shutil.rmtree(pool_root, ignore_errors=True)  # 清理上次残留
    with multiprocessing.Pool(
        jobs, initializer=_pool_worker_init, initargs=(local_key, str(pool_root))
    ) as pool:
        for cache_dir in cache_dirs:
            try:
                log(f"处理缓存目录：{cache_dir}")
                files = list(iter_cache_files(cache_dir))
            except CacheNotFoundError as exc:
                log(f"跳过：{exc}")
                continue
            for path_str, plain, err in pool.imap(
                _pool_decrypt_one, (str(p) for p in files)
            ):
                if cancel_event is not None and cancel_event.is_set():
                    break
                extractor.consume_predecrypted(
                    Path(path_str), cache_dir.name,
                    Path(output_dir), total, plain, err,
                )
                file_cb()
    shutil.rmtree(pool_root, ignore_errors=True)


def analyze_cache(tdata_path: Path | None, log: Callable[[str], None] = print) -> None:
    """只读缓存占用分析（C-11）：不解密、不写 tdata、不写输出目录。

    输出：缓存总大小/文件数、占空间 Top 20（大小降序）、最旧 20 个
    （mtime 升序），末尾固定引导文案。

    Raises:
        TDataNotFoundError: tdata 目录不存在。
        CacheNotFoundError: 两个候选缓存目录都不存在。
    """
    tdata_path = (
        Path(tdata_path) if tdata_path else TdataReader.default_tdata_path()
    )
    user_data = tdata_path / "user_data"
    cache_dirs = [
        d for d in (user_data / name for name in CACHE_DIR_NAMES) if d.is_dir()
    ]
    if not cache_dirs:
        raise CacheNotFoundError(
            f"未找到缓存目录（{user_data} 下无 {'/'.join(CACHE_DIR_NAMES)}）"
        )

    entries: list[tuple[int, float, Path]] = []  # (size, mtime, path)
    for cache_dir in cache_dirs:
        for p in cache_dir.rglob("*"):
            if p.is_file() and p.name not in SKIP_FILENAMES:
                st = p.stat()
                entries.append((st.st_size, st.st_mtime, p))

    total_size = sum(e[0] for e in entries)
    log(f"tdata 目录：{tdata_path}")
    log(f"缓存总大小：{total_size} 字节（{total_size / (1 << 20):.1f} MiB），"
        f"文件数：{len(entries)}")

    def _fmt(entry: tuple[int, float, Path]) -> str:
        size, mtime, p = entry
        ts = datetime.fromtimestamp(mtime).isoformat(timespec="seconds")  # noqa: DTZ006 —— 与 manifest mtime 同口径（本地朴素时间）
        return f"  {size:>12} 字节  {ts}  {p}"

    log("占空间 Top 20：")
    for entry in sorted(entries, key=lambda e: (-e[0], e[1]))[:20]:
        log(_fmt(entry))
    log("最旧 20 个：")
    for entry in sorted(entries, key=lambda e: (e[1], -e[0]))[:20]:
        log(_fmt(entry))
    log(
        "清理建议：以上清单仅供人工核对。请优先使用 Telegram 自带功能"
        "（设置 → 高级 → 管理本地存储）清理旧缓存；"
        "tg-scoop 不删除任何 tdata 内文件。"
    )


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

    if args.analyze:
        # 只读分析模式（C-11）：不解密、不写任何目录
        try:
            analyze_cache(args.tdata_path)
        except (TDataNotFoundError, CacheNotFoundError) as exc:
            print(f"错误：{exc}", file=sys.stderr)
            return EXIT_NOT_FOUND
        return EXIT_OK

    allowed = None
    if args.types:
        try:
            allowed = {MediaType(t.strip().lower()) for t in args.types.split(",")}
        except ValueError as exc:
            print(f"错误：--types 含未知类型（{exc}）", file=sys.stderr)
            return EXIT_NOT_FOUND  # 参数错误复用退出码 2 口径

    try:
        try:
            total = run_pipeline(
                args.tdata_path, args.output_dir, args.password,
                progress_cb=print, jobs=args.jobs, allowed_types=allowed,
            )
        except PasswordRequiredError:
            # 未提供密码但 tdata 设有本地密码：交互询问一次后重试
            entered = getpass.getpass("该 tdata 设有本地密码，请输入: ")
            if not entered:
                raise PasswordRequiredError("passcode input cancelled")
            total = run_pipeline(
                args.tdata_path, args.output_dir, entered,
                progress_cb=print, jobs=args.jobs, allowed_types=allowed,
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

"""tg-scoop tdata 只读诊断工具（P0-12 辅助）。

对真实 tdata 做一次全格式假设体检：key 链派生、MTP 授权解析、
TDEF 缓存抽样解密与媒体识别。报告只到 stdout，逐段标记词
（PASS / FAIL / DRIFT / SKIP）按 DEVELOPMENT.md §9.3 的配套契约打印，
供人工验证时回传主脑裁决格式漂移；``--json`` 时改为输出单个
JSON 对象（结构见 ``main``），供机器读取裁决。

硬性约束：
- 只读：不创建输出目录、不写任何文件；
- 敏感数据：绝不打印 auth_key 本体、密码、salt；auth_key 只打印
  长度与 SHA-256 前 8 位指纹；
- 不新写二进制解析：一切解析只调用 tg_scoop 既有公开接口。

用法：
    python scripts/diagnose_tdata.py [tdata路径] [--password 密码] [--json]
"""

import argparse
import getpass
import hashlib
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tg_scoop.cache_decryptor import (
    CacheDecryptor,
    iter_cache_files,
)
from tg_scoop.exceptions import (
    CacheNotFoundError,
    CorruptedDataError,
    DecryptionError,
    PasswordRequiredError,
    TgScoopError,
)
from tg_scoop.media_detector import sniff_media_type
from tg_scoop.tdata_reader import TdataReader

# 缓存根目录候选（user_data 下）
_CACHE_DIR_NAMES = ("cache", "media_cache")

_CONCLUSION_OK = "全部格式假设成立"
_CONCLUSION_DRIFT = "发现漂移或失败点，请把本报告完整发回主脑"


@dataclass(frozen=True)
class _Section:
    """单段诊断结果：人类可读打印与 --json 输出共用的唯一数据源。

    ``detail`` 即人类可读行中标记词（``— `` 之后）的文本。
    """

    id: int
    name: str
    verdict: str  # PASS / FAIL / DRIFT / SKIP
    detail: str


def _build_parser() -> argparse.ArgumentParser:
    """构建参数解析器：位置参数 tdata 路径（缺省自动探测）+ --password + --json。"""
    parser = argparse.ArgumentParser(
        prog="diagnose_tdata",
        description="tg-scoop tdata 只读诊断：全格式假设体检，报告输出到 stdout",
    )
    parser.add_argument(
        "tdata",
        nargs="?",
        default=None,
        help="tdata 目录路径；缺省按平台自动探测",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="tdata 本地密码（未设密码可省略）",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="stdout 只输出一个 JSON 对象（机器可读），缺省为人类可读报告",
    )
    return parser


def _section_key_chain(
    tdata_path: Path, password: str | None
) -> tuple[TdataReader | None, bytes | None, _Section]:
    """[1] key 链：TdataReader -> read_local_key -> read_account_indexes。

    Returns:
        (reader, local_key, section)；section.verdict != "PASS" 时
        reader/local_key 为 None。
    """
    try:
        reader = TdataReader(tdata_path)
        try:
            local_key = reader.read_local_key(password or "")
        except PasswordRequiredError:
            entered = getpass.getpass("该 tdata 设有本地密码，请输入: ")
            local_key = reader.read_local_key(entered)
        indexes = reader.read_account_indexes(local_key)
    except (TgScoopError, OSError) as exc:
        return None, None, _Section(
            1, "key 链", "FAIL", f"{type(exc).__name__}: {exc}"
        )
    return reader, local_key, _Section(
        1,
        "key 链",
        "PASS",
        f"LocalKey 派生成功（{len(local_key)}B）；账号索引: {indexes}",
    )


def _section_mtp_auth(reader: TdataReader, local_key: bytes) -> _Section:
    """[2] MTP 授权：解析 dbiMtpAuthorization 块。"""
    try:
        mtp = reader.read_mtp_authorization(local_key)
    except CorruptedDataError as exc:
        if "unsupported settings block id" in str(exc):
            # 格式漂移信号：块 id 必须保留，原样打印完整异常消息
            return _Section(2, "MTP 授权", "DRIFT", str(exc))
        return _Section(2, "MTP 授权", "FAIL", f"CorruptedDataError: {exc}")
    except (TgScoopError, OSError) as exc:
        return _Section(2, "MTP 授权", "FAIL", f"{type(exc).__name__}: {exc}")
    fingerprint = hashlib.sha256(mtp.auth_key).hexdigest()[:8]
    return _Section(
        2,
        "MTP 授权",
        "PASS",
        f"user_id={mtp.user_id}, dc_id={mtp.dc_id}, "
        f"auth_key={len(mtp.auth_key)}B, fingerprint={fingerprint}",
    )


def _sample_cache_dir(decryptor: CacheDecryptor, cache_dir: Path) -> tuple[str, int]:
    """统计单个缓存目录（不落盘）。返回 (报告段, 解出数)。"""
    try:
        files = list(iter_cache_files(cache_dir))
    except CacheNotFoundError:
        return f"{cache_dir.name}/: SKIP（目录为空）", 0

    decrypted = 0
    failed: Counter[str] = Counter()
    types: Counter[str] = Counter()
    unrecognized = 0
    for path in files:
        try:
            data = decryptor.decrypt_file(path)
        except DecryptionError as exc:
            failed[type(exc).__name__] += 1
            continue
        decrypted += 1
        media_type = sniff_media_type(data)
        if media_type is None:
            unrecognized += 1
        else:
            types[media_type.value] += 1

    segment = (
        f"{cache_dir.name}/: 总 {len(files)}，解出 {decrypted}"
        f"（类型分布 {dict(types)}），失败 {sum(failed.values())}"
        f"（{dict(failed)}），未识别 {unrecognized}"
    )
    return segment, decrypted


def _section_cache(tdata_path: Path, local_key: bytes) -> _Section:
    """[3] 缓存抽样：cache/ 与 media_cache/ 分别统计。"""
    decryptor = CacheDecryptor(local_key)
    user_data = tdata_path / "user_data"
    segments: list[str] = []
    existing = 0
    total_decrypted = 0
    for name in _CACHE_DIR_NAMES:
        cache_dir = user_data / name
        if not cache_dir.is_dir():
            segments.append(f"{name}/: SKIP（目录不存在）")
            continue
        existing += 1
        segment, decrypted = _sample_cache_dir(decryptor, cache_dir)
        segments.append(segment)
        total_decrypted += decrypted

    joined = "；".join(segments)
    if existing > 0 and total_decrypted > 0:
        return _Section(3, "缓存抽样", "PASS", joined)
    return _Section(3, "缓存抽样", "FAIL", joined)


def main(argv: list[str] | None = None) -> int:
    """诊断入口：逐段产出报告，返回退出码（0 全 PASS / 1 有 FAIL 或 DRIFT）。

    人类可读模式逐段打印 ``[{id}] {name}: {verdict} — {detail}`` 行；
    ``--json`` 模式 stdout 只输出一个 JSON 对象::

        {"tdata_path": "...", "sections": [{"id": 1, "name": "key 链",
        "verdict": "PASS", "detail": "..."}], "conclusion": "...",
        "exit_code": 0}

    两种模式共用同一份 _Section 数据，判定逻辑只有一套。
    """
    args = _build_parser().parse_args(argv)

    tdata_path: Path | None = None
    resolve_error: TgScoopError | None = None
    try:
        tdata_path = (
            Path(args.tdata) if args.tdata else TdataReader.default_tdata_path()
        )
    except TgScoopError as exc:
        resolve_error = exc

    sections: list[_Section] = []
    if resolve_error is not None:
        sections.append(
            _Section(
                1, "key 链", "FAIL",
                f"{type(resolve_error).__name__}: {resolve_error}",
            )
        )
        reader, local_key = None, None
    else:
        reader, local_key, key_section = _section_key_chain(tdata_path, args.password)  # type: ignore[arg-type]
        sections.append(key_section)

    if sections[0].verdict != "PASS":
        sections.append(_Section(2, "MTP 授权", "SKIP", "key 链失败"))
        sections.append(_Section(3, "缓存抽样", "SKIP", "key 链失败"))
    else:
        sections.append(_section_mtp_auth(reader, local_key))  # type: ignore[arg-type]
        sections.append(_section_cache(tdata_path, local_key))  # type: ignore[arg-type]

    all_ok = all(section.verdict == "PASS" for section in sections)
    conclusion = _CONCLUSION_OK if all_ok else _CONCLUSION_DRIFT
    exit_code = 0 if all_ok else 1

    if args.json:
        report = {
            "tdata_path": str(tdata_path) if tdata_path is not None else None,
            "sections": [asdict(section) for section in sections],
            "conclusion": conclusion,
            "exit_code": exit_code,
        }
        print(json.dumps(report, ensure_ascii=False))
    else:
        print("== tg-scoop tdata 诊断报告 ==")
        print(f"tdata 路径: {tdata_path if tdata_path is not None else '（自动探测失败）'}")
        for section in sections:
            print(f"[{section.id}] {section.name}: {section.verdict} — {section.detail}")
        print(f"[4] 结论: {conclusion}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

"""构建 + 组包脚本（D-01）：PyInstaller one-dir → 绿色 zip。

用法：
    python packaging/build_zip.py --version 0.1.5

版本号缺省取环境变量 GITHUB_REF_NAME（CI tag），再缺省 "dev"。
产物：dist/tg-scoop-{version}-windows-x64/ 与同名 .zip。
PyInstaller 为构建期依赖，不入 requirements/pyproject。
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"
SPEC = REPO_ROOT / "packaging" / "tg-scoop.spec"
ONEDIR_NAME = "tg-scoop"  # spec COLLECT 的产物目录名

# ---- 任务 2：补充文件四件套（写死进脚本，不改仓库既有文件）----

README_FIRST_TXT = """tg-scoop（tg缓存捞）——快速上手（30 秒）

1. 双击 tg-scoop.exe，等窗口出来
2. 确认 tdata 路径（通常已自动填好；找不到就点"浏览"，
   选 Telegram.exe 旁边的 tdata 文件夹）
3. 点"开始提取"，等进度条跑完，点"打开输出目录"

常见问题：
- 文件名为什么是 unknown_时间戳_哈希？这是按缓存时间命名的，
  内容与原文件一致，能正常播放/查看
- 本工具只读取你自己的缓存，不联网、不修改 Telegram 任何文件
- 卸载方法：整个文件夹删除即可，无残留
- 被杀软拦截：看"杀软误报说明.txt"
- 完整指南：USAGE.md
"""

CHANGELOG_MD = """# tg-scoop 版本历史

## v0.1.5（2026-08-27）
- CTR 解密换 pycryptodome 原生 MODE_CTR：全量提取实测 ≈6.8×（9 分钟 → 73 秒）
- v0.2 基础能力（实验性）：manifest 清单、binlog 缓存索引、消息三级匹配、
  限速器、断点续跑、原始文件名命名（--chat-id + api_id/api_hash 启用）

## v0.1.4（2026-08-25）
- 类型过滤：GUI 复选框 + --types

## v0.1.3（2026-08-25）
- 流式解密（内存峰值与文件大小脱钩）；并行档位 + 硬件推荐；--analyze 缓存占用分析

## v0.1.2（2026-08-24）
- GUI：进度条、协作取消、打开输出目录、导出报告；新手引导；本地密码说明

## v0.1.1（2026-08-24）
- 首个公开发布：缓存提取闭环（CLI + GUI）、MIT、CI 三平台
"""

THIRD_PARTY_LICENSES_MD = """# 第三方许可

本发行包含以下第三方组件（已随包内嵌，仅作运行时使用）：

## pycryptodome（BSD 2-Clause）
- 用途：AES 解密原语（ECB/MODE_CTR）
- 许可：BSD 2-Clause License
- 项目：https://www.pycryptodome.org/

## customtkinter（MIT）
- 用途：GUI 界面库
- 许可：MIT License
- 项目：https://github.com/TomSchimansky/CustomTkinter

## Python（PSF License）
- 用途：内嵌 Python 3.11 运行时
- 许可：Python Software Foundation License
- 项目：https://www.python.org/
"""

ANTIVIRUS_TXT = """为什么杀毒软件可能拦截本程序？

tg-scoop 使用 PyInstaller 打包且未购买代码签名证书。部分杀毒软件
对"无签名的 PyInstaller 单目录程序"会启发式误报——这不代表程序
有问题。本程序全部源码公开：https://github.com/GarrettFynn/tg-scoop

如何核实？
1. 上传 https://www.virustotal.com/ 查看多引擎扫描结果
2. 对照 GitHub Release 页的发布说明与本文件

如何放行？
- Windows Defender：病毒和威胁防护 → 管理设置 → 排除项 → 添加本文件夹
- 其他杀软：查其"信任区/白名单"设置，添加本文件夹

本程序行为边界（供审查）：
- 只读取你指定目录下的 Telegram 缓存文件，绝不写入
- 不联网（除非你自己用 --chat-id 启用实验性消息匹配）
- 不安装、不写注册表、不加启动项
"""

EXTRA_FILES = {
    "先看这里.txt": README_FIRST_TXT,
    "CHANGELOG.md": CHANGELOG_MD,
    "THIRD_PARTY_LICENSES.md": THIRD_PARTY_LICENSES_MD,
    "杀软误报说明.txt": ANTIVIRUS_TXT,
}

# 从仓库根复制的文件
ROOT_FILES = ("README.md", "USAGE.md", "LICENSE")


def main() -> int:
    parser = argparse.ArgumentParser(description="构建 tg-scoop 绿色版 zip")
    parser.add_argument(
        "--version",
        default=os.environ.get("GITHUB_REF_NAME", "dev"),
        help="版本号（缺省 GITHUB_REF_NAME，再缺省 dev）",
    )
    args = parser.parse_args()
    version = args.version

    # 1. PyInstaller 可用性检查（缺失则报清晰错误，不自动安装）
    check = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--version"],
        capture_output=True, text=True, check=False,
    )
    if check.returncode != 0:
        print("错误：未找到 PyInstaller——请先 pip install pyinstaller"
              "（构建期依赖，不入 requirements.txt）", file=sys.stderr)
        return 1
    print(f"PyInstaller {check.stdout.strip()}")

    # 2. 构建 one-dir
    build = subprocess.run(
        [sys.executable, "-m", "PyInstaller", str(SPEC), "--clean", "--noconfirm"],
        cwd=REPO_ROOT, check=False,
    )
    if build.returncode != 0:
        print("错误：PyInstaller 构建失败", file=sys.stderr)
        return 1

    # 3. 组包目录（one-dir 产物整体 + 文档与补充文件）
    onedir = DIST / ONEDIR_NAME
    if not onedir.is_dir():
        print(f"错误：未找到 one-dir 产物 {onedir}", file=sys.stderr)
        return 1
    pkg = DIST / f"tg-scoop-{version}-windows-x64"
    if pkg.exists():
        shutil.rmtree(pkg)
    shutil.copytree(onedir, pkg)
    for name in ROOT_FILES:
        shutil.copy2(REPO_ROOT / name, pkg / name)
    for name, content in EXTRA_FILES.items():
        (pkg / name).write_text(content, encoding="utf-8", newline="\r\n")

    # 4. 打 zip（deflate）
    zip_path = DIST / f"tg-scoop-{version}-windows-x64.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(pkg.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(DIST))

    # 5. 打印产物路径与体积
    size_mb = zip_path.stat().st_size / (1 << 20)
    print(f"产物目录：{pkg}")
    print(f"zip：{zip_path}（{size_mb:.1f} MiB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

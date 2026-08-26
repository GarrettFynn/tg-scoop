# tg-scoop PyInstaller spec（D-01，DEVELOPMENT.md §11.4）
# one-dir 三入口共享 _internal：GUI(windowed) + CLI(console) + 诊断(console)
# 图标本期不加（无现成图标源，D-03 跟进项）

from PyInstaller.utils.hooks import collect_all

import os

_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # 仓库根（spec 在 packaging/ 下）

ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")  # 硬要求：缺了 GUI 启动即崩
crypto_datas, crypto_binaries, crypto_hidden = collect_all("Crypto")  # pycryptodome 数据文件保险

_common = dict(
    pathex=[os.path.join(_ROOT, "src")],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# GUI：无控制台黑框
gui_a = Analysis(
    [os.path.join(_ROOT, "packaging", "entry_gui.py")],
    datas=ctk_datas,
    binaries=ctk_binaries + crypto_binaries,
    hiddenimports=ctk_hidden + crypto_hidden,
    **_common,
)
# CLI：console
cli_a = Analysis(
    [os.path.join(_ROOT, "packaging", "entry_cli.py")],
    datas=crypto_datas,
    binaries=crypto_binaries,
    hiddenimports=crypto_hidden,
    **_common,
)
# 诊断：console（scripts/diagnose_tdata.py 直接作入口；其 sys.path.insert
# 在冻结包内无害——tg_scoop 由 pathex 打包）
diag_a = Analysis(
    [os.path.join(_ROOT, "scripts", "diagnose_tdata.py")],
    datas=crypto_datas,
    binaries=crypto_binaries,
    hiddenimports=crypto_hidden,
    **_common,
)

gui_pyz = PYZ(gui_a.pure)
cli_pyz = PYZ(cli_a.pure)
diag_pyz = PYZ(diag_a.pure)

gui_exe = EXE(
    gui_pyz, gui_a.scripts,
    name="tg-scoop",
    console=False,
    exclude_binaries=True,
)
cli_exe = EXE(
    cli_pyz, cli_a.scripts,
    name="tg-scoop-cli",
    console=True,
    exclude_binaries=True,
)
diag_exe = EXE(
    diag_pyz, diag_a.scripts,
    name="diagnose-tdata",
    console=True,
    exclude_binaries=True,
)

COLLECT(
    gui_exe, cli_exe, diag_exe,
    gui_a.binaries, gui_a.datas,
    cli_a.binaries, cli_a.datas,
    diag_a.binaries, diag_a.datas,
    name="tg-scoop",
)

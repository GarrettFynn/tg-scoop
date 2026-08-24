"""pytest 共享配置：src 布局的路径引导。

tests/ 下所有用例经本文件 import tg_scoop，单测文件内禁止
自行 sys.path.insert。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

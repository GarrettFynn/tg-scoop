"""GUI 冻结入口薄封装（D-01；freeze_support 供 --jobs 并行路径）。"""

import multiprocessing

from tg_scoop.gui import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

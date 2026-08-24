"""CustomTkinter 简洁 GUI。

对应 DEVELOPMENT.md §11：核心逻辑之上的薄层，不含任何解密/识别/
命名业务规则；与 CLI 共用 ``run_pipeline``（§11.3 共享管道契约）。

线程模型硬约束（§11.2，违反的 PR 一律拒绝）：
1. 提取在 worker 线程执行，主线程保持事件循环响应；
2. worker 线程禁止直接读写任何控件，日志经 queue.Queue 投递；
3. 主线程用 root.after() 泵取队列更新 UI；
4. 运行期间"开始"按钮置灰防重入。
"""

import queue
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from tg_scoop.cli import run_pipeline
from tg_scoop.exceptions import (
    CacheNotFoundError,
    DecryptionError,
    PasswordRequiredError,
    TDataNotFoundError,
    TgScoopError,
)
from tg_scoop.extractor import ExtractionStats
from tg_scoop.tdata_reader import TdataReader

# worker -> 主线程的消息类型
_MSG_LOG = "log"
_MSG_DONE = "done"
_MSG_ERROR = "error"

_POLL_MS = 100  # 主线程泵取队列的间隔


class ScoopApp(ctk.CTk):
    """单窗口 GUI：路径/密码输入 + 开始按钮 + 只读日志 + 统计行。

    是核心逻辑之上的薄层，不含任何解密/命名规则。
    """

    def __init__(self) -> None:
        """构建窗口与控件；tdata 路径尝试自动探测预填。"""
        super().__init__()
        self.title("tg-scoop (tg缓存捞)")
        self.geometry("640x480")

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None

        # tdata 路径（自动探测预填，失败留空由用户浏览选择）
        try:
            default_tdata = str(TdataReader.default_tdata_path())
        except TDataNotFoundError:
            default_tdata = ""
        self._tdata_var = ctk.StringVar(value=default_tdata)
        self._output_var = ctk.StringVar(value="tg-scoop-output")
        self._password_var = ctk.StringVar()

        self._build_path_row(0, "tdata 路径:", self._tdata_var)
        self._build_path_row(1, "输出目录:", self._output_var)

        ctk.CTkLabel(self, text="本地密码:").grid(
            row=2, column=0, padx=8, pady=4, sticky="e"
        )
        ctk.CTkEntry(self, textvariable=self._password_var, show="*").grid(
            row=2, column=1, padx=8, pady=4, sticky="ew"
        )

        self._start_button = ctk.CTkButton(
            self, text="开始提取", command=self._start_extraction
        )
        self._start_button.grid(row=3, column=0, columnspan=3, padx=8, pady=8)

        self._log_box = ctk.CTkTextbox(self, state="disabled")
        self._log_box.grid(row=4, column=0, columnspan=3, padx=8, pady=4, sticky="nsew")

        self._stats_var = ctk.StringVar(value="成功 - / 跳过 - / 失败 - / 重复 -")
        ctk.CTkLabel(self, textvariable=self._stats_var).grid(
            row=5, column=0, columnspan=3, padx=8, pady=8
        )

        self.columnconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)

    def _build_path_row(self, row: int, label: str, var: ctk.StringVar) -> None:
        """构建一行 标签 + 输入框 + 浏览按钮。"""
        ctk.CTkLabel(self, text=label).grid(row=row, column=0, padx=8, pady=4, sticky="e")
        ctk.CTkEntry(self, textvariable=var).grid(
            row=row, column=1, padx=8, pady=4, sticky="ew"
        )
        ctk.CTkButton(
            self, text="浏览", width=60, command=lambda: self._browse(var)
        ).grid(row=row, column=2, padx=8, pady=4)

    def _browse(self, var: ctk.StringVar) -> None:
        """弹出目录选择框并回填输入框。"""
        chosen = filedialog.askdirectory()
        if chosen:
            var.set(chosen)

    # ------------------------------------------------------------------
    # 提取流程（线程模型见 §11.2）
    # ------------------------------------------------------------------

    def _start_extraction(self) -> None:
        """点击开始：置灰按钮、清空日志、启动 worker 线程。"""
        if self._worker is not None and self._worker.is_alive():
            return  # 防重入（按钮置灰之外的兜底）
        self._start_button.configure(state="disabled")
        self._set_log("")
        self._stats_var.set("成功 - / 跳过 - / 失败 - / 重复 -")

        tdata = self._tdata_var.get().strip() or None
        args = (
            Path(tdata) if tdata else None,
            Path(self._output_var.get().strip() or "tg-scoop-output"),
            self._password_var.get() or None,
        )
        self._worker = threading.Thread(
            target=self._worker_run, args=args, daemon=True
        )
        self._worker.start()
        self.after(_POLL_MS, self._poll_queue)

    def _worker_run(
        self,
        tdata_path: Path | None,
        output_dir: Path,
        password: str | None,
    ) -> None:
        """worker 线程入口：跑管道，消息一律投队列，禁止触碰控件。"""
        try:
            stats = run_pipeline(
                tdata_path,
                output_dir,
                password,
                progress_cb=lambda line: self._queue.put((_MSG_LOG, line)),
            )
        except Exception as exc:  # noqa: BLE001 —— 有意兜底：异常必须全量泵回主线程（§11.2-4）
            self._queue.put((_MSG_ERROR, exc))
        else:
            self._queue.put((_MSG_DONE, stats))

    def _poll_queue(self) -> None:
        """主线程泵：排空队列并更新 UI；未结束则继续轮询。"""
        finished = False
        while True:
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == _MSG_LOG:
                self._append_log(str(payload))
            elif kind == _MSG_DONE:
                self._on_done(payload)  # type: ignore[arg-type]
                finished = True
            elif kind == _MSG_ERROR:
                self._on_error(payload)  # type: ignore[arg-type]
                finished = True
        if not finished:
            self.after(_POLL_MS, self._poll_queue)
        else:
            self._start_button.configure(state="normal")

    # ------------------------------------------------------------------
    # UI 更新（只在主线程被调用）
    # ------------------------------------------------------------------

    def _set_log(self, text: str) -> None:
        """整体替换日志内容。"""
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.insert("end", text)
        self._log_box.configure(state="disabled")

    def _append_log(self, line: str) -> None:
        """追加一行日志并滚到底部。"""
        self._log_box.configure(state="normal")
        self._log_box.insert("end", line + "\n")
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _on_done(self, stats: ExtractionStats) -> None:
        """提取完成：更新统计行并提示。"""
        self._stats_var.set(
            f"成功 {stats.succeeded} / 跳过 {stats.skipped} / "
            f"失败 {stats.failed} / 重复 {stats.duplicates}"
        )
        self._append_log(
            f"完成：成功 {stats.succeeded}，跳过 {stats.skipped}，"
            f"失败 {stats.failed}，重复 {stats.duplicates}"
        )
        messagebox.showinfo("tg-scoop", "提取完成")

    def _on_error(self, exc: Exception) -> None:
        """错误映射（文案对应 DEVELOPMENT.md §7.2）。"""
        if isinstance(exc, PasswordRequiredError):
            msg = "该 tdata 设有本地密码，请在密码框中填入后重试"
        elif isinstance(exc, DecryptionError):
            msg = f"密码错误或数据损坏：{exc}"
        elif isinstance(exc, (TDataNotFoundError, CacheNotFoundError)):
            msg = str(exc)
        elif isinstance(exc, OSError):
            msg = f"写盘失败，已中止：{exc}"
        elif isinstance(exc, TgScoopError):
            msg = str(exc)
        else:
            msg = f"未预期的错误：{exc}"
        self._append_log(f"错误：{msg}")
        messagebox.showerror("tg-scoop", msg)


def main() -> None:
    """GUI 入口（pyproject 的 tg-scoop-gui 指向这里）。"""
    ctk.set_appearance_mode("system")
    app = ScoopApp()
    app.mainloop()


if __name__ == "__main__":
    main()

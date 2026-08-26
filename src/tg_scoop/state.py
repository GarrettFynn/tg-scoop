"""断点续跑状态文件（B-06；DEVELOPMENT.md §5.3 末段）。

状态落在 输出目录/.tg-scoop-state.json：{"chat_id": ..., "last_message_id": ...}
（已扫描聊天 + 已处理的最小 message_id；消息按最新→最旧翻页，
断点即最小 id）。损坏时从头开始并警告，绝不让坏状态中断提取。
"""

import json
from collections.abc import Callable
from pathlib import Path

STATE_NAME = ".tg-scoop-state.json"


def load_state(output_dir: Path, log: Callable[[str], None] = print) -> dict | None:
    """读状态；文件不存在 → None；JSON 损坏或字段缺失 → 警告日志 + None（从头）。"""
    path = Path(output_dir) / STATE_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        chat_id = data["chat_id"]
        last_message_id = data["last_message_id"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log(f"警告：{STATE_NAME} 损坏（{type(exc).__name__}），已从头开始")
        return None
    return {"chat_id": chat_id, "last_message_id": last_message_id}


def save_state(output_dir: Path, chat_id: int | str, last_message_id: int) -> Path:
    """写状态（覆盖重写自身状态文件，UTF-8 JSON）；返回路径。"""
    path = Path(output_dir) / STATE_NAME
    path.write_text(
        json.dumps(
            {"chat_id": chat_id, "last_message_id": last_message_id},
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return path

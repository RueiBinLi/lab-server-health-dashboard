from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path


def initialize_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    server_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL
                )
                """
            )


def is_ready(path: Path) -> bool:
    try:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("SELECT 1 FROM servers LIMIT 1").fetchall()
    except sqlite3.Error:
        return False
    return True

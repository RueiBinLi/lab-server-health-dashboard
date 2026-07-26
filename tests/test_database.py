import sqlite3
import tempfile
import unittest
from pathlib import Path

from lab_dashboard.database import initialize_database


class DatabaseStartupTests(unittest.TestCase):
    def test_first_start_creates_empty_wal_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "dashboard.sqlite3"

            initialize_database(database_path)

            with sqlite3.connect(database_path) as connection:
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                server_count = connection.execute(
                    "SELECT COUNT(*) FROM servers"
                ).fetchone()[0]

        self.assertEqual(journal_mode, "wal")
        self.assertEqual(server_count, 0)

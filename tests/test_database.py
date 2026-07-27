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

    def test_seeded_profile_revisions_and_server_ids_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "dashboard.sqlite3"
            initialize_database(database_path)

            with sqlite3.connect(database_path) as connection:
                profiles = connection.execute(
                    """
                    SELECT profile_id, revision, state
                    FROM server_profiles
                    ORDER BY profile_id
                    """
                ).fetchall()
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "seeded profile revision is immutable",
                ):
                    connection.execute(
                        """
                        UPDATE server_profiles
                        SET seeded = 0
                        WHERE profile_id = 'general-linux'
                        """
                    )

            with sqlite3.connect(database_path) as connection:
                connection.execute(
                    """
                    INSERT INTO servers (
                        server_id, display_name, scrape_address,
                        profile_id, profile_revision, enrollment_state,
                        created_at
                    ) VALUES (
                        'original-id', 'Compute 1',
                        'https://10.0.0.1:9100/metrics',
                        'general-linux', 1,
                        'awaiting-first-contact',
                        '2026-07-27T00:00:00+00:00'
                    )
                    """
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "server ID is immutable"
                ):
                    connection.execute(
                        """
                        UPDATE servers
                        SET server_id = 'replacement-id'
                        WHERE server_id = 'original-id'
                        """
                    )

        self.assertEqual(
            profiles,
            [
                ("general-linux", 1, "published"),
                ("nvidia-gpu-compute", 1, "published"),
            ],
        )

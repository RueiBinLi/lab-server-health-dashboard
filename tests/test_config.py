import tempfile
import unittest
from pathlib import Path

from lab_dashboard.config import ConfigurationError, load_config


class ConfigurationTests(unittest.TestCase):
    def test_loads_database_path_and_loopback_trust(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)

            config = load_config(
                {
                    "DASHBOARD_DB_PATH": str(directory / "dashboard.sqlite3"),
                }
            )

        self.assertEqual(config.database_path, directory / "dashboard.sqlite3")
        self.assertEqual(
            config.trusted_proxy_networks, ("127.0.0.0/8", "::1/128")
        )

    def test_empty_trusted_proxy_list_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "trusted proxy networks are required"
        ):
            load_config({"DASHBOARD_TRUSTED_PROXY_CIDRS": ""})

    def test_invalid_trusted_proxy_list_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "trusted proxy networks are invalid"
        ):
            load_config({"DASHBOARD_TRUSTED_PROXY_CIDRS": "not-a-network"})


if __name__ == "__main__":
    unittest.main()

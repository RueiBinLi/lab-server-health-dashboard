import tempfile
import unittest
from pathlib import Path

from lab_dashboard.config import ConfigurationError, load_config


class ConfigurationTests(unittest.TestCase):
    def test_allowlist_authentication_requires_explicit_mode_and_role_lists(
        self,
    ) -> None:
        config = load_config(
            {
                "DASHBOARD_AUTH_MODE": "identity-allowlist",
                "DASHBOARD_LAB_ADMINISTRATOR_LOGINS": "ada@example.com",
                "DASHBOARD_LAB_USER_LOGINS": "lin@example.com",
            }
        )

        self.assertEqual(config.auth_mode, "identity-allowlist")
        self.assertEqual(
            config.lab_administrator_logins, ("ada@example.com",)
        )
        self.assertEqual(config.lab_user_logins, ("lin@example.com",))

    def test_allowlist_mode_fails_closed_without_allowlisted_identities(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "allowlist identities are required"
        ):
            load_config({"DASHBOARD_AUTH_MODE": "identity-allowlist"})

    def test_unknown_authentication_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "authentication mode is invalid"
        ):
            load_config({"DASHBOARD_AUTH_MODE": "automatic"})

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

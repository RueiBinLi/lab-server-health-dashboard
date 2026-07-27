import os
import subprocess
import tempfile
import unittest
from pathlib import Path


INSTALLER = (
    Path(__file__).parent.parent / "deploy" / "collector" / "install.sh"
)


class CollectorInstallerTests(unittest.TestCase):
    def test_installer_reports_inventory_and_matching_verification_code(
        self,
    ) -> None:
        source = INSTALLER.read_text()

        self.assertIn('"cpu": cpu', source)
        self.assertIn('"memory": memory', source)
        self.assertIn('"disks": disks', source)
        self.assertIn('"gpus": gpus', source)
        self.assertIn('"stableIdentifiers": stable_identifiers', source)
        self.assertIn("lab_critical_errors_total", source)
        self.assertIn("DCGM_FI_DEV_GPU_UTIL", source)
        self.assertIn("--collector.textfile.directory", source)
        self.assertIn("lab-collector-textfile.timer", source)
        self.assertIn('issued["verificationCode"]', source)
        self.assertIn("Verification code:", source)

    def test_installer_accepts_only_supported_ubuntu_releases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text('ID=debian\nVERSION_ID="13"\n')
            result = subprocess.run(
                ["bash", str(INSTALLER)],
                input="not-a-real-secret\n",
                text=True,
                capture_output=True,
                env={
                    **os.environ,
                    "LAB_OS_RELEASE_FILE": str(os_release),
                    "LAB_INSTALLER_PREFLIGHT_ONLY": "1",
                },
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ubuntu 22.04 or 24.04 LTS", result.stderr)

    def test_installer_rejects_token_arguments_and_checks_gpu_prerequisites(
        self,
    ) -> None:
        source = INSTALLER.read_text()
        argument_result = subprocess.run(
            ["bash", str(INSTALLER), "secret-must-not-be-an-argument"],
            text=True,
            capture_output=True,
        )

        self.assertNotEqual(argument_result.returncode, 0)
        self.assertIn("standard input or hidden prompt", argument_result.stderr)
        self.assertIn('read -r -s', source)
        self.assertIn("nvidia-smi", source)
        self.assertIn("/api/enrollment/requirements", source)
        self.assertIn("client_auth_type: RequireAndVerifyClientCert", source)
        self.assertIn("NODE_EXPORTER_VERSION=1.11.1", source)
        self.assertIn("DCGM_EXPORTER_VERSION=4.4.1-4.7.0", source)
        self.assertIn("DCGM_FI_DEV_GPU_UTIL", source)
        self.assertIn("DCGM_FI_DEV_FB_RESERVED", source)
        self.assertIn("DCGM_FI_DEV_SLOWDOWN_TEMP", source)
        self.assertIn("DCGM_FI_DEV_THERMAL_VIOLATION", source)
        self.assertIn("DCGM_EXP_XID_ERRORS_TOTAL", source)
        self.assertIn("DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", source)
        self.assertIn("DCGM_FI_DEV_ECC_DBE_AGG_TOTAL", source)
        self.assertIn("lab_health_gpu_resets_total", source)
        self.assertIn("ExecStart=$DCGM_EXPORTER_BIN", source)
        self.assertNotIn("lab_gpu_utilization_ratio", source)
        self.assertIn("install -d -m 0700", source)
        self.assertIn("chmod 0600", source)
        self.assertNotIn("nvidia-driver", source)
        self.assertNotIn("ufw", source)
        self.assertNotIn("iptables", source)


if __name__ == "__main__":
    unittest.main()

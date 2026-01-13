import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from unisecure.host_security import HostSecurityScanner


class HostSecurityScannerTests(unittest.TestCase):
    def test_scan_quick_mode_uses_common_tools(self):
        scanner = HostSecurityScanner(command_timeout=1)

        def mock_run(command, **_):
            if command[0] == "ufw":
                return CompletedProcess(command, 0, "Status: active\n", "")
            if command[0] == "ss":
                output = (
                    "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                    "tcp   LISTEN 0      128      0.0.0.0:22      0.0.0.0:*\n"
                )
                return CompletedProcess(command, 0, output, "")
            return CompletedProcess(command, 1, "", "")

        with patch.object(scanner, "_run_command", side_effect=mock_run), patch.object(
            scanner, "_command_exists", side_effect=lambda name: name in {"ufw", "ss"}
        ):
            results = scanner.scan(quick_mode=True)

        self.assertEqual(results["summary"]["total_checks"], 3)
        firewall = next(check for check in results["checks"] if check["check"] == "Firewall Status")
        self.assertEqual(firewall["status"], "passed")

        open_ports = next(check for check in results["checks"] if check["check"] == "Open Ports")
        self.assertEqual(open_ports["status"], "warning")
        self.assertIn("22/tcp", open_ports["details"])

    def test_security_updates_detects_available_packages(self):
        scanner = HostSecurityScanner(command_timeout=1)
        results = {
            "hostname": "localhost",
            "os": "Linux",
            "os_version": "test",
            "quick_mode": False,
            "checks": [],
            "summary": {"total_checks": 6, "passed": 0, "warnings": 0, "failed": 0},
        }

        def mock_run(command, **_):
            if command == ["apt-get", "-s", "upgrade"]:
                return CompletedProcess(command, 0, "2 upgraded, 0 newly installed, 0 to remove.\n", "")
            return CompletedProcess(command, 1, "", "")

        with patch.object(scanner, "_command_exists", side_effect=lambda name: name == "apt-get"), patch.object(
            scanner, "_run_command", side_effect=mock_run
        ):
            scanner._check_security_updates(results)

        update_check = next(check for check in results["checks"] if check["check"] == "Security Updates")
        self.assertEqual(update_check["status"], "warning")
        self.assertIn("2", update_check["message"])


if __name__ == "__main__":
    unittest.main()

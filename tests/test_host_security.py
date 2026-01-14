import io
import unittest
from contextlib import redirect_stdout
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
            results = scanner.scan(quick_mode=True, host="localhost")

        self.assertEqual(results["summary"]["total_checks"], 3)
        self.assertEqual(results["target"], "localhost")
        firewall = next(check for check in results["checks"] if check["check"] == "Firewall Status")
        self.assertEqual(firewall["status"], "passed")

        open_ports = next(check for check in results["checks"] if check["check"] == "Open Ports")
        self.assertEqual(open_ports["status"], "warning")
        self.assertIn("22/tcp", open_ports["details"])

    def test_scan_remote_target_runs_remote_checks(self):
        scanner = HostSecurityScanner(command_timeout=1)

        with patch.object(scanner, "_probe_host", return_value=True), patch.object(
            scanner, "_scan_remote_ports", return_value=["80/tcp"]
        ), patch.object(scanner, "_guess_remote_os", return_value=None):
            results = scanner.scan(quick_mode=True, host="example.com")

        self.assertEqual(results["hostname"], "example.com")
        self.assertEqual(results["summary"]["total_checks"], 4)

        target_check = next(check for check in results["checks"] if check["check"] == "Target Host")
        self.assertEqual(target_check["status"], "passed")

        open_ports = next(check for check in results["checks"] if check["check"] == "Open Ports")
        self.assertEqual(open_ports["status"], "warning")
        self.assertIn("80/tcp", open_ports["details"])

    def test_remote_os_guess_from_ping_output(self):
        scanner = HostSecurityScanner(command_timeout=1)
        ping_output = "64 bytes from 192.0.2.1: icmp_seq=1 ttl=128 time=10 ms\n"

        with patch.object(scanner, "_probe_host", return_value=True), patch.object(
            scanner, "_scan_remote_ports", return_value=[]
        ), patch.object(
            scanner, "_run_command", return_value=CompletedProcess(["ping"], 0, ping_output, "")
        ), patch.object(scanner, "_command_exists", side_effect=lambda name: name == "ping"):
            results = scanner.scan(quick_mode=True, host="example.com")

        os_check = next(check for check in results["checks"] if check["check"] == "Operating System")
        self.assertEqual(os_check["status"], "passed")
        self.assertIn("Windows-like", os_check["details"])

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

    def test_print_report_includes_details(self):
        scanner = HostSecurityScanner()
        results = {
            "hostname": "example",
            "os": "Linux",
            "os_version": "1.0",
            "quick_mode": True,
            "summary": {"total_checks": 2, "passed": 1, "warnings": 1, "failed": 0},
            "checks": [
                {"check": "Target Host", "status": "passed", "message": "ok", "details": "Host reachable"},
                {
                    "check": "Open Ports",
                    "status": "warning",
                    "message": "Detected 1 listening services",
                    "details": "Listening ports: 22/tcp (ssh)",
                },
            ],
        }

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            scanner.print_report(results)

        output = buffer.getvalue()
        self.assertIn("Details: Host reachable", output)
        self.assertIn("Listening ports: 22/tcp (ssh)", output)


if __name__ == "__main__":
    unittest.main()

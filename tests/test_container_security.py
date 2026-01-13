import json
import os
import tempfile
import unittest

from unisecure.container_security import ContainerSecurityScanner


class ContainerSecurityScannerTests(unittest.TestCase):
    def test_scan_with_mock_data(self):
        scanner = ContainerSecurityScanner(use_mock_data=True)
        results = scanner.scan("example:latest")

        self.assertEqual(results["image"], "example:latest")
        self.assertGreaterEqual(results["summary"]["warnings"], 1)
        self.assertGreaterEqual(len(results["vulnerabilities"]), 1)
        self.assertEqual(results["summary"]["vulnerabilities"]["medium"], 1)

    def test_save_report_outputs_file(self):
        scanner = ContainerSecurityScanner(use_mock_data=True)
        results = scanner.scan("example:latest")

        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            scanner.save_report(results, tmp_file.name)
            with open(tmp_file.name, "r", encoding="utf-8") as f:
                saved = json.load(f)
        finally:
            tmp_file.close()
            os.unlink(tmp_file.name)

        self.assertEqual(saved["image"], "example:latest")
        self.assertIn("checks", saved)
        self.assertIn("vulnerabilities", saved)


if __name__ == "__main__":
    unittest.main()

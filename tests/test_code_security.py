import json
import tempfile
from pathlib import Path
import unittest

from unisecure.code_security import CodeSecurityScanner


class CodeSecurityScannerTests(unittest.TestCase):
    def test_scan_reports_languages_and_tools(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            Path(tmp_dir, "main.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
            Path(tmp_dir, "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            Path(tmp_dir, "Main.java").write_text(
                "public class Main { public static void main(String[] args) { System.out.println(\"hi\"); }}\n",
                encoding="utf-8",
            )

            scanner = CodeSecurityScanner(tool_paths={"python": None, "go": None, "java": None})
            results = scanner.scan(tmp_dir)

            self.assertIn("python", results["languages"])
            self.assertIn("go", results["languages"])
            self.assertIn("java", results["languages"])

            self.assertGreaterEqual(results["summary"]["total_files"], 3)
            self.assertTrue(results["tools"])

            python_tool = next(tool for tool in results["tools"] if tool["language"] == "python")
            self.assertEqual(python_tool["status"], "skipped")
            self.assertGreater(results["summary"]["total_issues"], 0)
            self.assertTrue(any(issue["type"] == "command_injection" for issue in results["issues"]))

    def test_save_report_includes_tool_metadata(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            Path(tmp_dir, "main.py").write_text("print('ok')\n", encoding="utf-8")
            scanner = CodeSecurityScanner(tool_paths={"python": None})
            results = scanner.scan(tmp_dir)

            report_path = Path(tmp_dir, "code-report.json")
            scanner.save_report(results, report_path)

            with open(report_path, "r", encoding="utf-8") as f:
                saved = json.load(f)

            self.assertIn("tools", saved)
            self.assertIn("languages", saved)
            self.assertIn("issues", saved)


if __name__ == "__main__":
    unittest.main()

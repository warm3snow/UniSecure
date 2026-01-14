import unittest
from typing import Dict, Optional
from unittest.mock import Mock, patch

import requests

from unisecure.app_security import AppSecurityScanner


def build_response(status_code: int = 200, headers: Optional[Dict[str, str]] = None, body: str = "OK") -> Mock:
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = headers or {}
    response.text = body
    return response


class AppSecurityScannerTests(unittest.TestCase):
    def test_scan_reports_missing_security_headers(self):
        scanner = AppSecurityScanner()
        with patch.object(scanner, "_fetch", return_value=build_response(headers={"Content-Type": "text/html"})):
            results = scanner.scan("https://example.com")

        header_check = next(check for check in results["issues"] if check["check"] == "Security Headers")
        self.assertEqual(header_check["status"], "warning")
        self.assertIn("Missing security headers", header_check["message"])
        self.assertEqual(results["summary"]["total_checks"], len(scanner.checks))
        self.assertGreaterEqual(results["summary"]["warnings"], 1)

    def test_scan_handles_ssl_errors(self):
        scanner = AppSecurityScanner()
        with patch.object(scanner, "_fetch", side_effect=requests.exceptions.SSLError("certificate verify failed")):
            results = scanner.scan("https://bad.example")

        tls_check = next(check for check in results["issues"] if check["check"] == "SSL/TLS Configuration")
        self.assertEqual(tls_check["status"], "failed")
        self.assertIn("handshake failed", tls_check["message"].lower())
        self.assertEqual(results["summary"]["failed"], 1)

    def test_scan_detects_authentication_challenge(self):
        response = build_response(
            status_code=401,
            headers={
                "WWW-Authenticate": "Basic",
                "Strict-Transport-Security": "max-age=63072000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Access-Control-Allow-Origin": "https://example.com",
            },
            body="Auth required",
        )

        scanner = AppSecurityScanner()
        with patch.object(scanner, "_fetch", return_value=response):
            results = scanner.scan("https://secure.example")

        auth_check = next(check for check in results["issues"] if check["check"] == "Authentication")
        self.assertEqual(auth_check["status"], "passed")
        total_checks = len(scanner.checks)
        self.assertEqual(results["summary"]["warnings"], 0)
        self.assertEqual(results["summary"]["failed"], 0)
        self.assertEqual(results["summary"]["passed"], total_checks)
        self.assertEqual(results["summary"]["total_checks"], total_checks)


if __name__ == "__main__":
    unittest.main()

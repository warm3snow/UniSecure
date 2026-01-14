import unittest
from unittest.mock import patch

import requests

from unisecure.app_security import AppSecurityScanner


class AppSecurityScannerTests(unittest.TestCase):
    @patch("unisecure.app_security.requests.get")
    def test_scan_reports_missing_security_headers(self, mock_get):
        response = requests.Response()
        response.status_code = 200
        response._content = b"OK"
        response.headers = {"Content-Type": "text/html"}
        mock_get.return_value = response

        scanner = AppSecurityScanner()
        results = scanner.scan("https://example.com")

        header_check = next(check for check in results["issues"] if check["check"] == "Security Headers")
        self.assertEqual(header_check["status"], "warning")
        self.assertIn("Missing security headers", header_check["message"])
        self.assertEqual(results["summary"]["total_checks"], 5)
        self.assertGreaterEqual(results["summary"]["warnings"], 1)

    @patch("unisecure.app_security.requests.get")
    def test_scan_handles_ssl_errors(self, mock_get):
        mock_get.side_effect = requests.exceptions.SSLError("certificate verify failed")

        scanner = AppSecurityScanner()
        results = scanner.scan("https://bad.example")

        tls_check = next(check for check in results["issues"] if check["check"] == "SSL/TLS Configuration")
        self.assertEqual(tls_check["status"], "failed")
        self.assertIn("handshake failed", tls_check["message"].lower())
        self.assertEqual(results["summary"]["failed"], 1)

    @patch("unisecure.app_security.requests.get")
    def test_scan_detects_authentication_challenge(self, mock_get):
        response = requests.Response()
        response.status_code = 401
        response._content = b"Auth required"
        response.headers = {
            "WWW-Authenticate": "Basic",
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Access-Control-Allow-Origin": "https://example.com",
        }
        mock_get.return_value = response

        scanner = AppSecurityScanner()
        results = scanner.scan("https://secure.example")

        auth_check = next(check for check in results["issues"] if check["check"] == "Authentication")
        self.assertEqual(auth_check["status"], "passed")
        self.assertEqual(results["summary"]["warnings"], 0)
        self.assertEqual(results["summary"]["failed"], 0)
        self.assertEqual(results["summary"]["passed"], 5)


if __name__ == "__main__":
    unittest.main()

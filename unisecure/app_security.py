"""Application security scanner module."""
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException, SSLError


class AppSecurityScanner:
    """Scanner for application security vulnerabilities."""

    DEFAULT_TIMEOUT = 5
    RECOMMENDED_HEADERS = (
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    )
    HTTP_UNAUTHORIZED = 401
    HTTP_FORBIDDEN = 403
    MAX_BODY_BYTES = 8192
    DEFAULT_USER_AGENT = "UniSecure-AppScanner/0.1"
    MAX_REDIRECTS = 3

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, user_agent: Optional[str] = None):
        self.checks = [
            "ssl_tls_configuration",
            "security_headers",
            "authentication",
            "authorization",
            "input_validation",
        ]
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self.session = requests.Session()

    def scan(self, target: str, ports: Tuple[str, ...] = ()) -> Dict[str, Any]:
        """Scan application for security issues.

        Args:
            target: Target application URL or identifier
            ports: Optional ports to scan

        Returns:
            Dictionary containing scan results
        """
        normalized_target = self._normalize_target(target, ports)
        results = {
            "target": normalized_target,
            "ports": list(ports) if ports else [],
            "issues": [],
            "summary": {
                "total_checks": len(self.checks),
                "passed": 0,
                "failed": 0,
                "warnings": 0,
            },
        }

        response: Optional[Response] = None
        fetch_error: Optional[RequestException] = None
        try:
            response = self._fetch(normalized_target)
        except SSLError as exc:  # TLS/SSL specific failures should fail the check
            fetch_error = exc
        except RequestException as exc:
            fetch_error = exc

        self._check_ssl_tls(normalized_target, results, response, fetch_error)
        self._check_security_headers(results, response)
        self._check_authentication(results, response)
        self._check_authorization(results, response)
        self._check_input_validation(results, response)

        return results

    def _record_check(self, results: Dict[str, Any], check: Dict[str, Any]) -> None:
        results["issues"].append(check)
        status = check.get("status")
        if status == "passed":
            results["summary"]["passed"] += 1
        elif status == "warning":
            results["summary"]["warnings"] += 1
        elif status == "failed":
            results["summary"]["failed"] += 1

    def _normalize_target(self, target: str, ports: Tuple[str, ...]) -> str:
        parsed = urlparse(target)
        if parsed.scheme:
            return target

        parsed_with_scheme = urlparse(f"https://{target}")
        host = parsed_with_scheme.hostname or target
        path = parsed_with_scheme.path or ""
        query = f"?{parsed_with_scheme.query}" if parsed_with_scheme.query else ""

        if host and ":" in host and not host.startswith("["):
            host = f"[{host}]"

        if parsed_with_scheme.port:
            host_port = f"{host}:{parsed_with_scheme.port}"
        elif ports:
            host_port = f"{host}:{ports[0]}"
        else:
            host_port = host

        return f"https://{host_port}{path}{query}"

    def _fetch(self, target: str) -> Response:
        headers = {"User-Agent": self.user_agent}
        url = target
        redirects = 0

        while True:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=True,
                headers=headers,
            )

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if location and redirects < self.MAX_REDIRECTS:
                    redirects += 1
                    url = urljoin(url, location)
                    continue
                if location:
                    raise RequestException(f"Redirect limit exceeded after {redirects} hops")

            return response

    def _check_ssl_tls(
        self,
        target: str,
        results: Dict[str, Any],
        response: Optional[Response],
        error: Optional[RequestException],
    ) -> None:
        """Check SSL/TLS configuration."""
        parsed = urlparse(target)
        if parsed.scheme != "https":
            self._record_check(
                results,
                {
                    "check": "SSL/TLS Configuration",
                    "status": "warning",
                    "message": "HTTPS not enforced; enable TLS for transport security.",
                },
            )
            return

        if isinstance(error, SSLError):
            self._record_check(
                results,
                {
                    "check": "SSL/TLS Configuration",
                    "status": "failed",
                    "message": f"SSL/TLS handshake failed: {error}",
                },
            )
            return
        if error:
            self._record_check(
                results,
                {
                    "check": "SSL/TLS Configuration",
                    "status": "warning",
                    "message": f"TLS verification could not be completed: {error}",
                },
            )
            return
        if response is None:
            self._record_check(
                results,
                {
                    "check": "SSL/TLS Configuration",
                    "status": "warning",
                    "message": "TLS verification could not be completed: No response received.",
                },
            )
            return

        has_hsts = bool(response.headers.get("Strict-Transport-Security"))
        self._record_check(
            results,
            {
                "check": "SSL/TLS Configuration",
                "status": "passed" if has_hsts else "warning",
                "message": "HTTPS with HSTS configured."
                if has_hsts
                else "HTTPS detected but HSTS header missing.",
            },
        )

    def _check_security_headers(self, results: Dict[str, Any], response: Optional[Response]) -> None:
        """Check security headers."""
        if response is None:
            self._record_check(
                results,
                {
                    "check": "Security Headers",
                    "status": "warning",
                    "message": "Unable to evaluate security headers (no response).",
                },
            )
            return

        missing_headers = [header for header in self.RECOMMENDED_HEADERS if header not in response.headers]
        status = "passed" if not missing_headers else "warning"
        message = (
            "All recommended security headers present."
            if status == "passed"
            else f"Missing security headers: {', '.join(missing_headers)}"
        )
        self._record_check(
            results,
            {
                "check": "Security Headers",
                "status": status,
                "message": message,
            },
        )

    def _check_authentication(self, results: Dict[str, Any], response: Optional[Response]) -> None:
        """Check authentication mechanisms."""
        if response is None:
            self._record_check(
                results,
                {
                    "check": "Authentication",
                    "status": "warning",
                    "message": "Authentication mechanisms could not be assessed.",
                },
            )
            return

        if response.status_code in (self.HTTP_UNAUTHORIZED, self.HTTP_FORBIDDEN):
            self._record_check(
                results,
                {
                    "check": "Authentication",
                    "status": "passed",
                    "message": f"Authentication enforced (HTTP {response.status_code}).",
                },
            )
            return

        if response.headers.get("WWW-Authenticate"):
            self._record_check(
                results,
                {
                    "check": "Authentication",
                    "status": "passed",
                    "message": "Authentication challenge detected.",
                },
            )
            return

        self._record_check(
            results,
            {
                "check": "Authentication",
                "status": "warning",
                "message": "No authentication challenge detected; verify access controls for protected endpoints.",
            },
        )

    def _check_authorization(self, results: Dict[str, Any], response: Optional[Response]) -> None:
        """Check authorization controls."""
        if response is None:
            self._record_check(
                results,
                {
                    "check": "Authorization",
                    "status": "warning",
                    "message": "Authorization controls could not be evaluated.",
                },
            )
            return

        cors_origin = response.headers.get("Access-Control-Allow-Origin")
        if cors_origin == "*":
            self._record_check(
                results,
                {
                    "check": "Authorization",
                    "status": "warning",
                    "message": "Permissive CORS policy detected (Access-Control-Allow-Origin: *).",
                },
            )
            return

        self._record_check(
            results,
            {
                "check": "Authorization",
                "status": "passed",
                "message": "No overly permissive CORS configuration detected.",
            },
        )

    def _check_input_validation(self, results: Dict[str, Any], response: Optional[Response]) -> None:
        """Check input validation."""
        if response is None:
            self._record_check(
                results,
                {
                    "check": "Input Validation",
                    "status": "warning",
                    "message": "Input validation could not be reviewed without application response.",
                },
            )
            return

        body = (response.text or "")[: self.MAX_BODY_BYTES]
        body = body.lower()
        error_indicators = (
            "traceback (most recent call last)",
            "stack trace",
            "unhandled exception",
            "nullpointerexception",
            "fatal error",
            "exception in thread",
        )
        if any(indicator in body for indicator in error_indicators):
            self._record_check(
                results,
                {
                    "check": "Input Validation",
                    "status": "warning",
                    "message": "Verbose error details exposed; review input validation and error handling.",
                },
            )
            return

        self._record_check(
            results,
            {
                "check": "Input Validation",
                "status": "passed",
                "message": "No verbose error messages detected in response body.",
            },
        )

    def print_report(self, results: Dict):
        """Print scan results to console."""
        print(f"\nApplication Security Scan Results")
        print(f"{'='*60}")
        print(f"Target: {results['target']}")
        if results["ports"]:
            print(f"Ports: {', '.join(results['ports'])}")
        print(f"\nSummary:")
        print(f"  Total checks: {results['summary']['total_checks']}")
        print(f"  Passed:       {results['summary']['passed']}")
        print(f"  Warnings:     {results['summary']['warnings']}")
        print(f"  Failed:       {results['summary']['failed']}")

        print(f"\nCheck Details:")
        for issue in results["issues"]:
            status_symbol = {
                "passed": "✓",
                "warning": "⚠",
                "failed": "✗",
            }.get(issue["status"], "?")
            print(f"  {status_symbol} {issue['check']}: {issue['message']}")

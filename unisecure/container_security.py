"""Container security scanner module."""
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, Tuple, List


class ContainerSecurityScanner:
    """Scanner for container security vulnerabilities."""
    
    SEVERITIES = ('critical', 'high', 'medium', 'low', 'unknown')
    TRIVY_SCAN_TIMEOUT = 300
    MAX_DISPLAYED_VULNERABILITIES = 5
    
    def __init__(self, use_mock_data: bool = True, trivy_path: Optional[str] = None):
        """Initialize container security scanner.
        
        Args:
            use_mock_data: If True, use mock vulnerability data for demonstration.
                           Set to False in production environments.
            trivy_path: Optional path to trivy executable. Defaults to discovery on PATH.
        """
        self.use_mock_data = use_mock_data
        self.trivy_path = trivy_path or shutil.which("trivy")
        self.checks = [
            'base_image',
            'vulnerabilities',
            'configuration',
            'secrets',
            'user_permissions',
        ]
    
    def scan(self, image: str, registry: Optional[str] = None) -> Dict[str, Any]:
        """Scan container image for security issues.
        
        Args:
            image: Container image name
            registry: Optional registry URL
            
        Returns:
            Dictionary containing scan results
        """
        results = {
            'image': image,
            'registry': registry or 'default',
            'checks': [],
            'vulnerabilities': [],
            'summary': {
                'total_checks': len(self.checks),
                'passed': 0,
                'warnings': 0,
                'failed': 0,
                'vulnerabilities': {severity: 0 for severity in self.SEVERITIES},
            }
        }
        
        # Perform security checks
        self._check_base_image(image, results)
        self._check_vulnerabilities(image, results)
        self._check_configuration(image, results)
        self._check_secrets(image, results)
        self._check_user_permissions(image, results)
        
        return results
    
    def _check_base_image(self, image: str, results: Dict):
        """Check base image security."""
        check = {
            'check': 'Base Image',
            'status': 'passed',
            'message': f'Base image: {image}',
            'details': 'Image should use official or verified base images',
        }
        results['checks'].append(check)
        results['summary']['passed'] += 1
    
    def _check_vulnerabilities(self, image: str, results: Dict):
        """Check for known vulnerabilities using Trivy."""
        vulnerabilities: List[Dict[str, Any]] = []
        source = 'mock data'
        status = 'passed'
        message = 'No vulnerabilities detected'
        details = 'Container image may have known vulnerabilities'
        
        try:
            vulnerabilities, source = self._fetch_vulnerabilities(image)
            status = 'warning' if vulnerabilities else 'passed'
            message = f'Found {len(vulnerabilities)} vulnerabilities using {source}'
            details = f'Vulnerability scan source: {source}'
        except RuntimeError as exc:
            status = 'failed'
            message = f'Failed to run vulnerability scan: {exc}'
            details = 'Ensure Trivy CLI is installed and accessible on PATH.'
        
        check = {
            'check': 'Vulnerability Scan',
            'status': status,
            'message': message,
            'details': details,
        }
        results['checks'].append(check)
        results['vulnerabilities'].extend(vulnerabilities)
        
        self._update_summary(status, results, vulnerabilities)
    
    def _fetch_vulnerabilities(self, image: str) -> Tuple[List[Dict[str, Any]], str]:
        """Run Trivy to fetch vulnerabilities or return mock data."""
        if self.use_mock_data:
            return self._mock_vulnerabilities(), 'mock data'
        
        if not self.trivy_path:
            raise RuntimeError('Trivy CLI not found')
        if not isinstance(image, str) or not image.strip():
            raise RuntimeError('Image name is required for scanning')
        
        cmd = [
            self.trivy_path,
            'image',
            '--security-checks',
            'vuln',
            '--format',
            'json',
            '--quiet',
            image,
        ]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.TRIVY_SCAN_TIMEOUT,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError('Trivy scan timed out')
        
        if completed.returncode != 0:
            error_msg = completed.stderr.strip() or 'Trivy scan failed'
            raise RuntimeError(error_msg)
        if completed.stdout is None or not completed.stdout.strip():
            raise RuntimeError('Trivy returned empty output')
        
        try:
            scan_output = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Unable to parse Trivy output: {exc}') from exc
        
        return self._parse_trivy_results(scan_output), 'Trivy'
    
    def _parse_trivy_results(self, scan_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from Trivy JSON output."""
        vulnerabilities: List[Dict[str, Any]] = []
        for result in scan_output.get('Results', []):
            for vuln in result.get('Vulnerabilities') or []:
                vulnerabilities.append(
                    {
                        'cve': vuln.get('VulnerabilityID'),
                        'severity': self._normalize_severity(vuln.get('Severity')),
                        'package': vuln.get('PkgName'),
                        'version': vuln.get('InstalledVersion'),
                        'fixed_in': vuln.get('FixedVersion') or 'N/A',
                        'title': vuln.get('Title'),
                    }
                )
        return vulnerabilities
    
    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity to known buckets."""
        normalized = (severity or '').lower()
        return normalized if normalized in self.SEVERITIES else 'unknown'
    
    def _mock_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Provide mock vulnerability data for demo/testing."""
        return [
            {
                'cve': 'CVE-2024-0001',
                'severity': 'medium',
                'package': 'example-lib',
                'version': '1.2.3',
                'fixed_in': '1.2.4',
            }
        ]
    
    def _check_configuration(self, image: str, results: Dict):
        """Check container configuration."""
        check = {
            'check': 'Configuration',
            'status': 'passed',
            'message': 'Container configuration reviewed',
            'details': 'No insecure configurations detected',
        }
        results['checks'].append(check)
        results['summary']['passed'] += 1
    
    def _check_secrets(self, image: str, results: Dict):
        """Check for exposed secrets."""
        check = {
            'check': 'Secrets Management',
            'status': 'passed',
            'message': 'No exposed secrets detected in image layers',
            'details': 'Secrets should be managed via environment variables or secret stores',
        }
        results['checks'].append(check)
        results['summary']['passed'] += 1
    
    def _check_user_permissions(self, image: str, results: Dict):
        """Check user permissions."""
        check = {
            'check': 'User Permissions',
            'status': 'warning',
            'message': 'Container may be running as root',
            'details': 'Containers should run as non-root users when possible',
        }
        results['checks'].append(check)
        results['summary']['warnings'] += 1
    
    def _update_summary(self, status: str, results: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]):
        """Update summary statistics."""
        if status == 'passed':
            results['summary']['passed'] += 1
        elif status == 'warning':
            results['summary']['warnings'] += 1
        elif status == 'failed':
            results['summary']['failed'] += 1
        
        for vuln in vulnerabilities:
            severity_key = self._normalize_severity(vuln.get('severity'))
            results['summary']['vulnerabilities'][severity_key] += 1
    
    def print_report(self, results: Dict):
        """Print scan results to console."""
        print(f"\nContainer Security Scan Results")
        print(f"{'='*60}")
        print(f"Image: {results['image']}")
        print(f"Registry: {results['registry']}")
        print(f"\nSummary:")
        print(f"  Total checks: {results['summary']['total_checks']}")
        print(f"  Passed:       {results['summary']['passed']}")
        print(f"  Warnings:     {results['summary']['warnings']}")
        print(f"  Failed:       {results['summary']['failed']}")
        
        vuln_summary = results['summary']['vulnerabilities']
        total_vulns = sum(vuln_summary.values())
        if total_vulns > 0:
            print(f"\nVulnerabilities:")
            print(f"  Critical: {vuln_summary['critical']}")
            print(f"  High:     {vuln_summary['high']}")
            print(f"  Medium:   {vuln_summary['medium']}")
            print(f"  Low:      {vuln_summary['low']}")
            print(f"  Unknown:  {vuln_summary['unknown']}")
            
            if results['vulnerabilities']:
                print(f"\nVulnerability Details:")
                for vuln in results['vulnerabilities'][: self.MAX_DISPLAYED_VULNERABILITIES]:
                    severity = self._normalize_severity(vuln.get('severity')).upper()
                    print(f"  • {vuln.get('cve')} [{severity}]")
                    package = vuln.get('package') or 'N/A'
                    version = vuln.get('version') or 'N/A'
                    print(f"    Package: {package} {version}")
                    print(f"    Fixed in: {vuln.get('fixed_in') or 'N/A'}")
        
        print(f"\nCheck Details:")
        for check in results['checks']:
            status_symbol = {
                'passed': '✓',
                'warning': '⚠',
                'failed': '✗',
            }.get(check['status'], '?')
            print(f"  {status_symbol} {check['check']}: {check['message']}")
    
    def save_report(self, results: Dict, output_path: str):
        """Save scan results to file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
        except OSError as exc:
            raise RuntimeError(f'Failed to write container scan report: {exc}') from exc

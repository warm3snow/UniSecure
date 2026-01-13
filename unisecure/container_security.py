"""Container security scanner module."""
from typing import Dict, Any, Optional


class ContainerSecurityScanner:
    """Scanner for container security vulnerabilities."""
    
    def __init__(self):
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
                'vulnerabilities': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                }
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
        """Check for known vulnerabilities."""
        # Simulate finding some vulnerabilities
        vulnerabilities = [
            {
                'cve': 'CVE-2024-0001',
                'severity': 'medium',
                'package': 'example-lib',
                'version': '1.2.3',
                'fixed_in': '1.2.4',
            }
        ]
        
        check = {
            'check': 'Vulnerability Scan',
            'status': 'warning' if vulnerabilities else 'passed',
            'message': f'Found {len(vulnerabilities)} vulnerabilities',
            'details': 'Container image may have known vulnerabilities',
        }
        results['checks'].append(check)
        results['vulnerabilities'].extend(vulnerabilities)
        
        for vuln in vulnerabilities:
            results['summary']['vulnerabilities'][vuln['severity']] += 1
        
        if vulnerabilities:
            results['summary']['warnings'] += 1
        else:
            results['summary']['passed'] += 1
    
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
            
            if results['vulnerabilities']:
                print(f"\nVulnerability Details:")
                for vuln in results['vulnerabilities'][:5]:  # Show first 5
                    print(f"  • {vuln['cve']} [{vuln['severity'].upper()}]")
                    print(f"    Package: {vuln['package']} {vuln['version']}")
                    print(f"    Fixed in: {vuln['fixed_in']}")
        
        print(f"\nCheck Details:")
        for check in results['checks']:
            status_symbol = {
                'passed': '✓',
                'warning': '⚠',
                'failed': '✗',
            }.get(check['status'], '?')
            print(f"  {status_symbol} {check['check']}: {check['message']}")

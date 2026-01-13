"""Code security scanner module."""
import os
import re
from pathlib import Path
from typing import Dict, List, Any


class CodeSecurityScanner:
    """Scanner for code security vulnerabilities."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.patterns = {
            'sql_injection': [
                r'execute\s*\([^)]*%s',
                r'\.query\s*\([^)]*\+',
                r'SELECT.*FROM.*WHERE.*=.*\+',
            ],
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
            ],
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\([^)]*shell\s*=\s*True',
                r'eval\s*\(',
            ],
            'path_traversal': [
                r'open\s*\([^)]*\.\.[/\\]',
                r'file\s*\([^)]*\.\.[/\\]',
            ],
        }
    
    def scan(self, path: str) -> Dict[str, Any]:
        """Scan code at given path for security issues.
        
        Args:
            path: Path to code directory or file
            
        Returns:
            Dictionary containing scan results
        """
        results = {
            'path': path,
            'issues': [],
            'summary': {
                'total_files': 0,
                'total_issues': 0,
                'severity_counts': {
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                }
            }
        }
        
        path_obj = Path(path)
        
        if path_obj.is_file():
            self._scan_file(path_obj, results)
        elif path_obj.is_dir():
            for root, dirs, files in os.walk(path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', 'env']]
                
                for file in files:
                    if self._is_code_file(file):
                        file_path = Path(root) / file
                        self._scan_file(file_path, results)
                        results['summary']['total_files'] += 1
        
        results['summary']['total_issues'] = len(results['issues'])
        return results
    
    def _is_code_file(self, filename: str) -> bool:
        """Check if file is a code file."""
        code_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.go', '.rb', '.php', '.cs', '.ts', '.jsx', '.tsx'}
        return any(filename.endswith(ext) for ext in code_extensions)
    
    def _scan_file(self, file_path: Path, results: Dict):
        """Scan a single file for vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for vuln_type, patterns in self.patterns.items():
                    for pattern in patterns:
                        for line_num, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                severity = self._get_severity(vuln_type)
                                issue = {
                                    'file': str(file_path),
                                    'line': line_num,
                                    'type': vuln_type,
                                    'severity': severity,
                                    'description': self._get_description(vuln_type),
                                    'code': line.strip(),
                                }
                                results['issues'].append(issue)
                                results['summary']['severity_counts'][severity] += 1
        except (UnicodeDecodeError, PermissionError, OSError):
            # Skip files that can't be read or don't have proper permissions
            pass
    
    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type."""
        high_severity = {'sql_injection', 'command_injection'}
        medium_severity = {'hardcoded_credentials', 'path_traversal'}
        
        if vuln_type in high_severity:
            return 'high'
        elif vuln_type in medium_severity:
            return 'medium'
        return 'low'
    
    def _get_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type."""
        descriptions = {
            'sql_injection': 'Potential SQL injection vulnerability',
            'hardcoded_credentials': 'Hardcoded credentials detected',
            'command_injection': 'Potential command injection vulnerability',
            'path_traversal': 'Potential path traversal vulnerability',
        }
        return descriptions.get(vuln_type, 'Security issue detected')
    
    def print_report(self, results: Dict):
        """Print scan results to console."""
        print(f"\nCode Security Scan Results")
        print(f"{'='*60}")
        print(f"Path: {results['path']}")
        print(f"Files scanned: {results['summary']['total_files']}")
        print(f"Total issues: {results['summary']['total_issues']}")
        print(f"\nSeverity breakdown:")
        print(f"  High:   {results['summary']['severity_counts']['high']}")
        print(f"  Medium: {results['summary']['severity_counts']['medium']}")
        print(f"  Low:    {results['summary']['severity_counts']['low']}")
        
        if results['issues']:
            print(f"\nIssues found:")
            for i, issue in enumerate(results['issues'][:10], 1):  # Show first 10
                print(f"\n{i}. [{issue['severity'].upper()}] {issue['description']}")
                print(f"   File: {issue['file']}:{issue['line']}")
                print(f"   Code: {issue['code'][:80]}")
            
            if len(results['issues']) > 10:
                print(f"\n... and {len(results['issues']) - 10} more issues")
        else:
            print("\n✓ No security issues detected!")
    
    def save_report(self, results: Dict, output_path: str):
        """Save scan results to file."""
        import json
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

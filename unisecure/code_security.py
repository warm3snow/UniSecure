"""Code security scanner module."""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from xml.etree import ElementTree


class CodeSecurityScanner:
    """Scanner for code security vulnerabilities."""

    TOOL_TIMEOUT = 300
    ACCEPTABLE_TOOL_RETURNCODES = (0, 1)
    LANGUAGE_TOOLING = {
        'python': {'extensions': {'.py'}, 'tool': 'bandit'},
        'go': {'extensions': {'.go'}, 'tool': 'gosec'},
        'java': {'extensions': {'.java'}, 'tool': 'spotbugs'},
    }

    def __init__(
        self,
        tool_paths: Optional[Dict[str, Optional[str]]] = None,
        language_tooling: Optional[Dict[str, Dict[str, Any]]] = None,
        tool_timeout: int = TOOL_TIMEOUT,
    ):
        self.vulnerabilities = []
        self.tool_paths = tool_paths or {}
        self.language_tooling = language_tooling or self.LANGUAGE_TOOLING
        self.tool_timeout = tool_timeout
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
            'languages': [],
            'tools': [],
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
        languages: Set[str] = set()
        
        if path_obj.is_file():
            if self._is_code_file(path_obj.name):
                self._scan_file(path_obj, results)
                results['summary']['total_files'] = 1
                lang = self._language_from_extension(path_obj.suffix)
                if lang:
                    languages.add(lang)
        elif path_obj.is_dir():
            for root, dirs, files in os.walk(path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', 'env']]
                
                for file in files:
                    if self._is_code_file(file):
                        file_path = Path(root) / file
                        self._scan_file(file_path, results)
                        results['summary']['total_files'] += 1
                        lang = self._language_from_extension(file_path.suffix)
                        if lang:
                            languages.add(lang)
        
        results['languages'] = sorted(languages)
        results['tools'] = self._run_language_tools(path_obj, languages, results)
        results['summary']['total_issues'] = len(results['issues'])
        return results
    
    def _is_code_file(self, filename: str) -> bool:
        """Check if file is a code file."""
        code_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.go', '.rb', '.php', '.cs', '.ts', '.jsx', '.tsx'}
        return any(filename.endswith(ext) for ext in code_extensions)
    
    def _language_from_extension(self, extension: str) -> Optional[str]:
        """Map file extension to supported language."""
        for language, config in self.language_tooling.items():
            if extension in config['extensions']:
                return language
        return None
    
    def _resolve_tool_path(self, language: str, tool_name: Optional[str]) -> Optional[str]:
        """Resolve and validate executable path for a language tool."""
        override = self.tool_paths.get(language)
        candidate = override if override is not None else (shutil.which(tool_name) if tool_name else None)
        if not candidate:
            return None
        
        resolved = Path(candidate).expanduser()
        if not resolved.is_absolute():
            resolved = Path.cwd() / resolved
        
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
        return None
    
    def _run_language_tools(self, path_obj: Path, languages: Set[str], results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run external open-source scanners for detected languages."""
        if not languages:
            return []
        
        target_path = path_obj
        tool_reports: List[Dict[str, Any]] = []
        
        for language in sorted(languages):
            report = self._run_language_tool(language, target_path)
            tool_reports.append(report)
            for issue in report.get('issues', []):
                issue['severity'] = self._normalize_severity(issue.get('severity'))
                results['issues'].append(issue)
                results['summary']['severity_counts'][issue['severity']] += 1
        
        return tool_reports
    
    def _run_language_tool(self, language: str, target_path: Path) -> Dict[str, Any]:
        """Execute language-specific open-source scanner."""
        tool_name = self.language_tooling.get(language, {}).get('tool')
        tool_path = self._resolve_tool_path(language, tool_name)
        
        if language == 'java' and not self._has_java_bytecode(target_path):
            return {
                'language': language,
                'tool': tool_name,
                'status': 'skipped',
                'message': 'SpotBugs requires compiled .class or .jar files; none found.',
                'issues': [],
            }
        
        if not tool_path:
            return {
                'language': language,
                'tool': tool_name,
                'status': 'skipped',
                'message': f'{tool_name} not found on PATH; install to enable {language} security scanning.',
                'issues': [],
            }
        
        runner = {
            'python': self._run_python_tool,
            'go': self._run_go_tool,
            'java': self._run_java_tool,
        }.get(language)
        
        if not runner:
            return {
                'language': language,
                'tool': tool_name,
                'status': 'skipped',
                'message': f'No scanner configured for {language}',
                'issues': [],
            }
        
        try:
            issues = runner(target_path, tool_path)
            return {
                'language': language,
                'tool': tool_name,
                'status': 'succeeded',
                'message': f'Completed scan with {tool_name}',
                'issues': issues,
            }
        except RuntimeError as exc:
            return {
                'language': language,
                'tool': tool_name,
                'status': 'failed',
                'message': str(exc),
                'issues': [],
            }
    
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

    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity strings to standard buckets."""
        normalized = (severity or '').lower()
        if normalized in {'high', 'medium', 'low'}:
            return normalized
        return 'low'
    
    def _has_java_bytecode(self, target_path: Path) -> bool:
        """Check if path contains Java bytecode needed for SpotBugs."""
        if target_path.is_file():
            return target_path.suffix in {'.class', '.jar'}
        
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', 'env']]
            if any(Path(root, f).suffix in {'.class', '.jar'} for f in files):
                return True
        return False
    
    def _run_python_tool(self, target_path: Path, tool_path: str) -> List[Dict[str, Any]]:
        """Run Bandit for Python security scanning."""
        cmd = [
            tool_path,
            '-r',
            str(target_path),
            '-f',
            'json',
            '-q',
        ]
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=self.tool_timeout,
            shell=False,
        )
        if completed.returncode not in self.ACCEPTABLE_TOOL_RETURNCODES:
            error_detail = completed.stderr.strip() or 'Bandit scan failed'
            raise RuntimeError(f'{error_detail} (exit code {completed.returncode})')
        if not completed.stdout.strip():
            return []
        
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Unable to parse Bandit output: {exc}') from exc
        
        issues = []
        for finding in data.get('results', []):
            issues.append(
                {
                    'file': finding.get('filename'),
                    'line': finding.get('line_number'),
                    'type': finding.get('test_id') or 'bandit_issue',
                    'severity': self._normalize_severity(finding.get('issue_severity')),
                    'description': finding.get('issue_text'),
                    'code': finding.get('code') or '',
                }
            )
        return issues
    
    def _run_go_tool(self, target_path: Path, tool_path: str) -> List[Dict[str, Any]]:
        """Run Gosec for Golang security scanning."""
        scan_root = target_path if target_path.is_dir() else target_path.parent
        if not scan_root.exists():
            raise RuntimeError('Invalid Go scan target')
        path_arg = './...'
        cmd = [
            tool_path,
            '-fmt=json',
            '-quiet',
            path_arg,
        ]
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=self.tool_timeout,
            cwd=str(scan_root),
            shell=False,
        )
        if completed.returncode not in self.ACCEPTABLE_TOOL_RETURNCODES:
            error_detail = completed.stderr.strip() or 'Gosec scan failed'
            raise RuntimeError(f'{error_detail} (exit code {completed.returncode})')
        if not completed.stdout.strip():
            return []
        
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Unable to parse Gosec output: {exc}') from exc
        
        issues = []
        for finding in data.get('Issues', []):
            issues.append(
                {
                    'file': finding.get('file'),
                    'line': finding.get('line'),
                    'type': finding.get('rule_id') or 'gosec_issue',
                    'severity': self._normalize_severity(finding.get('severity')),
                    'description': finding.get('details'),
                    'code': '',
                }
            )
        return issues
    
    def _run_java_tool(self, target_path: Path, tool_path: str) -> List[Dict[str, Any]]:
        """Run SpotBugs for Java security scanning."""
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp_file:
            output_path = Path(tmp_file.name)
        cmd = [
            tool_path,
            '-textui',
            '-xml:withMessages',
            '-output',
            str(output_path),
            '-quiet',
            str(target_path),
        ]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.tool_timeout,
                shell=False,
            )
            if completed.returncode not in self.ACCEPTABLE_TOOL_RETURNCODES:
                error_detail = completed.stderr.strip() or 'SpotBugs scan failed'
                raise RuntimeError(f'{error_detail} (exit code {completed.returncode})')
            try:
                xml_output = output_path.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError) as exc:
                raise RuntimeError(f'Unable to read SpotBugs output: {exc}') from exc
            if not xml_output.strip():
                return []
            return self._parse_spotbugs_xml(xml_output)
        finally:
            output_path.unlink(missing_ok=True)
    
    def _parse_spotbugs_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse SpotBugs XML output."""
        try:
            root = ElementTree.fromstring(xml_content)
        except ElementTree.ParseError as exc:
            raise RuntimeError(f'Unable to parse SpotBugs output: {exc}') from exc
        
        issues: List[Dict[str, Any]] = []
        for bug in root.findall('.//BugInstance'):
            source = bug.find('.//SourceLine')
            severity = self._spotbugs_priority_to_severity(bug.get('priority'))
            source_path = None
            source_line = None
            if source is not None:
                source_path = source.get('sourcepath') or source.get('sourcefile')
                source_line = source.get('start')
            line_number = None
            if source_line:
                try:
                    line_number = int(source_line)
                except (TypeError, ValueError):
                    line_number = None
            issues.append(
                {
                    'file': source_path or 'unknown',
                    'line': line_number,
                    'type': bug.get('type') or 'spotbugs_issue',
                    'severity': severity,
                    'description': (bug.findtext('LongMessage') or bug.findtext('ShortMessage') or 'SpotBugs finding'),
                    'code': '',
                }
            )
        return issues
    
    def _spotbugs_priority_to_severity(self, priority: Optional[str]) -> str:
        """Map SpotBugs priority values to severity buckets."""
        mapping = {
            '1': 'high',
            '2': 'medium',
            '3': 'low',
        }
        return mapping.get(priority or '', 'medium')
    
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
        
        if results.get('tools'):
            print(f"\nExternal scanners:")
            for tool in results['tools']:
                tool_name = tool.get('tool') or 'scanner'
                print(f"  {tool_name} ({tool.get('language')}): {tool.get('status')} - {tool.get('message')}")
        
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
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

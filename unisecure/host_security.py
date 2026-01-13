"""Host security scanner module."""
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
from typing import Dict, Any, List, Optional


class HostSecurityScanner:
    """Scanner for host system security."""

    DEFAULT_COMMAND_TIMEOUT = 5
    MAX_DISPLAYED_PORTS = 8
    GROUP_OTHER_WRITE_MASK = 0o022
    COMMON_REMOTE_PORTS = (22, 80, 443, 3389, 3306, 5432, 8080, 8443)

    def __init__(self, command_timeout: int = DEFAULT_COMMAND_TIMEOUT):
        self.checks = [
            'os_version',
            'firewall_status',
            'open_ports',
            'user_accounts',
            'file_permissions',
            'security_updates',
        ]
        self.command_timeout = command_timeout
    
    def scan(self, quick_mode: bool = False, host: str = 'localhost') -> Dict[str, Any]:
        """Scan host system for security issues.
        
        Args:
            quick_mode: If True, perform quick scan only
            host: Target host to scan (local host supported by default)
            
        Returns:
            Dictionary containing scan results
        """
        is_local = self._is_local_host(host)
        results = {
            'target': host,
            'hostname': platform.node() if is_local else host,
            'os': platform.system() if is_local else 'Unknown (remote host)',
            'os_version': platform.version() if is_local else 'Unknown',
            'quick_mode': quick_mode,
            'checks': [],
            'summary': {
                'total_checks': len(self.checks) if not quick_mode else 3,
                'passed': 0,
                'warnings': 0,
                'failed': 0,
            }
        }
        
        if not is_local:
            results['summary']['total_checks'] += 1
            self._check_target_host(results, host)

        if is_local:
            self._check_os_version(results)
            self._check_firewall(results)
            self._check_open_ports(results)
            
            if not quick_mode:
                self._check_user_accounts(results)
                self._check_file_permissions(results)
                self._check_security_updates(results)
        else:
            self._check_os_version(results, host=host, is_local=False)
            self._check_firewall(results, host=host, is_local=False)
            self._check_open_ports(results, host=host, is_local=False)
            
            if not quick_mode:
                self._check_user_accounts(results, remote=True, host=host)
                self._check_file_permissions(results, remote=True, host=host)
                self._check_security_updates(results, remote=True, host=host)
        
        return results
    
    def _check_os_version(self, results: Dict, host: str = 'localhost', is_local: bool = True):
        """Check OS version."""
        if is_local:
            check = {
                'check': 'Operating System',
                'status': 'passed',
                'details': f"{results['os']} - {results['os_version']}",
                'message': 'Operating system identified',
            }
        else:
            remote_guess = self._guess_remote_os(host)
            if remote_guess:
                check = {
                    'check': 'Operating System',
                    'status': 'passed',
                    'details': remote_guess,
                    'message': 'Remote OS fingerprint collected',
                }
            else:
                check = {
                    'check': 'Operating System',
                    'status': 'warning',
                    'details': f'Remote OS for {host} could not be identified without agent access',
                    'message': 'Remote operating system could not be determined',
                }
        self._record_check(results, check)
    
    def _check_firewall(self, results: Dict, host: str = 'localhost', is_local: bool = True):
        """Check firewall status."""
        check = {
            'check': 'Firewall Status',
            'status': 'warning',
            'details': 'Unable to determine firewall status',
            'message': 'Firewall status should be verified manually',
        }
        
        if not is_local:
            check['details'] = f'Remote firewall status for {host} could not be determined'
            check['message'] = 'Verify firewall configuration on the remote host'
            self._record_check(results, check)
            return

        # Try to check firewall on different systems
        try:
            if results['os'] == 'Linux':
                firewall_commands = [
                    (['ufw', 'status'], 'ufw'),
                    (['firewall-cmd', '--state'], 'firewalld'),
                    (['iptables', '-L'], 'iptables'),
                ]

                for command, name in firewall_commands:
                    if not self._command_exists(command[0]):
                        continue
                    try:
                        result = self._run_command(command)
                    except subprocess.TimeoutExpired:
                        continue

                    if result.returncode == 0 and result.stdout is not None:
                        output = result.stdout.lower()
                        if name == 'ufw' and 'active' in output:
                            check['status'] = 'passed'
                            check['message'] = 'UFW firewall is active'
                            check['details'] = 'Detected active UFW ruleset'
                            break
                        if name == 'firewalld' and 'running' in output:
                            check['status'] = 'passed'
                            check['message'] = 'Firewalld is running'
                            check['details'] = 'Detected running firewalld service'
                            break
                        if name == 'iptables':
                            check['status'] = 'passed'
                            check['message'] = 'iptables ruleset detected'
                            check['details'] = 'iptables command available; validate rules manually'
                            break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # If command fails or times out, keep default warning status
            pass
        
        self._record_check(results, check)
    
    def _check_open_ports(self, results: Dict, host: str = 'localhost', is_local: bool = True):
        """Check for open ports."""
        ports = self._collect_listening_ports() if is_local else self._scan_remote_ports(host)
        status = 'warning' if ports else 'passed'
        message = f"Detected {len(ports)} listening services" if ports else 'No listening services detected'

        displayed_ports = (
            ', '.join(ports[: self.MAX_DISPLAYED_PORTS]) if ports else 'No open ports detected on common ports'
        )
        details = f"Listening ports: {displayed_ports}"

        check = {
            'check': 'Open Ports',
            'status': status,
            'details': details,
            'message': message,
        }
        self._record_check(results, check)
    
    def _check_user_accounts(self, results: Dict, remote: bool = False, host: str = 'localhost'):
        """Check user accounts configuration."""
        if remote:
            check = {
                'check': 'User Accounts',
                'status': 'warning',
                'details': f'Remote account enumeration for {host} is not available',
                'message': 'Review remote user accounts via SSH or configuration management',
            }
            self._record_check(results, check)
            return

        try:
            users = pwd.getpwall()
        except Exception:
            check = {
                'check': 'User Accounts',
                'status': 'warning',
                'details': 'Unable to inspect system accounts',
                'message': 'Review /etc/passwd manually for unexpected accounts',
            }
            self._record_check(results, check)
            return

        interactive_users = [
            user.pw_name
            for user in users
            if user.pw_shell not in ('/usr/sbin/nologin', '/bin/false', '/bin/nologin')
        ]
        privileged_users = [user.pw_name for user in users if user.pw_uid == 0 and user.pw_name != 'root']

        status = 'passed'
        message = f'{len(interactive_users)} interactive account(s) detected'
        details = 'Accounts: ' + ', '.join(sorted(interactive_users[: self.MAX_DISPLAYED_PORTS])) if interactive_users else 'No interactive accounts found'

        if privileged_users:
            status = 'warning'
            message = f"Additional privileged accounts detected: {', '.join(privileged_users)}"
            details = details + '; validate sudo/root access'

        check = {
            'check': 'User Accounts',
            'status': status,
            'details': details,
            'message': message,
        }
        self._record_check(results, check)
    
    def _check_file_permissions(self, results: Dict, remote: bool = False, host: str = 'localhost'):
        """Check critical file permissions."""
        if remote:
            check = {
                'check': 'File Permissions',
                'status': 'warning',
                'details': f'Permission checks for {host} require local access',
                'message': 'Validate critical system file permissions on the remote host',
            }
            self._record_check(results, check)
            return

        sensitive_files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
        }
        issues: List[str] = []

        for path, expected_mode in sensitive_files.items():
            if not os.path.exists(path):
                continue
            try:
                mode = stat.S_IMODE(os.stat(path).st_mode)
            except OSError:
                continue

            perms = mode & 0o777
            allowed_bits = expected_mode & 0o777
            extra_bits = perms & ~allowed_bits

            # Flag files that allow group/other write permissions
            if perms & self.GROUP_OTHER_WRITE_MASK:
                issues.append(f'{path} permissions too permissive ({oct(perms)})')

            # Identify any permission bits beyond the expected baseline
            other_excess = extra_bits & ~self.GROUP_OTHER_WRITE_MASK
            if other_excess:
                issues.append(f'{path} permissions exceed recommended {oct(expected_mode)} (found {oct(perms)})')

        status = 'warning' if issues else 'passed'
        details = '; '.join(issues) if issues else 'Core system file permissions appear hardened'
        message = 'Validate critical system file permissions'

        check = {
            'check': 'File Permissions',
            'status': status,
            'details': details,
            'message': message,
        }
        self._record_check(results, check)
    
    def _check_security_updates(self, results: Dict, remote: bool = False, host: str = 'localhost'):
        """Check for available security updates."""
        check = {
            'check': 'Security Updates',
            'status': 'warning',
            'details': 'Security update status',
            'message': 'Security updates should be checked and applied regularly',
        }

        if remote:
            check['details'] = f'Update status for {host} requires remote package manager access'
            check['message'] = 'Validate security updates directly on the remote host'
            self._record_check(results, check)
            return

        if results.get('os') != 'Linux':
            self._record_check(results, check)
            return

        package_manager = self._detect_package_manager()
        manager_label = package_manager or 'package manager'
        if not package_manager:
            check['message'] = 'No supported package manager detected'
            check['details'] = 'Install and configure package management for regular updates'
            self._record_check(results, check)
            return

        try:
            if package_manager == 'apt-get':
                completed = self._run_command(['apt-get', '-s', 'upgrade'])
                updates = self._parse_upgrade_output(completed.stdout or '')
                if completed.returncode == 0 and updates == 0:
                    check['status'] = 'passed'
                    check['message'] = 'System packages are up to date'
                    check['details'] = 'APT reports no pending upgrades'
                elif updates > 0:
                    check['status'] = 'warning'
                    check['message'] = f'{updates} package upgrades available via APT'
                    check['details'] = 'Run apt-get update && apt-get upgrade to apply patches'
                else:
                    check['status'] = 'warning'
                    check['message'] = 'Unable to determine updates via APT'
                    check['details'] = 'APT returned non-zero status; rerun update check manually'
            elif package_manager in ('yum', 'dnf'):
                completed = self._run_command([package_manager, '-q', 'check-update'])
                if completed.returncode == 100:
                    check['status'] = 'warning'
                    check['message'] = 'Package updates available'
                    check['details'] = (
                        f'{manager_label} reports pending updates (command may contact remote repositories)'
                    )
                elif completed.returncode == 0:
                    check['status'] = 'passed'
                    check['message'] = 'System packages are up to date'
                    check['details'] = (
                        f'{manager_label} did not report pending updates (may require network access)'
                    )
                else:
                    check['status'] = 'warning'
                    check['message'] = f'Unable to determine updates via {manager_label}'
        except subprocess.TimeoutExpired:
            check['status'] = 'warning'
            check['message'] = 'Package manager check timed out'
            check['details'] = f'{manager_label} did not respond within timeout'
        except OSError as exc:
            check['status'] = 'warning'
            check['message'] = f'Failed to run {manager_label}'
            check['details'] = f'{manager_label} error: {exc}'

        self._record_check(results, check)
    
    def print_report(self, results: Dict):
        """Print scan results to console."""
        print(f"\nHost Security Scan Results")
        print(f"{'='*60}")
        print(f"Hostname: {results['hostname']}")
        print(f"OS: {results['os']} {results['os_version']}")
        print(f"Scan mode: {'Quick' if results['quick_mode'] else 'Full'}")
        print(f"\nSummary:")
        print(f"  Total checks: {results['summary']['total_checks']}")
        print(f"  Passed:       {results['summary']['passed']}")
        print(f"  Warnings:     {results['summary']['warnings']}")
        print(f"  Failed:       {results['summary']['failed']}")
        
        print(f"\nCheck Details:")
        for check in results['checks']:
            status_symbol = {
                'passed': '✓',
                'warning': '⚠',
                'failed': '✗',
            }.get(check['status'], '?')
            print(f"  {status_symbol} {check['check']}")
            print(f"     {check['message']}")
            if check.get('details'):
                print(f"     Details: {check['details']}")

    def _collect_listening_ports(self) -> List[str]:
        """Collect listening TCP/UDP ports using common open-source tools."""
        commands = [
            (['ss', '-tuln'], 'ss'),
            (['netstat', '-tuln'], 'netstat'),
        ]

        for command, _ in commands:
            if not self._command_exists(command[0]):
                continue
            try:
                result = self._run_command(command)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0 and result.stdout:
                ports = self._parse_listening_ports(result.stdout)
                if ports:
                    return ports
        return []

    def _parse_listening_ports(self, output: str) -> List[str]:
        """Parse listening ports from ss/netstat output."""
        ports = set()
        for line in output.splitlines():
            if line.lower().startswith(('netid', 'proto', 'state')):
                continue
            parts = line.split()
            if not parts:
                continue
            protocol = parts[0].lower()
            if protocol.startswith('udp'):
                proto = 'udp'
            elif protocol.startswith('tcp'):
                proto = 'tcp'
            else:
                continue
            port: Optional[str] = None
            for token in reversed(parts):
                if ':' in token:
                    candidate = token.rsplit(':', 1)[-1]
                    if candidate.isdigit():
                        port = candidate
                        break
            if port:
                ports.add(f'{port}/{proto}')
        return sorted(ports)

    def _scan_remote_ports(self, host: str) -> List[str]:
        """Perform a lightweight TCP scan for common ports on a remote host."""
        ports: List[str] = []
        timeout = min(1.0, max(0.1, self.command_timeout / 5))
        for port in self.COMMON_REMOTE_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                try:
                    if sock.connect_ex((host, port)) == 0:
                        ports.append(self._format_port(port))
                except OSError:
                    continue
        return ports

    def _format_port(self, port: int) -> str:
        """Return a descriptive port string including service name if available."""
        try:
            service = socket.getservbyport(port, 'tcp')
        except OSError:
            service = None
        return f"{port}/tcp" + (f" ({service})" if service else "")

    def _guess_remote_os(self, host: str) -> Optional[str]:
        """Attempt basic remote OS fingerprinting using ping TTL heuristic."""
        if not self._command_exists('ping'):
            return None

        try:
            completed = self._run_command(['ping', '-c', '1', '-W', str(max(1, self.command_timeout)), host])
        except subprocess.TimeoutExpired:
            return None
        if completed.returncode != 0 or not completed.stdout:
            return None

        match = re.search(r'ttl[=|:](\d+)', completed.stdout, re.IGNORECASE)
        if not match:
            return None

        ttl = int(match.group(1))
        if ttl >= 200:
            return f'Network device or BSD-like (TTL {ttl})'
        if ttl >= 128:
            return f'Windows-like (TTL {ttl})'
        if ttl >= 64:
            return f'Linux/Unix-like (TTL {ttl})'
        return f'Unknown OS (TTL {ttl})'

    def _detect_package_manager(self) -> Optional[str]:
        """Detect available package manager."""
        for candidate in ('apt-get', 'dnf', 'yum'):
            if self._command_exists(candidate):
                return candidate
        return None

    def _parse_upgrade_output(self, output: str) -> int:
        """Parse upgrade simulation output for number of available updates."""
        match = re.search(r'(\d+)\s+upgraded', output)
        if match:
            return int(match.group(1))
        match = re.search(r'(\d+)\s+packages?\s+can\s+be\s+upgraded', output)
        if match:
            return int(match.group(1))
        return 0

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists on PATH."""
        return shutil.which(command) is not None

    def _run_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a system command with sane defaults."""
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
            check=False,
            shell=False,
        )

    def _record_check(self, results: Dict[str, Any], check: Dict[str, Any]):
        """Append a check result and update summary counts."""
        results['checks'].append(check)
        status = check.get('status')
        if status == 'passed':
            results['summary']['passed'] += 1
        elif status == 'warning':
            results['summary']['warnings'] += 1
        elif status == 'failed':
            results['summary']['failed'] += 1

    def _check_target_host(self, results: Dict[str, Any], host: str):
        """Verify that the remote host appears reachable."""
        reachable = self._probe_host(host)
        check = {
            'check': 'Target Host',
            'status': 'passed' if reachable else 'failed',
            'details': f'Host {host} resolved successfully' if reachable else f'Unable to reach {host}',
            'message': 'Remote host appears reachable' if reachable else 'Remote host is unreachable',
        }
        self._record_check(results, check)

    def _probe_host(self, host: str) -> bool:
        """Lightweight reachability probe for remote hosts."""
        try:
            socket.gethostbyname(host)
        except OSError:
            return False

        for port in (22, 443, 80):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(min(1.0, max(0.1, self.command_timeout / 5)))
                try:
                    if sock.connect_ex((host, port)) == 0:
                        return True
                except OSError:
                    continue
        return False

    def _is_local_host(self, host: str) -> bool:
        """Determine if the requested host represents the local machine."""
        return host in ('localhost', '127.0.0.1', '::1')

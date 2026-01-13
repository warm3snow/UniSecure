# UniSecure

**UniSecure** is all-in-one platform for end-to-end IT security — code, app, host, and container.

## Overview

UniSecure provides comprehensive security scanning and analysis across four critical domains:

- **Code Security**: Static analysis to detect vulnerabilities in source code
- **Application Security**: Runtime security checks for web applications and services
- **Host Security**: System-level security assessment for servers and workstations
- **Container Security**: Container image scanning for vulnerabilities and misconfigurations

## Features

### Code Security Scanner
- Detects SQL injection vulnerabilities
- Identifies hardcoded credentials
- Finds command injection risks
- Detects path traversal vulnerabilities
- Supports multiple programming languages (Python, JavaScript, Java, C++, Go, Ruby, PHP, C#, TypeScript)

### Application Security Scanner
- SSL/TLS configuration validation
- Security headers analysis
- Authentication mechanism checks
- Authorization control verification
- Input validation review

### Host Security Scanner
- Operating system version verification
- Firewall status checking
- Open ports detection
- User account security assessment
- File permissions analysis
- Security updates monitoring

### Container Security Scanner
- Base image security analysis
- Known vulnerability detection (CVE scanning)
- Configuration security review
- Secret exposure detection
- User permission validation

> Container image vulnerability scanning leverages the Trivy CLI. Ensure `trivy` is installed and available in your PATH for real image scans.

## Installation

```bash
# Clone the repository
git clone https://github.com/warm3snow/UniSecure.git
cd UniSecure

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Command Line Interface

UniSecure provides a comprehensive CLI for all security scanning operations:

```bash
# Display help
unisecure --help

# Scan code for security vulnerabilities
unisecure scan-code /path/to/code

# Save code scan report to file
unisecure scan-code /path/to/code --output report.json

# Scan application
unisecure scan-app https://example.com

# Scan application with specific ports
unisecure scan-app example.com --port 80 --port 443

# Scan host system (quick mode)
unisecure scan-host --quick

# Scan host system (full scan)
unisecure scan-host

# Scan container image
unisecure scan-container nginx:latest

# Scan container from specific registry
unisecure scan-container myapp:1.0 --registry registry.example.com

# Save container scan report (JSON)
unisecure scan-container nginx:latest --output container-report.json

# Run comprehensive scan (all security checks)
unisecure scan-all /path/to/project
```

### Python API

You can also use UniSecure programmatically:

```python
from unisecure.code_security import CodeSecurityScanner
from unisecure.app_security import AppSecurityScanner
from unisecure.host_security import HostSecurityScanner
from unisecure.container_security import ContainerSecurityScanner

# Code security scanning
code_scanner = CodeSecurityScanner()
results = code_scanner.scan('/path/to/code')
code_scanner.print_report(results)

# Application security scanning
app_scanner = AppSecurityScanner()
results = app_scanner.scan('https://example.com')
app_scanner.print_report(results)

# Host security scanning
host_scanner = HostSecurityScanner()
results = host_scanner.scan(quick_mode=True)
host_scanner.print_report(results)

# Container security scanning
container_scanner = ContainerSecurityScanner()
results = container_scanner.scan('nginx:latest')
container_scanner.print_report(results)
```

## Examples

See the `examples/` directory for sample projects and use cases demonstrating UniSecure's capabilities.

## Requirements

- Python 3.8 or higher
- See `requirements.txt` for Python dependencies

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Security

If you discover a security vulnerability within UniSecure, please send an email to security@unisecure.io. All security vulnerabilities will be promptly addressed.

## Support

- Documentation: [https://docs.unisecure.io](https://docs.unisecure.io)
- Issues: [https://github.com/warm3snow/UniSecure/issues](https://github.com/warm3snow/UniSecure/issues)
- Discussions: [https://github.com/warm3snow/UniSecure/discussions](https://github.com/warm3snow/UniSecure/discussions)

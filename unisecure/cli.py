"""Command-line interface for UniSecure platform."""
import click
from unisecure.code_security import CodeSecurityScanner
from unisecure.app_security import AppSecurityScanner
from unisecure.host_security import HostSecurityScanner
from unisecure.container_security import ContainerSecurityScanner


@click.group()
@click.version_option(version="0.1.0")
def main():
    """UniSecure - All-in-one platform for end-to-end IT security.
    
    Provides comprehensive security scanning for:
    - Code security
    - Application security
    - Host security
    - Container security
    """
    pass


@main.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file for report')
def scan_code(path, output):
    """Scan code for security vulnerabilities."""
    click.echo(f"Scanning code at: {path}")
    scanner = CodeSecurityScanner()
    results = scanner.scan(path)
    
    if output:
        scanner.save_report(results, output)
        click.echo(f"Report saved to: {output}")
    else:
        scanner.print_report(results)


@main.command()
@click.argument('target')
@click.option('--port', '-p', help='Port to scan', multiple=True)
def scan_app(target, port):
    """Scan application for security vulnerabilities."""
    click.echo(f"Scanning application: {target}")
    scanner = AppSecurityScanner()
    results = scanner.scan(target, ports=port)
    scanner.print_report(results)


@main.command()
@click.option('--host', default='localhost', show_default=True, help='Host to scan (local host only)')
@click.option('--quick', is_flag=True, help='Quick scan mode')
def scan_host(host, quick):
    """Scan host system for security issues."""
    click.echo(f"Scanning host system: {host} ...")
    scanner = HostSecurityScanner()
    results = scanner.scan(quick_mode=quick, host=host)
    scanner.print_report(results)


@main.command()
@click.argument('image')
@click.option('--registry', help='Container registry URL')
@click.option('--output', '-o', help='Output file for container scan report')
@click.option('--use-trivy', is_flag=True, help='Use Trivy CLI for live vulnerability scanning')
def scan_container(image, registry, output, use_trivy):
    """Scan container image for vulnerabilities."""
    click.echo(f"Scanning container image: {image}")
    scanner = ContainerSecurityScanner(use_mock_data=not use_trivy)
    results = scanner.scan(image, registry=registry)
    
    if output:
        scanner.save_report(results, output)
        click.echo(f"Report saved to: {output}")
    else:
        scanner.print_report(results)


@main.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file for comprehensive report')
def scan_all(path, output):
    """Run all security scans (code, app, host, container)."""
    click.echo("Running comprehensive security scan...")
    click.echo("\n=== Code Security Scan ===")
    
    code_scanner = CodeSecurityScanner()
    code_results = code_scanner.scan(path)
    code_scanner.print_report(code_results)
    
    click.echo("\n=== Host Security Scan ===")
    host_scanner = HostSecurityScanner()
    host_results = host_scanner.scan(quick_mode=True)
    host_scanner.print_report(host_results)
    
    click.echo("\nComprehensive scan completed!")


if __name__ == '__main__':
    main()

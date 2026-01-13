"""Example: Scanning host system with UniSecure."""

from unisecure.host_security import HostSecurityScanner


def main():
    """Scan the host system for security issues."""
    print("UniSecure Host Security Scanner - Example\n")
    
    # Create scanner instance
    scanner = HostSecurityScanner()
    
    # Perform quick scan
    print("Performing quick host security scan...\n")
    results = scanner.scan(quick_mode=True)
    
    # Print the report
    scanner.print_report(results)
    
    print("\n" + "="*60)
    print("Host scan complete!")
    print("\nTip: Run without --quick flag for a comprehensive scan")


if __name__ == '__main__':
    main()

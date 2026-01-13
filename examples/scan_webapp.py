"""Example: Scanning a web application with UniSecure."""

from unisecure.app_security import AppSecurityScanner


def main():
    """Scan a web application for security issues."""
    print("UniSecure Application Security Scanner - Example\n")
    
    # Create scanner instance
    scanner = AppSecurityScanner()
    
    # Scan example web application
    print("Scanning example.com...\n")
    results = scanner.scan('https://example.com', ports=('80', '443'))
    
    # Print the report
    scanner.print_report(results)
    
    print("\n" + "="*60)
    print("Application scan complete!")


if __name__ == '__main__':
    main()

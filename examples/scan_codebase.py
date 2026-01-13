"""Example: Scanning a codebase with UniSecure."""

from unisecure.code_security import CodeSecurityScanner


def main():
    """Scan example vulnerable code."""
    print("UniSecure Code Security Scanner - Example\n")
    
    # Create scanner instance
    scanner = CodeSecurityScanner()
    
    # Scan the vulnerable_code.py file
    print("Scanning vulnerable_code.py for security issues...\n")
    results = scanner.scan('vulnerable_code.py')
    
    # Print the report
    scanner.print_report(results)
    
    # Save results to JSON file
    print("\nSaving detailed report to scan_results.json")
    scanner.save_report(results, 'scan_results.json')
    
    print("\n" + "="*60)
    print("Scan complete! Check scan_results.json for detailed results.")


if __name__ == '__main__':
    main()

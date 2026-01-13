"""Example: Scanning container images with UniSecure."""

from unisecure.container_security import ContainerSecurityScanner


def main():
    """Scan container images for security vulnerabilities."""
    print("UniSecure Container Security Scanner - Example\n")
    
    # Create scanner instance
    scanner = ContainerSecurityScanner()
    
    # Scan a popular container image
    print("Scanning nginx:latest container image...\n")
    results = scanner.scan('nginx:latest')
    
    # Print the report
    scanner.print_report(results)
    
    print("\n" + "="*60)
    print("Container scan complete!")
    print("\nNote: This is a simulated scan. In production, this would")
    print("connect to container registries and scan actual images.")


if __name__ == '__main__':
    main()

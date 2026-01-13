#!/bin/bash
# Integration test script for UniSecure platform

echo "======================================"
echo "UniSecure Integration Test Suite"
echo "======================================"
echo ""

# Test 1: Check version
echo "Test 1: Version check"
unisecure --version
if [ $? -eq 0 ]; then
    echo "✓ Version check passed"
else
    echo "✗ Version check failed"
    exit 1
fi
echo ""

# Test 2: Code security scan
echo "Test 2: Code security scan"
unisecure scan-code examples/vulnerable_code.py > /tmp/test_code_scan.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Code security scan passed"
else
    echo "✗ Code security scan failed"
    exit 1
fi
echo ""

# Test 3: Host security scan
echo "Test 3: Host security scan"
unisecure scan-host --quick > /tmp/test_host_scan.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Host security scan passed"
else
    echo "✗ Host security scan failed"
    exit 1
fi
echo ""

# Test 4: Container security scan
echo "Test 4: Container security scan"
unisecure scan-container nginx:latest > /tmp/test_container_scan.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Container security scan passed"
else
    echo "✗ Container security scan failed"
    exit 1
fi
echo ""

# Test 5: Application security scan
echo "Test 5: Application security scan"
unisecure scan-app example.com > /tmp/test_app_scan.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Application security scan passed"
else
    echo "✗ Application security scan failed"
    exit 1
fi
echo ""

# Test 6: Comprehensive scan
echo "Test 6: Comprehensive scan"
unisecure scan-all examples/ > /tmp/test_comprehensive.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Comprehensive scan passed"
else
    echo "✗ Comprehensive scan failed"
    exit 1
fi
echo ""

# Test 7: Python API
echo "Test 7: Python API examples"
cd examples && python3 scan_codebase.py > /tmp/test_python_api.txt 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Python API test passed"
    cd ..
else
    echo "✗ Python API test failed"
    cd ..
    exit 1
fi
echo ""

echo "======================================"
echo "All tests passed successfully!"
echo "======================================"

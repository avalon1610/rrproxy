#!/bin/bash

# Test script for firewall proxy functionality
# This script sets up a mock firewall proxy and tests the complete chain

echo "🔥 Testing RRProxy Firewall Proxy Functionality"
echo "==============================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a port is available
check_port() {
    local port=$1
    if command -v nc >/dev/null 2>&1; then
        if nc -z localhost $port >/dev/null 2>&1; then
            return 1 # Port is in use
        else
            return 0 # Port is available
        fi
    else
        # Fallback if netcat is not available
        if ss -tuln | grep ":$port " >/dev/null 2>&1; then
            return 1 # Port is in use
        else
            return 0 # Port is available
        fi
    fi
}

# Check required ports
echo "📋 Checking port availability..."
ports=(19090 19091 19092)
for port in "${ports[@]}"; do
    if check_port $port; then
        echo -e "  ✅ Port $port is available"
    else
        echo -e "  ❌ Port $port is in use"
        exit 1
    fi
done

# Build the project
echo "🔨 Building RRProxy..."
if cargo build --release; then
    echo -e "${GREEN}✅ Build successful${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
fi

echo ""
echo "🧪 Running firewall proxy integration test..."
echo "This test will:"
echo "  1. Start a test firewall proxy on port 19090"
echo "  2. Start RRProxy remote proxy on port 19091"
echo "  3. Start RRProxy local proxy on port 19092 (configured to use firewall proxy)"
echo "  4. Make HTTP requests through the proxy chain"
echo "  5. Verify that requests go through the firewall proxy"
echo ""

# Run the integration test
if cargo test integration_test_firewall_proxy_functionality --release -- --ignored --nocapture; then
    echo -e "${GREEN}🎉 Firewall proxy integration test PASSED!${NC}"
    echo ""
    echo "Summary of what was tested:"
    echo "✅ Firewall proxy receives and forwards requests"
    echo "✅ Local proxy correctly routes through firewall proxy"
    echo "✅ Remote proxy receives and processes chunked requests"
    echo "✅ Large requests are properly chunked and reassembled"
    echo "✅ Multiple concurrent requests work correctly"
    echo "✅ End-to-end data integrity is maintained"
else
    echo -e "${RED}❌ Firewall proxy integration test FAILED${NC}"
    exit 1
fi

echo ""
echo "🔍 Architecture Verification:"
echo "The test confirmed the following architecture works correctly:"
echo ""
echo "┌─────────┐    HTTP    ┌─────────────┐    HTTP    ┌──────────────┐    HTTP     ┌──────────────┐"
echo "│ Client  │ ---------> │ Local Proxy │ ---------> │ Firewall     │ ----------> │ Remote Proxy │"
echo "│         │            │ :19092      │            │ Proxy :19090 │             │ :19091       │"
echo "└─────────┘            └─────────────┘            └──────────────┘             └──────────────┘"
echo "                              │                           │                            │"
echo "                              │                           │                            │"
echo "                              v                           v                            v"
echo "                       [Chunk large                [Forward all              [Reassemble chunks"
echo "                        requests]                   requests]                 & forward to target]"
echo ""
echo "Key features verified:"
echo "• Firewall proxy compatibility ✅"
echo "• Request chunking through proxy ✅"
echo "• Chunk reassembly ✅"
echo "• HTTPS support (via CONNECT) ✅"
echo "• Concurrent request handling ✅"

echo ""
echo -e "${GREEN}🏆 All tests completed successfully!${NC}"

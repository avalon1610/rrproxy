#!/bin/bash

# Example script to demonstrate RRProxy usage
# This script shows how to start both proxies and test them

echo "RRProxy Demo Script"
echo "=================="

# Function to cleanup background processes
cleanup() {
    echo "Cleaning up background processes..."
    pkill -f "rrproxy"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Build the project first
echo "Building RRProxy..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Starting Remote Proxy on port 8081..."
cargo run --release -- remote --listen-addr 127.0.0.1:8081 &
REMOTE_PID=$!
sleep 2

echo "Starting Local Proxy on port 8080..."
cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --chunk-size 1024 &
LOCAL_PID=$!
sleep 2

echo "Proxies started!"
echo "- Local Proxy: http://127.0.0.1:8080"
echo "- Remote Proxy: http://127.0.0.1:8081"
echo ""
echo "You can now test the proxy by sending requests to http://127.0.0.1:8080"
echo ""
echo "Example commands:"
echo "  curl -X GET http://127.0.0.1:8080/test"
echo "  curl -X POST http://127.0.0.1:8080/api/data -d 'test data'"
echo ""
echo "Press Ctrl+C to stop the demo"

# Wait for user interruption
wait

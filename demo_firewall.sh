#!/bin/bash
# RRProxy Firewall Proxy Demo Script
# This script demonstrates using RRProxy with a firewall proxy

echo "RRProxy Firewall Proxy Demo"
echo "============================="

echo "Building RRProxy..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo ""
echo "This demo shows how to use RRProxy with a firewall proxy."
echo ""
echo "Step 1: Starting Remote Proxy on port 8081..."
cargo run --release -- remote --listen-addr 127.0.0.1:8081 &
REMOTE_PID=$!

sleep 2

echo "Step 2: Starting Local Proxy with firewall proxy support..."
echo ""
echo "OPTION 1 - No firewall proxy (direct connection):"
echo "  cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081"
echo ""
echo "OPTION 2 - With HTTP firewall proxy:"
echo "  cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --firewall-proxy http://proxy.company.com:8080"
echo ""
echo "OPTION 3 - With SOCKS5 firewall proxy:"
echo "  cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --firewall-proxy socks5://proxy.company.com:1080"
echo ""
echo "For this demo, we'll use OPTION 1 (no firewall proxy)"
cargo run --release -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --chunk-size 1024 &
LOCAL_PID=$!

sleep 2

echo ""
echo "Proxies started!"
echo "- Local Proxy: http://127.0.0.1:8080 (receives client requests)"
echo "- Remote Proxy: http://127.0.0.1:8081 (forwards to target servers)"
echo ""
echo "To use with a firewall proxy in your environment:"
echo "1. Stop the local proxy"
echo "2. Restart with: cargo run -- local --firewall-proxy http://your-proxy:port"
echo ""
echo "Example test commands:"
echo "  curl -X GET http://127.0.0.1:8080/test"
echo "  curl -X POST http://127.0.0.1:8080/api/data -d \"large data that will be chunked\""
echo ""
echo "Architecture:"
echo "  Client -> Local Proxy -> [Firewall Proxy] -> Remote Proxy -> Target Server"
echo ""
echo "Press Enter to stop the demo..."
read

echo "Stopping proxies..."
kill $LOCAL_PID 2>/dev/null
kill $REMOTE_PID 2>/dev/null
echo "Demo stopped."

# RRProxy - Request/Response Proxy

A Rust-based HTTP/HTTPS proxy system that supports chunking large requests for transmission between local and remote components.

## Overview

RRProxy consists of two main components:

1. **Local Proxy** - Receives HTTP requests, chunks large ones, and forwards them to the remote proxy
2. **Remote Proxy** - Receives requests (chunked or single), reassembles chunked requests, and forwards to the target server

## Features

- ✅ HTTP request/response proxying
- ✅ Automatic chunking of large requests
- ✅ Request reassembly on remote side
- ✅ Configurable chunk size
- ✅ Transaction ID tracking for chunked requests
- ✅ Async/await support with Tokio
- ✅ Command-line interface
- ✅ Firewall proxy support (HTTP, HTTPS)
- ✅ Configurable logging levels (trace, debug, info, warn, error)
- ✅ File logging with daily rotation
- ✅ Structured JSON logs for production use
- ✅ Request/response timing and metrics
- ✅ Comprehensive error tracking

## Architecture

RRProxy has been restructured into a modular architecture with better separation of concerns:

### Request Flow Architecture

For HTTP requests, the architecture is as follows:
```
Client -> (HTTP) -> Local Proxy -> (HTTP) -> [Firewall Proxy] -> (HTTP) -> Remote Proxy -> (HTTP) -> Target Server
                |                                  |                              |
                v                                  v                              v
        [Chunk large                      [Forward all                   [Reassemble
         requests]                         requests]                      chunks]
```

For HTTPS requests, the architecture is as follows:
```
Client -> (HTTPS) -> Local Proxy -> (HTTP) -> [Firewall Proxy] -> (HTTP) -> Remote Proxy -> (HTTPS) -> Target Server
                |                                  |                              |
                v                                  v                              v
        [Terminate TLS,                   [Forward all                   [Reassemble chunks,
         chunk if needed]                  requests]                      forward to target]
```

### Important Note on HTTPS
Beware that HTTPS requests are tunneled via the CONNECT method, so the local proxy does not see the actual request URL or headers. 
So we need setup a HTTPS server on Local Proxy with (configurable, maybe Self-Signed) certificate to intercept HTTPS requests. then decode its content,
chunk it if it reaches the chunk size limit, and forward to Remote Proxy (which use http). 

## Usage

### Local Proxy

Start the local proxy that will receive requests and forward them:

```bash
cargo run -- local --listen-addr 127.0.0.1:8080 --remote-addr http://127.0.0.1:8081 --chunk-size 10240
```

Options:
- `--listen-addr`: Address to listen on (default: 127.0.0.1:8080)
- `--remote-addr`: Remote proxy address (default: http://127.0.0.1:8081)
- `--chunk-size`: Size of chunks in bytes (default: 10240)
- `--firewall-proxy`: Optional firewall proxy URL (e.g., http://proxy.company.com:8080)
- `--log-level`: Log level - trace, debug, info, warn, error (default: info)
- `--log-file`: Optional log file path for file logging with daily rotation

### Remote Proxy

Start the remote proxy that will reassemble and forward requests:

```bash
cargo run -- remote --listen-addr 127.0.0.1:8081
```

Options:
- `--listen-addr`: Address to listen on (default: 127.0.0.1:8081)
- `--log-level`: Log level - trace, debug, info, warn, error (default: info)
- `--log-file`: Optional log file path for file logging with daily rotation

## How It Works

### Small Requests
Requests smaller than the chunk size are forwarded as-is without modification.

### Large Requests
1. Local proxy splits the request body into chunks
2. Each chunk gets special headers:
   - `X-Transaction-Id`: Unique identifier for the request
   - `X-Chunk-Index`: Index of this chunk (0-based)
   - `X-Total-Chunks`: Total number of chunks
   - `X-Is-Last-Chunk`: Whether this is the final chunk
   - `X-Original-Url`: The original request URL
3. Remote proxy collects all chunks for a transaction
4. When the last chunk arrives, remote proxy reassembles the original request
5. Reassembled request is forwarded to the target server

## Headers Used

- `X-Transaction-Id`: UUID identifying a chunked request
- `X-Chunk-Index`: 0-based index of the chunk
- `X-Total-Chunks`: Total number of chunks expected
- `X-Is-Last-Chunk`: "true" for the final chunk, "false" otherwise
- `X-Original-Url`: Original request URL preserved during chunking

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

## Examples

### Example 1: Basic Setup
```bash
# Terminal 1: Start remote proxy
cargo run -- remote

# Terminal 2: Start local proxy
cargo run -- local

# Terminal 3: Send a request
curl -X POST http://127.0.0.1:8080/api/data -d "some data"
```

### Example 2: Custom Configuration
```bash
# Start with custom chunk size and addresses
cargo run -- local --listen-addr 0.0.0.0:3000 --remote-addr http://remote-server:8081 --chunk-size 5120
```

### Example 3: Using Firewall Proxy
```bash
# Start local proxy with firewall proxy (corporate environment)
cargo run -- local --listen-addr 127.0.0.1:8080 --remote-addr http://remote-server:8081 --firewall-proxy http://proxy.company.com:8080

# For SOCKS5 proxy
cargo run -- local --listen-addr 127.0.0.1:8080 --remote-addr http://remote-server:8081 --firewall-proxy socks5://proxy.company.com:1080

# For proxy with authentication (include username:password in URL)
cargo run -- local --listen-addr 127.0.0.1:8080 --remote-addr http://remote-server:8081 --firewall-proxy http://username:password@proxy.company.com:8080
```

### Example 4: Enhanced Logging
```bash
# Debug logging to console
cargo run -- local --log-level debug

# Production logging to file with rotation
cargo run -- local --log-level info --log-file logs/rrproxy.log

# Trace everything to both console and file
cargo run -- remote --log-level trace --log-file logs/remote.log
```

## Logging

RRProxy provides comprehensive logging with configurable levels and optional file output.

### Log Levels

- `trace`: Most verbose, includes all debug information
- `debug`: Detailed information for debugging
- `info`: General information about operations (default)
- `warn`: Warning messages
- `error`: Error messages only

### Console Logging

By default, logs are output to the console with pretty formatting:

```bash
# Default info level
cargo run -- local

# Debug level for detailed information
cargo run -- local --log-level debug

# Error level for minimal output
cargo run -- remote --log-level error
```

### File Logging

Enable file logging with daily rotation:

```bash
# Log to file with daily rotation
cargo run -- local --log-file logs/rrproxy.log

# Combined console and file logging
cargo run -- local --log-level debug --log-file logs/rrproxy.log
```

### Log File Features

- **Daily Rotation**: Log files are automatically rotated daily
- **JSON Format**: File logs are in structured JSON format for easy parsing
- **Detailed Metrics**: Includes timing, request/response sizes, transaction IDs
- **Error Tracking**: Comprehensive error logging with context

### Example Log Output

Console output (pretty format):
```
2024-08-23T10:30:15.123Z INFO rrproxy::local_proxy: Processing incoming request
    method=POST uri=http://example.com/api/data request_size=1024
```

File output (JSON format):
```json
{
  "timestamp": "2024-08-23T10:30:15.123Z",
  "level": "INFO",
  "target": "rrproxy::local_proxy",
  "fields": {
    "method": "POST",
    "uri": "http://example.com/api/data",
    "request_size": 1024,
    "duration_ms": 150,
    "status": 200,
    "result": "success"
  }
}
```

## Testing

### Unit Tests
```bash
cargo test
```

### Integration Tests

**Test basic internet connectivity through proxy:**
```bash
cargo test integration_test_real_internet_request --release -- --ignored
```

**Test large request chunking functionality:**
```bash
cargo test integration_test_large_request_chunking --release -- --ignored
```

**Test firewall proxy functionality:**
```bash
cargo test integration_test_firewall_proxy_functionality --release -- --ignored
```

**Run all integration tests:**
```bash
cargo test --release -- --ignored
```

**Test firewall proxy with automated script:**
```bash
# Linux/macOS
./scripts/test_firewall_proxy.sh

# Windows
scripts\test_firewall_proxy.bat
```

The firewall proxy test verifies:
- Test firewall proxy receives and forwards requests correctly
- Local proxy routes through firewall proxy as configured
- Remote proxy receives and processes chunked requests
- Large requests are properly chunked and reassembled through the proxy chain
- Multiple concurrent requests work correctly through firewall proxy
- End-to-end data integrity is maintained through the entire chain

### Manual Testing

1. Start both proxies as described in deployment
2. Configure your browser to use `127.0.0.1:8080` as HTTP/HTTPS proxy
3. Visit websites and verify they load correctly
4. Test with large POST requests to verify chunking works

### Load Testing

For performance testing, you can use tools like:
- `curl` for simple requests
- `ab` (Apache Benchmark) for load testing
- `wrk` for modern HTTP benchmarking

Example load test:
```bash
# Test with Apache Benchmark
ab -n 1000 -c 10 -X 127.0.0.1:8080 http://httpbin.org/post

# Test large requests with curl
curl -X POST -H "Content-Type: application/json" \
     --proxy http://127.0.0.1:8080 \
     --data '{"large_data":"'$(head -c 50000 /dev/zero | tr '\0' 'x')'"}' \
     https://httpbin.org/post
```

## Troubleshooting

### Common Issues

1. **Certificate Errors**
   - Ensure OpenSSL is installed
   - Run certificate generation scripts as described above
   - For testing, use `-k` flag with curl to ignore certificate errors

2. **Connection Refused**
   - Check if proxy ports are available
   - Verify firewall settings
   - Ensure both local and remote proxies are running

3. **Firewall Proxy Issues**
   - Verify firewall proxy URL format: `http://proxy.company.com:8080`
   - Test connectivity to firewall proxy directly
   - Check corporate proxy authentication requirements
   - For SOCKS5 proxies, use: `socks5://proxy.company.com:1080`
   - Enable debug logging to see proxy connection attempts

4. **Chunking Issues**
   - Enable debug logging: `--log-level debug`
   - Check transaction IDs in logs for chunk tracking
   - Verify chunk size configuration matches your network requirements

5. **Performance Issues**
   - Adjust chunk size based on network conditions
   - Use release builds for production: `cargo build --release`
   - Monitor logs for timing information
   - Check firewall proxy performance if configured

## License

This project is for proof-of-concept purposes.

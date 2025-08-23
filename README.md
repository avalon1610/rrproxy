# RRProxy - Request/Response Proxy

A Rust-based HTTP proxy system that supports chunking large requests for transmission between local and remote components.

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
- ✅ Firewall proxy support (HTTP, HTTPS, SOCKS5)

## Architecture

```
Client -> Local Proxy -> [Firewall Proxy] -> Remote Proxy -> Target Server
                |                                  |
                v                                  v
        [Chunk large                      [Reassemble
         requests]                         chunks]
```

Note: Firewall proxy is optional and can be configured with `--firewall-proxy` option.

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

### Remote Proxy

Start the remote proxy that will reassemble and forward requests:

```bash
cargo run -- remote --listen-addr 127.0.0.1:8081
```

Options:
- `--listen-addr`: Address to listen on (default: 127.0.0.1:8081)

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

## Dependencies

- `tokio`: Async runtime
- `hyper`: HTTP client/server
- `clap`: Command line parsing
- `uuid`: Transaction ID generation
- `reqwest`: HTTP client for forwarding (with proxy support)
- `anyhow`: Error handling
- `bytes`: Efficient byte buffer handling

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

## Logging

Set the `RUST_LOG` environment variable to control logging:

```bash
# Debug level
RUST_LOG=debug cargo run -- local

# Info level (default)
RUST_LOG=info cargo run -- remote
```

## License

This project is for proof-of-concept purposes.

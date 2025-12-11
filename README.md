# MiniGuard

A minimal Layer-3 VPN implementation for Windows using Wintun and UDP tunneling, secured with modern cryptography.

## Overview

MiniGuard is a lightweight VPN solution that creates secure network tunnels using:
- **Wintun Interface**: High-performance Layer-3 TUN driver for Windows
- **UDP Tunnel**: Fast, connectionless transport protocol with acknowledgment
- **X25519 Key Exchange**: Elliptic curve Diffie-Hellman for ephemeral key agreement
- **ChaCha20-Poly1305**: Authenticated encryption (AEAD) for data confidentiality and integrity
- **HKDF-SHA256**: Key derivation function for generating encryption keys from shared secrets

## Features

- ✨ Minimal design with focus on simplicity
- 🔒 Modern cryptographic primitives (X25519 + ChaCha20-Poly1305)
- 🚀 High-performance UDP-based transport with retry logic
- 🔧 Layer-3 networking for flexible routing
- 📦 Written in Rust for memory safety and performance
- 🪟 Windows-native using Wintun driver
- 🤝 Custom handshake protocol with acknowledgments

## Architecture

```
┌─────────────────┐                        ┌─────────────────┐
│     Client      │                        │     Server      │
│                 │                        │                 │
│ Wintun (10.0.0.2)│                       │                 │
│       ↕         │                        │                 │
│  1. Handshake   │ ──── PubKey ────────→  │  1. Receive     │
│     (X25519)    │ ←──── PubKey ──────────│     PubKey      │
│                 │ ──── ACK ────────────→  │                 │
│                 │                        │                 │
│  2. Derive Key  │   (Shared Secret +     │  2. Derive Key  │
│     (HKDF)      │    Salt → ChaCha Key)  │     (HKDF)      │
│                 │                        │                 │
│  3. Encrypt     │ ── Nonce+Ciphertext ──→│  3. Decrypt     │
│  (ChaCha20)     │ ←────── ACK ───────────│     (ChaCha20)  │
└─────────────────┘                        └─────────────────┘
```

## Prerequisites

- **Rust** (latest stable version)
- **Windows OS** (for Wintun support)
- **Administrator privileges** (required for network interface creation)
- **Wintun driver** (automatically loaded by the application)

## Installation

```bash
git clone https://github.com/chahat-101/MiniGuard.git
cd MiniGuard
cargo build --release
```

## Usage

### Server Mode

Run the server to listen for incoming VPN connections:

```bash
cargo run --bin server -- --listen 0.0.0.0:4000 --salt "your-secret-salt"
```

**Options:**
- `--listen, -l`: Address and port to listen on (default: `0.0.0.0:4000`)
- `--salt, -s`: Salt for key derivation (required, must match client)

**Example:**
```bash
cargo run --bin server -- -l 0.0.0.0:4000 -s "my-secure-salt-123"
```

### Client Mode

**⚠️ IMPORTANT: Administrator privileges are required to create Wintun network interfaces.**

Run as Administrator in PowerShell or Command Prompt:

```powershell
cargo run --bin client -- --data <local-data> --target <server-ip>:4000 --salt "your-secret-salt"
```

**Options:**
- `--data`: Local data identifier (application-specific)
- `--target`: Server address and port to connect to
- `--salt`: Salt for key derivation (required, must match server)

**Example:**
```powershell
cargo run --bin client -- --data "client1" --target 192.168.1.100:4000 --salt "my-secure-salt-123"
```

The client will create a Wintun adapter named "minguard" with:
- Client IP: `10.0.0.2`
- Netmask: `255.255.255.0`
- Gateway: `10.0.0.1`

After connection, you can test with:
```powershell
ping 203.0.113.10
```

## How It Works

### 1. Handshake Protocol

1. **Client → Server**: Client generates ephemeral X25519 keypair and sends public key (32 bytes)
2. **Server → Client**: Server sends its ephemeral public key (32 bytes)
3. **Client → Server**: Client sends ACK to confirm receipt

### 2. Key Derivation

Both client and server independently derive the same symmetric key:
- Compute shared secret using X25519 Diffie-Hellman
- Apply HKDF-SHA256 with the shared salt
- Derive 32-byte ChaCha20-Poly1305 key with info string `"chacha20poly1305 key"`

### 3. Packet Encryption & Transmission

**Client side:**
1. Reads IP packets from Wintun interface
2. Generates random 12-byte nonce
3. Encrypts packet with ChaCha20-Poly1305
4. Sends `[nonce || ciphertext]` to server via UDP
5. Waits for ACK with retry logic (400ms timeout)

**Server side:**
1. Receives encrypted packet
2. Extracts nonce (first 12 bytes) and ciphertext
3. Decrypts using ChaCha20-Poly1305
4. Logs decrypted packet contents
5. Sends ACK back to client

## Security

MiniGuard uses industry-standard cryptographic protocols:

- **X25519**: Curve25519-based ECDH providing ~128-bit security level
- **ChaCha20-Poly1305**: AEAD cipher providing both confidentiality and authentication
- **HKDF-SHA256**: Key derivation function for secure key generation from shared secrets
- **Ephemeral Keys**: New X25519 keypair for each connection (forward secrecy)
- **Random Nonces**: Fresh 12-byte nonce for every encrypted packet
- **Acknowledgments**: UDP reliability through custom ACK mechanism

**Security Notes:**
- Keys are ephemeral and regenerated per connection
- Salt must be kept secret and shared between client/server
- No key rotation implemented (reconnect for new keys)
- Server only logs packets, no forwarding implemented

## Configuration

### Network Settings (Client)

The client automatically configures the Wintun adapter with:
```rust
IP Address:    10.0.0.2
Netmask:       255.255.255.0
Gateway:       10.0.0.1
```

To modify these, edit the `adapter.set_network_addresses_tuple()` call in `client/main.rs`.

### Timeout Settings

Handshake and packet transmission use timeout/retry logic:
- **Handshake timeout**: 400ms between retries
- **ACK timeout**: 400ms for server ACK (client), 500ms for client ACK (server)
- Infinite retries until successful

## Project Structure

```
MiniGuard/
├── src/
│   ├── lib.rs          # Shared utilities (key generation)
│   └── utils/
│       └── mod.rs      # X25519 key generation
├── client/
│   └── main.rs         # Client implementation with Wintun
└── server/
    └── main.rs         # Server implementation
```

## Dependencies

Key dependencies include:
- `tokio` - Async runtime
- `wintun` - Windows TUN driver interface
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - AEAD encryption
- `hkdf` - Key derivation function
- `sha2` - SHA-256 hashing
- `clap` - CLI argument parsing

## Limitations

- **Windows only**: Uses Wintun driver (Windows-specific)
- **No packet forwarding**: Server only decrypts and logs packets
- **No routing**: No IP forwarding or NAT implementation
- **Single connection**: Server handles one handshake at a time
- **No reconnection**: Client must restart for new connection
- **No key rotation**: Keys valid only for single session

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source. Please check the repository for license details.

## Disclaimer

⚠️ **MiniGuard is an educational/experimental project** demonstrating VPN concepts and cryptographic protocols. It is **NOT production-ready** and lacks many features required for a secure VPN:

- No proper routing or packet forwarding
- No connection state management
- No rate limiting or DoS protection
- No authentication beyond shared salt
- No IP address management
- No comprehensive error handling

For production use, consider established VPN solutions like **WireGuard**, **OpenVPN**, or **IPsec**.

## Troubleshooting

**"Access Denied" when running client:**
- Ensure you're running as Administrator
- Right-click PowerShell/CMD and select "Run as Administrator"

**Connection timeouts:**
- Verify server is running and listening
- Check firewall rules allow UDP traffic on the specified port
- Ensure salt matches between client and server

**Wintun errors:**
- Reinstall Wintun driver if adapter creation fails
- Check Windows event logs for driver issues

## Acknowledgments

Inspired by modern VPN protocols, particularly WireGuard's minimalist design philosophy and cryptographic choices.

---

**Educational Purpose**: This implementation demonstrates Layer-3 VPN concepts, X25519 key exchange, and AEAD encryption in a minimal codebase (~300 lines total).

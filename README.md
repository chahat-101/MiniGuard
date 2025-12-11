# MiniGuard

A minimal Layer-3 VPN implementation for Windows using Wintun and UDP tunneling, secured with X25519 key exchange and ChaCha20-Poly1305 encryption.

## Overview

MiniGuard demonstrates core VPN concepts through a clean implementation using:
- **Wintun**: High-performance Layer-3 TUN driver for Windows
- **X25519**: Elliptic curve Diffie-Hellman for key exchange
- **ChaCha20-Poly1305**: AEAD cipher for authenticated encryption
- **HKDF-SHA256**: Key derivation from shared secrets
- **UDP**: Fast transport with custom ACK mechanism

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client (Windows)                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Wintun Virtual Interface                   │   │
│  │                  (10.0.0.2/24)                          │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │ IP Packets                            │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Packet Processing Layer                      │   │
│  │                                                         │   │
│  │  1. Read IP packet from Wintun                          │   │
│  │  2. Generate random 12-byte nonce                       │   │
│  │  3. Encrypt with ChaCha20-Poly1305                      │   │
│  │  4. Prepend nonce to ciphertext                         │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            X25519 Key Exchange Layer                    │   │
│  │                                                         │   │
│  │  • Generate ephemeral keypair                           │   │
│  │  • Exchange public keys                                 │   │
│  │  • Compute shared secret                                │   │
│  │  • Derive encryption key (HKDF-SHA256)                  │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              UDP Transport Layer                        │   │
│  │                                                         │   │
│  │  • Send encrypted packets over UDP                      │   │
│  │  • Retry with 400ms timeout until ACK                   │   │
│  │  • Handle acknowledgments                               │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
└─────────────────────────┼───────────────────────────────────────┘
                          │
                          │ UDP Tunnel
                          │ (Encrypted Traffic)
                          │
┌─────────────────────────┼───────────────────────────────────────┐
│                         │                  Server               │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              UDP Transport Layer                        │   │
│  │                                                         │   │
│  │  • Receive encrypted packets                            │   │
│  │  • Send ACK responses                                   │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            X25519 Key Exchange Layer                    │   │
│  │                                                         │   │
│  │  • Generate ephemeral keypair                           │   │
│  │  • Exchange public keys                                 │   │
│  │  • Compute shared secret                                │   │
│  │  • Derive encryption key (HKDF-SHA256)                  │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Packet Processing Layer                      │   │
│  │                                                         │   │
│  │  1. Extract nonce (first 12 bytes)                      │   │
│  │  2. Extract ciphertext                                  │   │
│  │  3. Decrypt with ChaCha20-Poly1305                      │   │
│  │  4. Log decrypted packet contents                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- 🔒 Modern cryptography (X25519 + ChaCha20-Poly1305 + HKDF)
- 🚀 UDP-based transport with retry logic
- 🪟 Windows-native using Wintun driver
- 🔧 Ephemeral keys for forward secrecy
- 📦 Clean Rust implementation (~300 lines)

## Prerequisites

- Rust (latest stable version)
- Windows OS
- **Administrator privileges** (required for network interface creation)

## Installation

```bash
git clone https://github.com/chahat-101/MiniGuard.git
cd MiniGuard
cargo build --release
```

## Usage

### Server Mode

Start the server to listen for incoming connections:

```bash
cargo run --bin server -- --listen 0.0.0.0:4000 --salt "your-secret-salt"
```

**Arguments:**
- `--listen, -l`: Bind address and port (default: `0.0.0.0:4000`)
- `--salt, -s`: Shared salt for key derivation (must match client)

### Client Mode

**⚠️ Administrator privileges required** to create Wintun network interfaces.

```powershell
cargo run --bin client -- --data "client1" --target 192.168.1.100:4000 --salt "your-secret-salt"
```

**Arguments:**
- `--data`: Local data identifier
- `--target`: Server address and port
- `--salt`: Shared salt for key derivation (must match server)

The client automatically creates a Wintun adapter with:
- IP Address: `10.0.0.2`
- Netmask: `255.255.255.0`
- Gateway: `10.0.0.1`

Test the connection:
```powershell
ping 203.0.113.10
```

## How It Works

### Protocol Flow

```
Client                                    Server
  │                                         │
  ├──── X25519 Public Key ─────────────────→│  1. Handshake
  │←─── X25519 Public Key ──────────────────┤ 
  ├──── ACK ───────────────────────────────→│
  │                                         │
  │     (Both derive shared key via HKDF)   │  2. Key Derivation
  │                                         │
  ├──── [Nonce || Encrypted Packet] ──────→ │  3. Data Transfer
  │←─── ACK ─────────────────────────────── ┤
```

### Step-by-Step

1. **Handshake**: Client and server exchange ephemeral X25519 public keys over UDP
2. **Key Derivation**: Both compute shared secret and derive ChaCha20 key using HKDF with the shared salt
3. **Encryption**: Client reads IP packets from Wintun, encrypts with ChaCha20-Poly1305 (random nonce per packet)
4. **Transmission**: Encrypted packets sent over UDP with retry logic until ACK received
5. **Decryption**: Server decrypts packets and logs contents (no forwarding implemented)

## Security Details

**Cryptographic Primitives:**
- **X25519**: Curve25519 ECDH providing ~128-bit security
- **ChaCha20-Poly1305**: AEAD providing both confidentiality and authenticity
- **HKDF-SHA256**: Cryptographically strong key derivation
- **Random Nonces**: 12-byte nonce generated per packet using OsRng

**Security Properties:**
- Ephemeral key exchange (new keys per connection)
- Forward secrecy enabled
- Authenticated encryption prevents tampering
- Salt-based key derivation prevents rainbow table attacks

**Note**: Salt must be kept secret and shared between client and server.

## Configuration

### Network Settings

Client automatically configures:
```
IP Address:    10.0.0.2
Netmask:       255.255.255.0
Gateway:       10.0.0.1
Adapter Name:  minguard
```

### Timeout Settings

- Handshake retry: 400ms
- ACK timeout: 400-500ms
- Retries: Infinite until success

## Limitations

⚠️ **This is an educational project** demonstrating VPN cryptography and protocols.

Current limitations:
- Windows only (Wintun driver dependency)
- No packet forwarding or routing implementation
- Server only decrypts and logs packets
- No concurrent connection handling
- No reconnection mechanism
- No key rotation (reconnect for new keys)
- No authentication beyond shared salt
- No rate limiting or DoS protection

## Dependencies

Core dependencies:
- `tokio` - Async runtime
- `wintun` - Windows TUN driver
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - AEAD encryption
- `hkdf` + `sha2` - Key derivation
- `clap` - CLI parsing

## Built With

<div align="center">

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Tokio](https://img.shields.io/badge/Tokio-000000?style=for-the-badge&logo=rust&logoColor=white)

</div>

### Special Thanks

This project is built on the shoulders of these excellent Rust crates:

**Networking & System:**
- [**tokio**](https://github.com/tokio-rs/tokio) - Asynchronous runtime for Rust
- [**wintun**](https://github.com/mullvad/wintun-rs) - Safe Rust bindings for the Wintun driver

**Cryptography:**
- [**x25519-dalek**](https://github.com/dalek-cryptography/x25519-dalek) - X25519 elliptic curve Diffie-Hellman
- [**chacha20poly1305**](https://github.com/RustCrypto/AEADs) - ChaCha20-Poly1305 AEAD cipher
- [**hkdf**](https://github.com/RustCrypto/KDFs) - HMAC-based Key Derivation Function
- [**sha2**](https://github.com/RustCrypto/hashes) - SHA-2 hash functions

**Utilities:**
- [**clap**](https://github.com/clap-rs/clap) - Command Line Argument Parser
- [**rand**](https://github.com/rust-random/rand) - Random number generation
- [**hex**](https://github.com/KokaKiwi/rust-hex) - Hexadecimal encoding/decoding

A huge thank you to all the maintainers and contributors of these crates! 🙏

## Troubleshooting

**"Access Denied" error:**
- Run client as Administrator
- Right-click PowerShell/CMD → "Run as administrator"

**Connection timeouts:**
- Verify server is running
- Check firewall allows UDP on specified port
- Ensure salt matches exactly between client and server

**Wintun adapter issues:**
- Check Windows Device Manager for adapter status
- Review Windows Event Viewer for driver errors
- Try deleting existing "minguard" adapter

## Contributing

Contributions welcome! Feel free to open issues or submit pull requests.

## License

See repository for license details.

## Disclaimer

**MiniGuard is for educational purposes only.** It demonstrates VPN concepts but lacks features needed for production use. For real-world VPN needs, use established solutions like **WireGuard**, **OpenVPN**, or **IPsec**.

## Acknowledgments

Inspired by WireGuard's minimalist design philosophy and modern cryptographic choices.

---

**Project Stats**: ~300 lines of Rust demonstrating X25519 key exchange, HKDF key derivation, and ChaCha20-Poly1305 AEAD encryption in a VPN context.

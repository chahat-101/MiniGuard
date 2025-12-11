# MiniGuard

A minimal Layer-3 VPN implementation using TUN interfaces and UDP tunneling, secured with modern cryptography.

## Overview

MiniGuard is a lightweight VPN solution that creates secure network tunnels using:
- **TUN Interface**: Layer-3 virtual network device for IP packet routing
- **UDP Tunnel**: Fast, connectionless transport protocol
- **X25519 Key Exchange**: Elliptic curve Diffie-Hellman for secure key agreement
- **ChaCha20-Poly1305**: Authenticated encryption for data confidentiality and integrity

## Features

- ✨ Minimal design with focus on simplicity
- 🔒 Modern cryptographic primitives (X25519 + ChaCha20-Poly1305)
- 🚀 High-performance UDP-based transport
- 🔧 Layer-3 networking for flexible routing
- 📦 Written in Rust for memory safety and performance

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│             │                    │             │
│ TUN Device  │                    │ TUN Device  │
│     ↕       │                    │     ↕       │
│  Encrypt    │ ←── UDP Tunnel ──→ │  Decrypt    │
│ (ChaCha20)  │   (X25519 keys)    │ (ChaCha20)  │
└─────────────┘                    └─────────────┘
```

## Prerequisites

- Rust (latest stable version)
- Root/Administrator privileges (required for TUN interface creation)
- Linux/Unix-like operating system (for TUN device support)

## Installation

```bash
git clone https://github.com/chahat-101/MiniGuard.git
cd MiniGuard
cargo build --release
```

## Usage

### Server Mode

```bash
sudo ./target/release/miniguard --mode server --port 51820
```

### Client Mode

**Note**: Root/Administrator privileges are required to create TUN interfaces.

```bash
sudo ./target/release/miniguard --mode client --server <server-ip>:51820
```

## Configuration

Configuration options can be adjusted through command-line arguments:

- `--mode`: Operation mode (server/client)
- `--port`: UDP port for tunnel (default: 51820)
- `--server`: Server address for client mode
- `--tun-ip`: TUN interface IP address
- `--tun-netmask`: TUN interface netmask

## Security

MiniGuard uses industry-standard cryptographic protocols:

- **X25519**: Curve25519-based key exchange providing ~128-bit security
- **ChaCha20-Poly1305**: AEAD cipher combining ChaCha20 stream cipher with Poly1305 MAC
- **Forward Secrecy**: Ephemeral key exchange ensures past sessions remain secure

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source. Please check the repository for license details.

## Disclaimer

MiniGuard is an educational/experimental project. For production use, consider established VPN solutions like WireGuard, OpenVPN, or IPsec.

## Acknowledgments

Inspired by modern VPN protocols, particularly WireGuard's minimalist design philosophy.

---

**Note**: This is a minimal VPN implementation for learning purposes. Always ensure proper security audits before using in production environments.

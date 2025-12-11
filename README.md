# MiniGuard

A minimal Layer-3 VPN implementation for Windows using Wintun and UDP tunneling, secured with X25519 key exchange and ChaCha20-Poly1305 encryption.

## Features

- 🔒 X25519 ephemeral key exchange + ChaCha20-Poly1305 AEAD encryption
- 🚀 UDP-based transport with acknowledgment retry logic
- 🪟 Windows-native using Wintun driver
- 📦 Written in Rust (~300 lines total)

## Architecture

```
Client (10.0.0.2)                          Server
     │                                        │
     ├─── X25519 PubKey ──────────────────→  │
     │←── X25519 PubKey ────────────────────┤
     ├─── ACK ─────────────────────────────→  │
     │                                        │
     │    (Derive shared key via HKDF)       │
     │                                        │
     ├─── [Nonce || Encrypted Packet] ─────→  │
     │←── ACK ──────────────────────────────┤
```

## Prerequisites

- Rust (latest stable)
- Windows OS
- **Administrator privileges** (required for Wintun interface)

## Installation

```bash
git clone https://github.com/chahat-101/MiniGuard.git
cd MiniGuard
cargo build --release
```

## Usage

### Server

```bash
cargo run --bin server -- --listen 0.0.0.0:4000 --salt "your-secret-salt"
```

### Client

**⚠️ Must run as Administrator**

```powershell
cargo run --bin client -- --data "client1" --target <server-ip>:4000 --salt "your-secret-salt"
```

Client creates Wintun adapter with IP `10.0.0.2/24`. Test with:
```powershell
ping 203.0.113.10
```

## How It Works

1. **Handshake**: Client and server exchange X25519 public keys
2. **Key Derivation**: Both derive symmetric key using HKDF-SHA256 with shared salt
3. **Encryption**: Client encrypts packets with ChaCha20-Poly1305 and sends via UDP
4. **Acknowledgment**: Server decrypts, logs packet, and sends ACK

## Security

- **X25519**: ~128-bit security Diffie-Hellman key exchange
- **ChaCha20-Poly1305**: AEAD cipher for confidentiality + authentication
- **HKDF-SHA256**: Secure key derivation from shared secret
- **Ephemeral keys**: New keypair per connection (forward secrecy)
- **Random nonces**: Fresh 12-byte nonce per packet

## Configuration

**Network (Client):**
- IP: `10.0.0.2`
- Netmask: `255.255.255.0`
- Gateway: `10.0.0.1`

**Timeouts:**
- Handshake/ACK: 400-500ms with infinite retries

## Limitations

⚠️ **Educational project - NOT production-ready**

- Windows only (Wintun driver)
- No packet forwarding or routing
- Server only decrypts and logs packets
- Single connection handling
- No reconnection logic
- No key rotation

## Troubleshooting

- **Access Denied**: Run client as Administrator
- **Connection timeout**: Check firewall, verify salt matches
- **Wintun errors**: Check Windows event logs

## Dependencies

`tokio`, `wintun`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `clap`

## Disclaimer

This is an educational implementation demonstrating VPN cryptographic concepts. For production use, consider **WireGuard**, **OpenVPN**, or **IPsec**.

---

**License**: Check repository for details  
**Contributing**: Issues and PRs welcome!

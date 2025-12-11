use MiniGuard::utils::generate_key;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use clap::Parser;
use sha2::Sha256;
use hkdf::Hkdf;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use x25519_dalek::PublicKey;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4000")]
    listen: String,

    #[arg(short, long)]
    salt: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let listen_addr: String = args.listen.parse().expect("invalid addr");
    println!("[server] listening on {}", listen_addr);

    let socket = UdpSocket::bind(listen_addr).await?;
    let salt = args.salt;

    // Server's own X25519 keypair
    let (secret_key, public_key) = generate_key();
    println!(
        "[server] server public key = {}",
        hex::encode(public_key.as_bytes())
    );

    let mut buf = [0u8; 2048];

    loop {
        // --- RECEIVE CLIENT PUBLIC KEY ---
        let (len, addr) = socket.recv_from(&mut buf).await?;

        if len != 32 {
            eprintln!(
                "[server] expected 32-byte client pubkey from {}, got {} bytes",
                addr, len
            );
            continue;
        }

        println!("[server] handshake start from {}", addr);

        // Convert 32-byte slice → [u8; 32]
        let client_pub_bytes: [u8; 32] =
            buf[..32].try_into().expect("slice with incorrect length");

        let client_pub = PublicKey::from(client_pub_bytes);

        // Send server public key back
        socket.send_to(public_key.as_bytes(), addr).await?;

        // --- WAIT FOR ACK ---
        let mut ack = [0u8; 3];
        let recv = timeout(Duration::from_millis(500), socket.recv_from(&mut ack)).await;

        match recv {
            Ok(Ok((3, a))) if a == addr && &ack == b"ACK" => {
                println!("[server] handshake complete with {}", addr);
            }
            _ => {
                eprintln!("[server] invalid or missing ACK from {}", addr);
                continue;
            }
        }

        // --- KEY DERIVATION ---
        let shared = secret_key.diffie_hellman(&client_pub);

        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared.as_bytes());

        let mut key_bytes = [0u8; 32];

        hk.expand(b"chacha20poly1305 key", &mut key_bytes)
            .map_err(|_| "HKDF expand error")?;

        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        // --- RECEIVE ENCRYPTED PACKET ---
        let (enc_len, enc_addr) = socket.recv_from(&mut buf).await?;

        if enc_addr != addr || enc_len <= 12 {
            eprintln!("[server] invalid encrypted packet from {}", enc_addr);
            continue;
        }

        let nonce = Nonce::from_slice(&buf[..12]);
        let ciphertext = &buf[12..enc_len];

        // --- DECRYPT ---
        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                println!(
                    "[server] decrypted {} bytes from {}",
                    plaintext.len(),
                    addr
                );

                println!(
                    "[server] first bytes (hex): {}",
                    hex::encode(&plaintext[..plaintext.len().min(32)])
                );

                socket.send_to(b"ACK", addr).await?;
            }
            Err(e) => {
                eprintln!("[server] decrypt failed from {}: {e}", addr);
            }
        }
    }
}

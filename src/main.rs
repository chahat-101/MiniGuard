use MiniGuard::utils::generate_key;

use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tokio::task;

use clap::Parser;

use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use hkdf::Hkdf;
use sha2::Sha256;

use rand::RngCore;
use wintun;
use x25519_dalek::PublicKey;

#[derive(Parser)]
struct Args {
    data: String,
    target: String,
    salt: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let target_addr: SocketAddr = args.target.parse()?;
    let salt = args.salt.as_bytes().to_vec();

    // Load Wintun
    let wintun_lib = unsafe { wintun::load()? };

    let adapter = match wintun::Adapter::open(&wintun_lib, "minguard") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun_lib, "minguard", "Wintun", None)?,
    };

    adapter.set_network_addresses_tuple(
        IpAddr::V4("10.0.0.2".parse().unwrap()),
        IpAddr::V4("255.255.255.0".parse().unwrap()),
        Some(IpAddr::V4("10.0.0.1".parse().unwrap())),
    )?;

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    println!("[client] Wintun session started");

    // Spawn Wintun → encrypted UDP forwarding
    {
        let session_rx = session.clone();
        let socket_tx = socket.clone();
        let target_clone = target_addr.clone();
        let salt_clone = salt.clone();

        tokio::spawn(async move {
            loop {
                let packet = match task::spawn_blocking({
                    let session_rx = session_rx.clone();
                    move || session_rx.receive_blocking()
                })
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        eprintln!("[client] wintun error: {e:?}");
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[client] spawn_blocking error: {e:?}");
                        continue;
                    }
                };

                let ip_packet = packet.bytes();

                if let Err(e) = send_encrypted_packet(
                    ip_packet,
                    &socket_tx,
                    &target_clone,
                    &salt_clone,
                )
                .await
                {
                    eprintln!("[client] error sending packet: {e}");
                }
            }
        });
    }

    println!("\n[client] tunnel running.");
    println!("[client] Try:\n  ping 203.0.113.10\n");

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn send_encrypted_packet(
    packet: &[u8],
    socket: &UdpSocket,
    target: &SocketAddr,
    salt: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {

    let (secret_key, public_key) = generate_key();

    let mut server_pub = [0u8; 32];

    // ---- HANDSHAKE ----
    loop {
        socket.send_to(public_key.as_bytes(), target).await?;
        let recv = timeout(Duration::from_millis(400), socket.recv_from(&mut server_pub)).await;

        if let Ok(Ok((32, addr))) = recv {
            if addr == *target {
                socket.send_to(b"ACK", target).await?;
                break;
            }
        }
    }

    // ---- SHARED SECRET ----
    let server_public = PublicKey::from(<[u8; 32]>::try_from(&server_pub[..])?);
    let shared = secret_key.diffie_hellman(&server_public);

    let hk = Hkdf::<Sha256>::new(Some(salt), shared.as_bytes());

    let mut key_bytes = [0u8; 32];
    hk.expand(b"chacha20poly1305 key", &mut key_bytes)
        .map_err(|_| "HKDF expand failed")?;

    let key = Key::from_slice(&key_bytes);

    // ---- ENCRYPT ----
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let cipher_text = cipher
        .encrypt(nonce, packet)
        .map_err(|_| "AEAD encryption failed")?;

    let mut out = Vec::with_capacity(12 + cipher_text.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&cipher_text);

    let mut ack = [0u8; 3];

    // ---- SEND ENCRYPTED PACKET ----
    loop {
        socket.send_to(&out, target).await?;
        let recv = timeout(Duration::from_millis(400), socket.recv_from(&mut ack)).await;

        if let Ok(Ok((3, addr))) = recv {
            if addr == *target && &ack == b"ACK" {
                break;
            }
        }
    }

    Ok(())
}

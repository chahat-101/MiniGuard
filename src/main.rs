use MiniGuard::utils::{add_ip, generate_key};

use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

use clap::Parser;

use std::net::SocketAddr;
use std::sync::Arc;
use std::{net::IpAddr, process::Command};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce};
use hkdf::Hkdf;
use wintun::{self, Packet};

use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

#[derive(Parser)]
struct Args {
    data: String,
    target: String,
    salt: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());

    let args = Args::parse();
    let data = args.data; //data given by the user
    let salt = args.salt.as_bytes(); //used to generate pseudo random key from the shared secret

    let win_tun = unsafe { wintun::load().expect("failed to load wintun") };

    let adapter = match wintun::Adapter::open(&win_tun, "minguard") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&win_tun, "wintun", "Wintun", None)?,
    };

    adapter.set_network_addresses_tuple(
        IpAddr::V4("10.0.0.2".parse().unwrap()), // client virtual IP
        IpAddr::V4("255.255.255.0".parse().unwrap()), // netmask
        Some(IpAddr::V4("10.0.0.1".parse().unwrap())), // gateway IP (server side)
    )?;
    
    let demo_target_ip = "203.0.113.10";

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    println!("Wintun session started");

    let target: SocketAddr = args.target.parse().expect("invalid address");

    let session_rx = session.clone();
    let socket_tx = socket.clone();
    let target_addr = target.clone();
    let salt_clone = salt.to_vec();

    tokio::spawn(async move {
        loop {
            let packet = match session_rx.receive_blocking() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[client] Wintun receive error: {e:?}");
                    continue;
                }
            };
            let ip_packet = packet.bytes();

            if let Err(e) = 
                    send_encrypted_packet(ip_packet, &socket_tx, &target_addr, &salt_clone).await{
                        eprintln!("[client] Error sending encrypted packet: {e}");
                    }
        
        }
    });

    println!(
        "[client] tunnel running. Try something like:\n ping {}"
        ,demo_target_ip
    );

    loop{
        tokio::time::sleep(Duration::from_millis(3600)).await;
    }
}


async fn send_encrypted_packet(
    packet:&[u8],
    socket:&UdpSocket,
    target:&SocketAddr,
    salt:&[u8]
) -> Result<(),Box<dyn std::error::Error>> {
    
    let (secret_key,public_key) = generate_key();
    let mut server_pub = [0u8;32];


    loop{
        socket.send_to(public_key.as_bytes(), target);
        let recv = timeout(Duration::from_millis(400), socket.recv_from(&mut server_pub)).await;
        if let Ok(Ok((_len,addr))) = recv{
            if addr == *target{
                socket.send_to(b"ACK", target).await?;
                break;
            }
        }
    }

    let shared_secret = secret_key.diffie_hellman(&PublicKey::from(server_pub));
    let hk = Hkdf::<Sha256>::new(Some(salt),shared_secret.as_bytes());

    let mut key_bytes = [0u8;32];
    hk.expand(b"chacha20poly1305 key", &mut key_bytes)
    .map_err(|_| -> Box<dyn std::error::Error> {
        "HKDF expand InvalidLength".into()
    })?;


    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8;12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let cipher_text = cipher
            .encrypt(nonce, packet)
            .map_err(|e| format!("AEAD encryption failed: {e}"))?;


    let mut out = Vec::with_capacity(12+cipher_text.len());

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&cipher_text);

    let mut ack = [0u8;3];

    loop{
        socket.send_to(&out, target).await?;
        let recv = timeout(Duration::from_millis(400), socket.recv_from(&mut ack)).await;
        if let Ok(Ok((_l,addr))) = recv{
            if &ack == b"ACK" && addr == *target{
                break; 
            }
        }

    }


    
    Ok(())
}
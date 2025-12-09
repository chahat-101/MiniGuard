// use crate::utils::{generate_key,receive_packet};
use MiniGuard::utils::{generate_key, receive_packet};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("the server is running on 127.0.0.0.1:4000");
    let socket = UdpSocket::bind("127.0.0.1:4000").await.unwrap();
    let (secret_key, public_key) = generate_key();
    let mut shared_secrets = Vec::new();
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut packet_count = 0;
    loop {
        let mut buf = [0u8; 32];

        let (n, addr) = socket.recv_from(&mut buf).await?;
        if n == 32 {
            println!("Received public key from {}",addr);


            socket.send_to(public_key.as_bytes(), addr).await?;
            let mut flag = [0u8; 3];
            let (_len, sender) = socket.recv_from(&mut flag).await?;


            if &flag == b"ACK" && sender == addr {
                println!("Handshake complete with {}", addr);
                
                let shared_secret = secret_key.diffie_hellman(&PublicKey::from(buf));
                shared_secrets.push(shared_secret);
                receive_packet(&sender, &socket, &mut packets).await?;
                packet_count+=1;

            }
        } //n == 32
        else if n == 3 && &buf[..3] == b"END"{
            println!("Received END from {}",addr);
            socket.send_to(b"END", addr).await?;
            break;
        } // n == 3
    }

    println!("\nAll packets:");
    for (i, packet) in packets.iter().enumerate() {
        println!("Packet {}: {} bytes - {}", i, packet.len(), hex::encode(&packet[..packet.len().min(32)]));
    }

    Ok(())
}

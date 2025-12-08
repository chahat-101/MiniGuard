use crate::utils::{generate_key,receive_packet};
use tokio::net::UdpSocket;
use chacha20poly1305::{ChaChaPoly1305,ChaCha20Poly1305,Key,Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey,SharedSecret,StaticSecret};
#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    let sock_addr = String::from("127.0.0.0:4000");
    let socket = UdpSocket::bind(sock_addr).await.unwrap();
    let (secret_key,public_key) = generate_key();
    let mut shared_secrets = Vec::new();
    let mut packets: Vec<Vec<u8>> = Vec::new();
    loop{
        let mut buf = [0u8;32];
        
        let (n,addr) = socket.recv_from(&mut buf).await?;
        if n == 32{
            socket.send_to(public_key.as_bytes(),addr).await?;
            let mut flag = [0u8;3];
            let FLAG = b"ACK";
            let (len,sender) = socket.recv_from(&mut flag).await?;
            if &flag == FLAG && sender == addr{
                let shared_secret = secret_key.diffie_hellman(&public_key);
                shared_secrets.push(shared_secret);
                receive_packet(sender, socket, &mut packets).await?;
                
                break;

            }
        }
    }


    Ok(())
}
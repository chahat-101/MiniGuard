use serde::ser::SerializeStruct;
use tokio::time::{timeout,Duration};
use tokio::net::UdpSocket;
mod server;
use clap::Parser;
use serde::Serialize;
use std::sync::Arc;
use std::{net::IpAddr, process::Command};
use wintun;
use chacha20poly1305::aead::{Aead,KeyInit,AeadCore};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use rand::RngCore;

#[derive(Parser)]
struct Args {
    data: String,
    target:String,
    salt: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    
    let socket = UdpSocket::bind("0.0.0.0:4000").await.unwrap(); //initialising a udpsocket

    let args = Args::parse();
    let data = args.data; //data given by the user
    let salt =args.salt.as_bytes(); //used to generate pseudo random key from the shared secret
    let win_tun = unsafe { wintun::load().expect("failed to load wintun") }; //this generates the wintin object wrapped in arc

    let adapter = match wintun::Adapter::open(&win_tun, "minguard") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&win_tun, "minguard", "Wintun", None)?,
    }; //generates an adapter wrapped inside arc

    adapter.set_network_addresses_tuple(
        IpAddr::V4("10.0.0.2".parse().unwrap()),
        IpAddr::V4("255.255.255.0".parse().unwrap()),
        Some(IpAddr::V4("10.0.0.1".parse().unwrap())),
    ); //this assigns ip address to the adapter

    let target = String::from("127.0.0.0:4000"); //hardcoded target ip

    add_ip(&target, "10.0.0.1", "minguard");

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap()); //this starts the adpater session
    let raw_data = data.as_bytes();  
    let bytes_per_packet = 64; //this is 64 kb 
    let mut total_bytes = raw_byte_data.len(); //total bytes of data
    let i = 0;

    while total_bytes > 0 {
        
        if total_bytes>64{
            send(raw_data,
                start_index, 
                length, 
                socket, 
                target, 
                salt, 
                data).await
        }  
    }
    Ok(())
}


async fn send(raw_data:&[u8],start_index:usize,length:usize,socket:UdpSocket,target:String,salt:String,data:String) {
    let packet = &raw_data[start_index..start_index+length];
    let (secret_key,public_key) = generate_key();

    let mut buf = [0u8;32];

    loop{                           //this loop : clients sends the public key, server sends it public_key and then client sends ACK
        socket.send_to(&public_key.to_bytes(), &target);
        let recv = timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await;

        if let Ok(Ok((len,sender_socket))) = recv{
            if len == 32{
                socket.send_to(b"ACK", sender_socket);
                break;
            }
        }
    }

    let shared_secret = secret_key.diffie_hellman(&PublicKey::from(buf));
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret.as_bytes());

    let mut key_bytes = [0u8;12];
    hk.expand(b"chacha20poly1305 key", &mut key_bytes);

    let mut nonce_bytes = [0u8;32];
    let key = Key::from_slice(&key_bytes);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher:ChaCha20Poly1305 = ChaChaPoly1305::new(key);

    let cipher_text = cipher.encrypt(nonce, packet)
                .expect("failed to encrypt using chahcha20poly1305");
    
    println!("cipher_text hex {}",hex::encode(&cipher_text));
    

}




fn add_ip(ip: &str, gateway: &str, interface_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let route = format!("{}/32", ip);

    let output = Command::new("netsh")
        .args(&[
            "interface",
            "ipv4",
            "add",
            "route",
            &route,
            interface_name,
            gateway,
            "metric=1",
        ])
        .output()?;

    if !output.status.success() {
        eprint!("Failed:{}", String::from_utf8_lossy(&output.stderr));
        return Err("Failed to add route".into());
    }

    println!("Added route: {} -> VPN", ip);

    Ok(())
}



fn generate_key() -> (StaticSecret,PublicKey){
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret,public)
}

fn derive_secret(shared_public:PublicKey,our_secret:StaticSecret) -> SharedSecret{
    let shared_secret = our_secret.diffie_hellman(&shared_public);
    shared_secret
}

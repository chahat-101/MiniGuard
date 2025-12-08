use tokio::time::{timeout,Duration};
use tokio::net::UdpSocket;
mod server;

mod utils;
use utils::{generate_key,add_ip};

use clap::Parser;

use std::net::SocketAddr;
use std::sync::Arc;
use std::{net::IpAddr, process::Command};

use wintun;
use chacha20poly1305::aead::{Aead,KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce};
use hkdf::Hkdf;

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

    let target: SocketAddr = String::from("127.0.0.0:4000").parse().expect("invalid address"); //hardcoded target ip

    add_ip(&target.to_string(), "10.0.0.1", "minguard");

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap()); //this starts the adpater session
    let raw_data = data.as_bytes();  
    
    let mut total_bytes = raw_data.len(); //total bytes of data
    let i = 0;
    let mut i = 0;
    while total_bytes > 0 {
        send(raw_data,
                i, 
                total_bytes, 
                &socket, 
                &target, 
                String::from("this is some salt"), 
                &data).await;
        if total_bytes>8000 {     //I am using 64 bytes per packet 
            total_bytes-=8000;    
        }
        else{
            total_bytes = 0;    //this means it was the last packet
        }
        i+=1;
    }
    Ok(())
}


async fn send(raw_data:&[u8],start_index:usize,length:usize,socket:&UdpSocket,target:&SocketAddr,salt:String,data:&String) -> Result<(),Box<dyn std::error::Error>>{
    let packet = &raw_data[start_index..start_index+length];
    let (secret_key,public_key) = generate_key();

    let mut buf = [0u8;32];

    loop{                           //this loop : clients sends the public key, server sends it public_key and then client sends ACK
        socket.send_to(&public_key.to_bytes(), target);
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
    
    loop{
        socket.send_to(&cipher_text, target).await?;
        let mut flag = [0u8;3];
        let FLAG = b"ACK";
        let recv = timeout(Duration::from_millis(400), socket.recv_from(&mut flag)).await;
        let (len,sender) = match recv? {
            Ok(a) => a,
            Err(e) => return Err(e.into())
        };
        if &flag == FLAG && &sender == target{
            break;
        }
    }
    
    println!("cipher_text hex {}",hex::encode(&cipher_text));
    
    Ok(())
}










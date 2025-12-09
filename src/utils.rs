use rand_core::OsRng;
use std::net::SocketAddr;
use std::process::Command;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub fn generate_key() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn add_ip(
    ip: &str,
    gateway: &str,
    interface_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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

pub async fn receive_packet(
    target: &SocketAddr,
    socket: &UdpSocket,
    packets: &mut Vec<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut packet = [0u8; 8000];
        let (len, sender) = socket.recv_from(&mut packet).await?;
        if sender.ip() == target.ip() {
            packets.push(packet[..len].to_vec());

            socket.send_to(b"ACK", sender).await?;

            break;
        }
    }

    Ok(())
}

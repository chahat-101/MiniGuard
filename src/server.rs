use anyhow::Ok;
use tokio::net::UdpSocket;
use wintun::Packet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_socket = UdpSocket::bind("127.0.0.0:4000").await?;
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 65535];

    loop {
        let (len, addr) = server_socket.recv_from(&mut buf).await?;
        let index = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let total_packets = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let packet = buf[..len].to_vec();
        if index <= total_packets {
            packets.push(packet);
        } else {
            break;
        }
    }

    Ok(())
}

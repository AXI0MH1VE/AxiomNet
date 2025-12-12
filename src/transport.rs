use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: u8,
    pub counter: u64,
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await.context("Failed to bind UDP socket")?;
        Ok(Self { socket })
    }

    pub async fn send_packet(&self, header: &PacketHeader, payload: &[u8], target: &SocketAddr) -> Result<()> {
        let mut buf = bincode::serialize(header)?;
        buf.extend_from_slice(payload);
        self.socket.send_to(&buf, target).await?;
        Ok(())
    }

    pub async fn recv_packet(&self, buf: &mut [u8]) -> Result<(PacketHeader, usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf).await?;
        let header: PacketHeader = bincode::deserialize(&buf[..std::mem::size_of::<PacketHeader>()])?;
        Ok((header, n, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

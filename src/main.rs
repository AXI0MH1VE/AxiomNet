//! Axiom Daemon Entry Point
mod tun_adapter;
mod crypto;
mod transport;
mod peer;

use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting axiomd daemon...");

    // TUN interface config
    let tun_name = "ax0";
    let mtu = 1280;
    let address = Ipv4Addr::new(10, 0, 0, 1);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);

    let adapter = tun_adapter::TunAdapter::new(tun_name, mtu, address, netmask)?;
    tracing::info!("TUN device {} created (MTU {})", adapter.name(), adapter.mtu());

    let mut dev = adapter.into_inner();

    // Crypto identity
    let identity = crypto::NodeIdentity::load_or_generate("./config/identity.key")?;
    tracing::info!("Node public key: {}", identity.public_base64());

    // UDP transport
    let udp_addr = "0.0.0.0:40000";
    let udp = transport::UdpTransport::bind(udp_addr).await?;
    tracing::info!("UDP transport bound to {}", udp.local_addr()?);

    // Peer manager
    let peer_manager = peer::PeerManager::new();

    // For demo: hardcode remote peer (replace with real IP/port for test)
    let remote_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    // In real use, exchange public keys out-of-band
    let remote_pub = [0u8; 32]; // Replace with actual remote pubkey for real test

    // Handshake as initiator (for demo)
    let mut handshake = crypto::HandshakeManager::initiator(&identity, &remote_pub)?;
    let mut buf = [0u8; 65535];
    let mut msg = [0u8; 65535];
    // -> e
    let len = handshake.write_message(&[], &mut msg)?;
    udp.send_packet(&transport::PacketHeader { version: 1, packet_type: 2, counter: 0 }, &msg[..len], &remote_addr).await?;
    // <- e, ee, s, es
    let (header, n, from) = udp.recv_packet(&mut buf).await?;
    let _ = handshake.read_message(&buf[std::mem::size_of::<transport::PacketHeader>()..n], &mut msg)?;
    // -> s, se
    let len = handshake.write_message(&[], &mut msg)?;
    udp.send_packet(&transport::PacketHeader { version: 1, packet_type: 2, counter: 1 }, &msg[..len], &remote_addr).await?;
    assert!(handshake.is_handshake_finished());
    let transport_state = handshake.into_transport()?;
    peer_manager.insert(remote_addr, peer::Peer::new(remote_addr, transport_state));
    tracing::info!("Handshake complete with {}", remote_addr);

    // Event loop: select between TUN and UDP
    let mut tun_buf = vec![0u8; mtu];
    let mut udp_buf = vec![0u8; 65535];

    let shutdown = async {
        signal::ctrl_c().await.expect("failed to listen for event");
        tracing::info!("Received shutdown signal, exiting...");
    };

    tokio::select! {
        _ = async {
            loop {
                // Inbound UDP
                let (header, n, from) = udp.recv_packet(&mut udp_buf).await?;
                if let Some(mut peer) = peer_manager.get(&from) {
                    let decrypted = peer.transport.read_message(&udp_buf[std::mem::size_of::<transport::PacketHeader>()..n])?;
                    dev.write_all(&decrypted).await?;
                }
            }
        } => {},
        _ = async {
            loop {
                // Inbound TUN
                let n = dev.read(&mut tun_buf).await?;
                if n == 0 { continue; }
                // For demo: always send to remote_addr
                if let Some(mut peer) = peer_manager.get(&remote_addr) {
                    let mut encrypted = vec![0u8; n + 16];
                    let len = peer.transport.write_message(&tun_buf[..n], &mut encrypted)?;
                    udp.send_packet(&transport::PacketHeader { version: 1, packet_type: 0, counter: peer.counter }, &encrypted[..len], &remote_addr).await?;
                }
            }
        } => {},
        _ = shutdown => {},
    }

    Ok(())
}

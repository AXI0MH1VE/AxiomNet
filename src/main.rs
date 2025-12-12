//! Axiom Daemon Entry Point
mod tun_adapter;
mod protocol;
mod router;
mod identity;
mod session;
mod transport;

use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::Lazy;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting axiomd daemon...");

    // Load/generate Ed25519 keypair (reuse from previous phases or implement as needed)
    let keypair = crypto::NodeIdentity::load_or_generate("./config/identity.key")?;
    let public_key = &keypair.static_keypair.public;
    let overlay_ip = identity::generate_axiom_address(public_key)?;
    tracing::info!("Node overlay IPv6: {}", overlay_ip);

    // TUN interface config
    let tun_name = "ax0";
    let mtu = 1280;
    let address = Ipv4Addr::new(10, 0, 0, 1); // For TUN config only
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let adapter = tun_adapter::TunAdapter::new(tun_name, mtu, address, netmask)?;
    tracing::info!("TUN device {} created (MTU {})", adapter.name(), adapter.mtu());
    let mut dev = adapter.into_inner();

    // UDP transport
    let udp_addr = "0.0.0.0:40000";
    let udp = transport::UdpTransport::bind(udp_addr).await?;
    tracing::info!("UDP transport bound to {}", udp.local_addr()?);

    // Routing table
    let router = router::RoutingTable::new(overlay_ip);

    // Session management: DashMap<ReceiverIndex, Session>
    use dashmap::DashMap;
    use std::sync::Arc;
    let sessions: Arc<DashMap<u32, session::Session>> = Arc::new(DashMap::new());

    // For demo: hardcode remote peer (replace with real IP/port for test)
    let remote_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let remote_pub = [0u8; 32]; // Replace with actual remote pubkey for real test
    let remote_overlay_ip = identity::generate_axiom_address(&remote_pub)?;
    router.add_route(remote_overlay_ip, remote_addr);

    // Main event loop
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
                let axiom_packet = protocol::AxiomPacket::decode(bytes::Bytes::copy_from_slice(&udp_buf[..n]))?;
                match axiom_packet.header.packet_type {
                    protocol::PacketType::Handshake => {
                        // Handshake logic: advance state, promote to Established if done
                        if let Some(mut sess) = sessions.get_mut(&axiom_packet.header.receiver_index) {
                            let _ = sess.process_incoming(axiom_packet)?;
                        } else {
                            // New handshake: create Session in Handshaking state
                            // (For demo, not shown: extract remote pubkey, etc.)
                        }
                    }
                    protocol::PacketType::Data => {
                        if let Some(mut sess) = sessions.get_mut(&axiom_packet.header.receiver_index) {
                            let decrypted = sess.process_incoming(axiom_packet)?;
                            dev.write_all(&decrypted).await?;
                        }
                    }
                    _ => {}
                }
            }
        } => {},
        _ = async {
            loop {
                // Inbound TUN
                let n = dev.read(&mut tun_buf).await?;
                if n == 0 { continue; }
                // Extract dest IPv6 from packet (assume IPv6 for demo)
                let dest_ip = Ipv6Addr::from([0xfc,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]); // Replace with real extraction
                if let Some(next_hop) = router.lookup(&dest_ip) {
                    // Find or create session
                    let receiver_index = 1; // For demo, static
                    let mut sess = sessions.entry(receiver_index).or_insert_with(|| {
                        // If not connected, initiate handshake (not shown: real handshake logic)
                        // For demo, create dummy established session
                        let dummy_hs = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap()).build_initiator().unwrap();
                        session::Session::new_handshaking(dummy_hs, receiver_index, receiver_index)
                    });
                    if sess.is_established() {
                        let axiom_packet = sess.encrypt_outgoing(&tun_buf[..n])?;
                        udp.send_packet(&axiom_packet.header, &axiom_packet.payload, &next_hop).await?;
                    } else {
                        // Not established: trigger handshake (not shown)
                    }
                }
            }
        } => {},
        _ = shutdown => {},
    }

    Ok(())
}

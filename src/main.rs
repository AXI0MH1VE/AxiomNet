//! Axiom Daemon Entry Point
mod tun_adapter;
mod protocol;
mod router;
mod identity;
mod session;
mod transport;
mod topology;
mod control;

use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::Lazy;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9000")]
    bind: String,
    #[arg(long, default_value = "ax0")]
    tun: String,
    #[arg(long)]
    peer: Option<String>,
    #[arg(long)]
    secret_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // CLI
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    tracing::info!("Starting axiomd daemon...");

    // Identity
    let keypair = if let Some(hex) = cli.secret_key {
        // TODO: Load from hex
        crypto::NodeIdentity::load_or_generate("./config/identity.key")?
    } else {
        crypto::NodeIdentity::load_or_generate("./config/identity.key")?
    };
    let public_key = &keypair.static_keypair.public;
    let overlay_ip = identity::generate_axiom_address(public_key)?;
    tracing::info!("Node overlay IPv6: {}", overlay_ip);

    // TUN
    let mtu = 1280;
    let address = Ipv4Addr::new(10, 0, 0, 1);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let adapter = tun_adapter::TunAdapter::new(&cli.tun, mtu, address, netmask)?;
    tracing::info!("TUN device {} created (MTU {})", adapter.name(), adapter.mtu());
    let mut dev = adapter.into_inner();

    // UDP
    let udp = transport::UdpTransport::bind(&cli.bind).await?;
    tracing::info!("UDP transport bound to {}", udp.local_addr()?);

    // Routing table
    let router = router::RoutingTable::new(overlay_ip);

    // Session management
    use dashmap::DashMap;
    use std::sync::Arc;
    let sessions: Arc<DashMap<u32, session::Session>> = Arc::new(DashMap::new());

    // Topology: assign coordinates (for demo, random)
    use topology::Coordinates;
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let my_coords = Coordinates { r: rng.gen_range(0.0..0.99), theta: rng.gen_range(0.0..std::f64::consts::TAU) };

    // Bootstrap peer if provided
    if let Some(peer_addr) = cli.peer {
        let peer_sock: SocketAddr = peer_addr.parse().expect("Invalid peer address");
        // TODO: Initiate handshake with peer_sock
        // router.add_route(peer_overlay_ip, peer_sock);
    }

    // Heartbeat task
    let router_clone = router.clone();
    let my_coords_clone = my_coords;
    tokio::spawn(async move {
        loop {
            let msg = control::ControlMessage::Heartbeat { my_coords: my_coords_clone, my_load: 0 };
            // TODO: Broadcast to all peers
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

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
                        // Handshake logic
                        if let Some(mut sess) = sessions.get_mut(&axiom_packet.header.receiver_index) {
                            let _ = sess.process_incoming(axiom_packet)?;
                        } else {
                            // New handshake: create Session in Handshaking state
                        }
                    }
                    protocol::PacketType::Data => {
                        if let Some(mut sess) = sessions.get_mut(&axiom_packet.header.receiver_index) {
                            let decrypted = sess.process_incoming(axiom_packet)?;
                            dev.write_all(&decrypted).await?;
                        }
                    }
                    protocol::PacketType::Control => {
                        // Parse and handle control message
                        if let Ok(msg) = bincode::deserialize::<control::ControlMessage>(&axiom_packet.payload) {
                            control::handle_control_packet(&msg, axiom_packet.header.receiver_index, &router);
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
                // Extract dest IPv6 from packet (real extraction needed)
                let dest_ip = Ipv6Addr::from([0xfc,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]);
                // Routing: direct or greedy
                let next_hop = if let Some(hop) = router.lookup(&dest_ip) {
                    Some(hop)
                } else {
                    // Greedy routing
                    let neighbors = vec![]; // TODO: gather from router
                    topology::find_greedy_hop(/*target*/my_coords, neighbors).map(|id| router.lookup(&id)).flatten()
                };
                if let Some(next_hop) = next_hop {
                    // Find or create session
                    let receiver_index = 1; // For demo, static
                    let mut sess = sessions.entry(receiver_index).or_insert_with(|| {
                        let dummy_hs = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap()).build_initiator().unwrap();
                        session::Session::new_handshaking(dummy_hs, receiver_index, receiver_index)
                    });
                    if sess.is_established() {
                        let axiom_packet = sess.encrypt_outgoing(&tun_buf[..n])?;
                        udp.send_packet(&axiom_packet.header, &axiom_packet.payload, &next_hop).await?;
                    } else {
                        // Not established: trigger handshake
                    }
                }
            }
        } => {},
        _ = shutdown => {},
    }

    Ok(())
}

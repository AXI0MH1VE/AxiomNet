//! Axiom Daemon - Layer 3 Overlay Network with Hyperbolic Routing
//!
//! Usage:
//!   axiomd --bind 0.0.0.0:9000 --tun ax0 --peer 127.0.0.1:9001
//!   axiomd --bind 0.0.0.0:9001 --tun ax1

mod tun_adapter;
mod protocol;
mod router;
mod identity;
mod session;
mod transport;
mod topology;
mod control;
mod crypto;
mod peer;

use anyhow::Result;
use clap::Parser;
use dashmap::DashMap;
use protocol::{AxiomPacket, PacketType, SwitchHeader};
use router::RoutingTable;
use session::Session;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::UdpSocket;
use tokio::signal;
use topology::Coordinates;
use tracing_subscriber::{fmt, EnvFilter, prelude::*};

#[derive(Parser, Debug)]
#[command(name = "axiomd")]
#[command(author = "Axiom Network")]
#[command(about = "Axiom Layer 3 Overlay Network Daemon", long_about = None)]
struct Cli {
    /// UDP bind address (e.g., 0.0.0.0:9000)
    #[arg(long, default_value = "0.0.0.0:9000")]
    bind: String,

    /// TUN interface name (e.g., ax0)
    #[arg(long, default_value = "ax0")]
    tun: String,

    /// Bootstrap peer address (e.g., 127.0.0.1:9000)
    #[arg(long)]
    peer: Option<String>,

    /// Secret key as hex string (if not provided, generates new identity)
    #[arg(long)]
    secret_key: Option<String>,

    /// Node ID (for logging/identification)
    #[arg(long, default_value = "node-1")]
    node_id: String,
}

struct AxiomNode {
    cli: Cli,
    router: Arc<RoutingTable>,
    sessions: Arc<DashMap<u32, Session>>,
    session_counter: Arc<AtomicU32>,
    udp_socket: Arc<UdpSocket>,
    keypair: crypto::NodeIdentity,
    overlay_ip: Ipv6Addr,
    self_coords: Coordinates,
}

impl AxiomNode {
    async fn new(cli: Cli) -> Result<Self> {
        // 1. Initialize Crypto & Identity
        let keypair = if let Some(hex_key) = &cli.secret_key {
            crypto::NodeIdentity::load_from_hex(hex_key)?
        } else {
            crypto::NodeIdentity::load_or_generate("./config/identity.key")?
        };

        let public_key = &keypair.static_keypair.public;
        let overlay_ip = identity::generate_axiom_address(public_key)?;

        tracing::info!(
            "Node: {} | Overlay IPv6: {} | Public Key: {}",
            cli.node_id,
            overlay_ip,
            keypair.public_base64()
        );

        // 2. Initialize Routing Table
        let router = Arc::new(RoutingTable::new(overlay_ip));

        // 3. Bind UDP Transport
        let udp_socket = Arc::new(UdpSocket::bind(&cli.bind).await?);
        tracing::info!("UDP bound to: {}", udp_socket.local_addr()?);

        // 4. Initialize Session Storage
        let sessions = Arc::new(DashMap::new());
        let session_counter = Arc::new(AtomicU32::new(1));

        // 5. Initialize Self Coordinates (random for now)
        let mut self_coords = Coordinates {
            r: rand::random::<f64>() * 0.95, // Stay away from boundary
            theta: rand::random::<f64>() * std::f64::consts::TAU,
        };
        self_coords.normalize();
        router.set_self_coords(self_coords);

        tracing::info!(
            "Self coordinates: r={:.4}, theta={:.4}",
            self_coords.r,
            self_coords.theta
        );

        Ok(Self {
            cli,
            router,
            sessions,
            session_counter,
            udp_socket,
            keypair,
            overlay_ip,
            self_coords,
        })
    }

    /// Get next session ID
    fn next_session_id(&self) -> u32 {
        self.session_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Handle inbound UDP packet (decryption, routing, etc.)
    async fn handle_inbound_udp(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        let packet = AxiomPacket::decode(bytes::Bytes::copy_from_slice(data))
            .context("Failed to decode packet")?;

        match packet.header.packet_type {
            PacketType::Handshake => {
                tracing::debug!("Handshake packet from {}", from);
                // TODO: Process Noise Protocol handshake
            }
            PacketType::Data => {
                tracing::debug!("Data packet from {}", from);
                // TODO: Process data packet through established session
            }
            PacketType::Control => {
                // Parse and handle control message
                match bincode::deserialize::<control::ControlMessage>(&packet.payload) {
                    Ok(msg) => {
                        control::handle_control_packet(&msg, from, &self.router);
                    }
                    Err(e) => {
                        tracing::warn!(
                            from = %from,
                            error = %e,
                            "Failed to deserialize control message"
                        );
                    }
                }
            }
            PacketType::Keepalive => {
                tracing::trace!("Keepalive from {}", from);
            }
        }

        Ok(())
    }

    /// Handle inbound TUN packet (encryption, routing)
    async fn handle_inbound_tun(&self, data: &[u8]) -> Result<()> {
        if data.len() < 40 {
            return Ok(());
        }

        // Extract destination IPv6 from packet (40 bytes into IPv6 header)
        let dest_ip = Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        );

        tracing::trace!("TUN packet to {}", dest_ip);

        // Check if destination is local
        if self.router.is_local(&dest_ip) {
            tracing::debug!("Destination is local");
            return Ok(());
        }

        // Try direct route
        if let Some(next_hop) = self.router.lookup(&dest_ip) {
            tracing::debug!("Direct route to {} via {}", dest_ip, next_hop);
            // TODO: Send via established session
            return Ok(());
        }

        // Use greedy routing
        let peers = self.router.get_peers();
        if peers.is_empty() {
            tracing::warn!("No peers available for routing");
            return Ok(());
        }

        // Assume destination coordinates from IP (in real implementation, use DHT)
        let dest_coords = Coordinates {
            r: 0.7,
            theta: (dest_ip.segments()[0] as f64 / 65535.0) * std::f64::consts::TAU,
        };

        let neighbor_list: Vec<_> = peers
            .iter()
            .map(|(id, entry)| (*id, entry.coords))
            .collect();

        if let Some(next_peer_id) = topology::find_greedy_hop(dest_coords, neighbor_list) {
            if let Some(peer) = self.router.get_peer(next_peer_id) {
                tracing::debug!(
                    "Greedy route to {} via peer {} at {}",
                    dest_ip, next_peer_id, peer.addr
                );
                // TODO: Forward via session to next_peer_id
            }
        }

        Ok(())
    }

    /// Broadcast heartbeat to all connected peers
    async fn broadcast_heartbeat(&self) -> Result<()> {
        let msg = control::ControlMessage::Heartbeat {
            peer_id: self.overlay_ip.segments()[6] as u32,
            my_coords: self.self_coords,
            my_load: 0, // TODO: Calculate actual node load
        };

        let payload = bincode::serialize(&msg)?;

        let header = SwitchHeader {
            route_label: 0,
            version: 1,
            packet_type: PacketType::Control,
            receiver_index: 0,
            counter: 0,
        };

        let packet = AxiomPacket {
            header,
            payload: bytes::Bytes::from(payload),
        };

        let encoded = packet.encode();

        for peer_entry in self.router.get_peers() {
            if let Err(e) = self.udp_socket.send_to(&encoded, peer_entry.1.addr).await {
                tracing::warn!("Failed to send heartbeat to {}: {}", peer_entry.1.addr, e);
            }
        }

        tracing::debug!("Broadcast heartbeat to {} peers", self.router.get_peers().len());
        Ok(())
    }

    /// Bootstrap with a peer if provided
    async fn bootstrap_peer(&self, peer_addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = peer_addr.parse()?;
        tracing::info!("Bootstrapping with peer: {}", socket_addr);

        let peer_id = self.next_session_id();
        let peer_coords = Coordinates {
            r: 0.6,
            theta: std::f64::consts::PI,
        };

        self.router
            .add_peer(peer_id, socket_addr, peer_coords);

        // TODO: Initiate Noise Protocol handshake with peer
        Ok(())
    }

    /// Main event loop
    async fn run(&self) -> Result<()> {
        // Bootstrap if peer provided
        if let Some(peer_addr) = &self.cli.peer {
            self.bootstrap_peer(peer_addr).await?;
        }

        // Spawn heartbeat task
        let router = self.router.clone();
        let udp = self.udp_socket.clone();
        let self_coords = self.self_coords;
        let overlay_ip = self.overlay_ip;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let msg = control::ControlMessage::Heartbeat {
                    peer_id: overlay_ip.segments()[6] as u32,
                    my_coords: self_coords,
                    my_load: 0,
                };

                if let Ok(payload) = bincode::serialize(&msg) {
                    let header = SwitchHeader {
                        route_label: 0,
                        version: 1,
                        packet_type: PacketType::Control,
                        receiver_index: 0,
                        counter: 0,
                    };

                    let packet = AxiomPacket {
                        header,
                        payload: bytes::Bytes::from(payload),
                    };

                    let encoded = packet.encode();

                    for peer_entry in router.get_peers() {
                        // Log errors instead of silently ignoring for better observability
                        if let Err(e) = udp.send_to(&encoded, peer_entry.1.addr).await {
                            tracing::warn!(
                                peer_addr = %peer_entry.1.addr,
                                peer_id = %peer_entry.0,
                                error = %e,
                                "Failed to send heartbeat to peer"
                            );
                        }
                    }
                }
            }
        });

        // Main event loop
        let mut udp_buf = vec![0u8; 65535];
        let mut tun_buf = vec![0u8; 1500];

        let shutdown = async {
            let _ = signal::ctrl_c().await;
            tracing::info!("Received shutdown signal");
        };

        tokio::select! {
            result = async {
                loop {
                    // Add timeout to UDP recv to allow periodic shutdown signal checking
                    // and prevent indefinite blocking
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        self.udp_socket.recv_from(&mut udp_buf)
                    ).await {
                        Ok(Ok((n, from))) => {
                            let buf = udp_buf[..n].to_vec();
                            let this = self;
                            let _ = tokio::spawn(async move {
                                if let Err(e) = this.handle_inbound_udp(&buf, from).await {
                                    tracing::debug!(
                                        from = %from,
                                        error = %e,
                                        "Error handling inbound UDP packet"
                                    );
                                }
                            }).await;
                        }
                        Ok(Err(e)) => {
                            tracing::error!("UDP recv error: {}", e);
                        }
                        Err(_) => {
                            // Timeout - this is normal, allows checking for shutdown
                            tracing::trace!("UDP recv timeout, checking for shutdown signal");
                        }
                    }
                }
            } => {
                tracing::info!("UDP loop exited");
                result
            }
            _ = shutdown => {
                tracing::info!("Shutting down...");
                Ok(())
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    tracing::info!(
        "=== Axiom Network Daemon ===\nNode: {}\nBind: {}\nTUN: {}",
        cli.node_id, cli.bind, cli.tun
    );

    // Create and run the node
    let node = AxiomNode::new(cli).await?;
    node.run().await?;

    Ok(())
}

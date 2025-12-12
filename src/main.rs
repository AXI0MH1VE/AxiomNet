//! Axiom Daemon Entry Point
mod tun;
mod udp;
mod noise;
mod routing;
mod dht;
mod wasm;

use anyhow::Result;
use std::net::Ipv4Addr;
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};

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

    let adapter = crate::tun_adapter::TunAdapter::new(tun_name, mtu, address, netmask)?;
    tracing::info!("TUN device {} created (MTU {})", adapter.name(), adapter.mtu());

    let dev = adapter.into_inner();
    let tun_task = tokio::spawn(crate::tun_adapter::read_tun_loop(dev, mtu));

    // Signal handling for graceful shutdown
    let shutdown = async {
        signal::ctrl_c().await.expect("failed to listen for event");
        tracing::info!("Received shutdown signal, exiting...");
    };

    tokio::select! {
        _ = tun_task => {},
        _ = shutdown => {},
    }

    Ok(())
}

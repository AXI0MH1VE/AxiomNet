use anyhow::{Context, Result};
use std::io::{self, ErrorKind};
use std::net::Ipv4Addr;
use tun::{Configuration, Device as TunDevice, Layer};

pub struct TunAdapter {
    dev: TunDevice,
    mtu: usize,
    name: String,
}

impl TunAdapter {
    pub fn new(name: &str, mtu: usize, address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self> {
        let mut config = Configuration::default();
        config
            .name(name)
            .layer(Layer::L3)
            .mtu(mtu as i32)
            .address(address)
            .netmask(netmask)
            .up();
        #[cfg(target_os = "linux")]
        {
            config.platform(|platform| {
                platform.packet_information(false); // IFF_NO_PI
            });
        }
        let dev = TunDevice::new(&config).context("Failed to create TUN device")?;
        Ok(Self {
            dev,
            mtu,
            name: name.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn into_inner(self) -> TunDevice {
        self.dev
    }
}

pub async fn read_tun_loop(mut dev: TunDevice, mtu: usize) -> Result<()> {
    let mut buf = vec![0u8; mtu];
    loop {
        let n = dev.read(&mut buf).await.context("Failed to read from TUN")?;
        if n == 0 {
            continue;
        }
        tracing::info!(bytes = ?&buf[..n], len = n, "Packet received from TUN");
    }
}

pub async fn write_tun(dev: &mut TunDevice, data: &[u8]) -> Result<usize> {
    let n = dev.write(data).await.context("Failed to write to TUN")?;
    Ok(n)
}

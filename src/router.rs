use anyhow::Result;
use dashmap::DashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

pub struct RoutingTable {
    table: Arc<DashMap<Ipv6Addr, SocketAddr>>,
    pub self_overlay_ip: Ipv6Addr,
}

impl RoutingTable {
    pub fn new(self_overlay_ip: Ipv6Addr) -> Self {
        Self {
            table: Arc::new(DashMap::new()),
            self_overlay_ip,
        }
    }

    pub fn add_route(&self, overlay_ip: Ipv6Addr, underlay: SocketAddr) {
        self.table.insert(overlay_ip, underlay);
    }

    pub fn lookup(&self, overlay_ip: &Ipv6Addr) -> Option<SocketAddr> {
        self.table.get(overlay_ip).map(|v| *v)
    }

    pub fn is_local(&self, overlay_ip: &Ipv6Addr) -> bool {
        &self.self_overlay_ip == overlay_ip
    }
}

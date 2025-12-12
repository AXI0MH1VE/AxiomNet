use anyhow::Result;
use dashmap::DashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use crate::topology::Coordinates;

pub struct PeerEntry {
    pub addr: SocketAddr,
    pub coords: Coordinates,
    pub load: u32,
}

pub struct RoutingTable {
    table: Arc<DashMap<Ipv6Addr, SocketAddr>>,
    peers: Arc<DashMap<u32, PeerEntry>>,
    pub self_overlay_ip: Ipv6Addr,
    pub self_coords: Arc<parking_lot::Mutex<Coordinates>>,
}

impl RoutingTable {
    pub fn new(self_overlay_ip: Ipv6Addr) -> Self {
        Self {
            table: Arc::new(DashMap::new()),
            peers: Arc::new(DashMap::new()),
            self_overlay_ip,
            self_coords: Arc::new(parking_lot::Mutex::new(Coordinates { r: 0.5, theta: 0.0 })),
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

    pub fn add_peer(&self, peer_id: u32, addr: SocketAddr, coords: Coordinates) {
        self.peers.insert(peer_id, PeerEntry { addr, coords, load: 0 });
    }

    pub fn update_peer_coords(&self, peer_id: u32, coords: Coordinates) {
        if let Some(mut entry) = self.peers.get_mut(&peer_id) {
            entry.coords = coords;
        }
    }

    pub fn update_peer_load(&self, peer_id: u32, load: u32) {
        if let Some(mut entry) = self.peers.get_mut(&peer_id) {
            entry.load = load;
        }
    }

    pub fn get_peers(&self) -> Vec<(u32, PeerEntry)> {
        self.peers
            .iter()
            .map(|entry| (entry.key().clone(), PeerEntry {
                addr: entry.value().addr,
                coords: entry.value().coords,
                load: entry.value().load,
            }))
            .collect()
    }

    pub fn get_peer(&self, peer_id: u32) -> Option<PeerEntry> {
        self.peers.get(&peer_id).map(|entry| PeerEntry {
            addr: entry.addr,
            coords: entry.coords,
            load: entry.load,
        })
    }

    pub fn set_self_coords(&self, coords: Coordinates) {
        *self.self_coords.lock() = coords;
    }

    pub fn get_self_coords(&self) -> Coordinates {
        *self.self_coords.lock()
    }
}

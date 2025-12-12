use dashmap::DashMap;
use snow::TransportState;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub transport: TransportState,
    pub counter: u64,
}

impl Peer {
    pub fn new(addr: SocketAddr, transport: TransportState) -> Self {
        Self { addr, transport, counter: 0 }
    }
}

pub struct PeerManager {
    peers: Arc<DashMap<SocketAddr, Peer>>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self { peers: Arc::new(DashMap::new()) }
    }

    pub fn insert(&self, addr: SocketAddr, peer: Peer) {
        self.peers.insert(addr, peer);
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<Peer> {
        self.peers.get(addr).map(|p| p.clone())
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }
}

use dashmap::DashMap;
use snow::TransportState;
use std::net::SocketAddr;
use std::sync::Arc;

// Note: TransportState cannot be cloned due to cryptographic state
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

    // Note: Cannot return cloned Peer since TransportState is not Clone
    // Callers should use with_peer() to access peer data
    pub fn with_peer<F, R>(&self, addr: &SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&Peer) -> R,
    {
        self.peers.get(addr).map(|p| f(p.value()))
    }

    pub fn remove(&self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }
}

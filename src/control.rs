use serde::{Serialize, Deserialize};
use crate::topology::Coordinates;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Heartbeat {
        peer_id: u32,
        my_coords: Coordinates,
        my_load: u32,
    },
}

pub fn handle_control_packet(
    msg: &ControlMessage,
    sender_addr: std::net::SocketAddr,
    routing_table: &crate::router::RoutingTable,
) {
    match msg {
        ControlMessage::Heartbeat { peer_id, my_coords, my_load } => {
            // Validate coordinates before storing to prevent routing failures
            if !my_coords.is_valid() {
                tracing::warn!(
                    peer_addr = %sender_addr,
                    peer_id = %peer_id,
                    r = %my_coords.r,
                    theta = %my_coords.theta,
                    "Received invalid coordinates from peer, ignoring heartbeat"
                );
                return;
            }
            
            routing_table.update_peer_coords(*peer_id, *my_coords);
            routing_table.update_peer_load(*peer_id, *my_load);
            tracing::debug!(
                "Updated peer {} coords to r={:.4}, theta={:.4}, load={}",
                peer_id, my_coords.r, my_coords.theta, my_load
            );
        }
    }
}

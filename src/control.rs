use serde::{Serialize, Deserialize};
use crate::topology::Coordinates;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Heartbeat {
        my_coords: Coordinates,
        my_load: u32,
    },
}

pub fn handle_control_packet(msg: &ControlMessage, peer_id: u32, routing_table: &crate::router::RoutingTable) {
    match msg {
        ControlMessage::Heartbeat { my_coords, my_load: _ } => {
            // Update peer's coordinates in the routing table (not shown: actual peer management)
            // routing_table.update_coords(peer_id, *my_coords);
        }
    }
}

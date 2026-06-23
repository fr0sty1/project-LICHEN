//! Gateway state and async event loop.

use lichen_core::addr::NodeId;
use lichen_node::Node;
use tracing::{info, warn};

/// Top-level border router state.
///
/// Holds a `Node` for protocol layer state and a routing table mapping mesh
/// IPv6 addresses to EUI-64 nexthops.
pub struct Gateway {
    pub node: Node,
    /// Routes installed in the kernel routing table.
    /// Key: mesh IPv6 address (16 bytes, network order); Value: nexthop EUI-64.
    routes: std::collections::HashMap<[u8; 16], NodeId>,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        info!(?node_id, "gateway initialising");
        Self {
            node: Node::new(node_id),
            routes: std::collections::HashMap::new(),
        }
    }

    /// Process a raw IPv6 packet received from the mesh (via SLIP).
    ///
    /// Stub: logs the packet length; real implementation will forward to the
    /// upstream tun interface.
    pub fn handle_mesh_packet(&mut self, packet: &[u8]) {
        if packet.len() < 40 {
            warn!(len = packet.len(), "mesh packet too short for IPv6 header");
            return;
        }
        if packet[0] >> 4 != 6 {
            warn!("non-IPv6 packet received from mesh");
            return;
        }
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
        info!(payload_len, "packet from mesh");
    }

    /// Process a raw IPv6 packet received from upstream.
    ///
    /// Stub: looks up the destination in the route table; real implementation
    /// will SCHC-compress and forward via SLIP.
    pub fn handle_upstream_packet(&mut self, packet: &[u8]) {
        if packet.len() < 40 {
            return;
        }
        let dst: [u8; 16] = packet[24..40].try_into().unwrap();
        if let Some(nexthop) = self.routes.get(&dst) {
            info!(?nexthop, "routing packet to mesh node");
        }
    }

    /// Record that `node_id` is reachable at `addr`.
    pub fn add_route(&mut self, addr: [u8; 16], node_id: NodeId) {
        self.routes.insert(addr, node_id);
    }
}

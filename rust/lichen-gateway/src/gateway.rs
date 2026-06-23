//! Gateway state stub.

use lichen_node::Node;
use lichen_core::addr::NodeId;

/// Border router state.
///
/// Stub — will grow to hold a TUN interface handle, route table, and
/// DODAG root state when the RPL and tun layers are implemented.
pub struct Gateway {
    pub node: Node,
}

impl Gateway {
    pub fn new(node_id: NodeId) -> Self {
        Self { node: Node::new(node_id) }
    }
}

//! Node state stub.

use lichen_core::addr::NodeId;

/// Top-level node state.
///
/// Stub — fields will be expanded as each layer is implemented.
pub struct Node {
    pub node_id: NodeId,
}

impl Node {
    pub fn new(node_id: NodeId) -> Self {
        Self { node_id }
    }
}

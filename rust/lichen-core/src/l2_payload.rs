//! Authenticated L2 inner-payload dispatch helpers.

use crate::constants::{L2_DISPATCH_ROUTING, L2_DISPATCH_SCHC};

/// Routing/control message type for LICHEN announce.
pub const L2_ROUTING_TYPE_ANNOUNCE: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2PayloadKind {
    Schc,
    Routing,
    Unknown,
}

pub fn classify(payload: &[u8]) -> L2PayloadKind {
    match payload.first().copied() {
        Some(L2_DISPATCH_SCHC) => L2PayloadKind::Schc,
        Some(L2_DISPATCH_ROUTING) => L2PayloadKind::Routing,
        _ => L2PayloadKind::Unknown,
    }
}

pub fn body(payload: &[u8]) -> &[u8] {
    payload.get(1..).unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RULE_GLOBAL_COAP;

    #[test]
    fn dispatch_distinguishes_global_coap_rule_from_announce() {
        let schc = [L2_DISPATCH_SCHC, RULE_GLOBAL_COAP, 0x40];
        let announce = [L2_DISPATCH_ROUTING, L2_ROUTING_TYPE_ANNOUNCE, 0x00];

        assert_eq!(classify(&schc), L2PayloadKind::Schc);
        assert_eq!(body(&schc), &[RULE_GLOBAL_COAP, 0x40]);
        assert_eq!(classify(&announce), L2PayloadKind::Routing);
        assert_eq!(body(&announce), &[L2_ROUTING_TYPE_ANNOUNCE, 0x00]);
        assert_eq!(schc[1], announce[1]);
    }

    #[test]
    fn unwrapped_first_byte_is_unknown() {
        assert_eq!(classify(&[RULE_GLOBAL_COAP, 0x00]), L2PayloadKind::Unknown);
        assert_eq!(classify(&[]), L2PayloadKind::Unknown);
    }
}

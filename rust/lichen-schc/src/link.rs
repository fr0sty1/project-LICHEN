//! SCHC compress/fragment over the authenticated LICHEN link layer.
//!
//! Lives in `lichen-schc` because `lichen-link` cannot depend on this crate.
//! The Python `LinkLayer` methods of the same names are the behavioral source.

use lichen_core::constants::{RULE_UNCOMPRESSED, SCHC_FRAG_MAX_PACKET_SIZE, SCHC_MAX_DECOMPRESSED};
use lichen_core::error::BufferTooSmall;
use lichen_core::l2_payload::{self, L2PayloadKind};
use lichen_link::frame::AddrMode;
use lichen_link::frame::MAX_FRAME_BODY;
use lichen_link::link_layer::{AuthenticatedFrame, LinkLayer};
use lichen_link::schnorr::SIGNATURE_LENGTH;

use crate::codec::{decode_rule255, AuthenticatedPeerSchcContext, ExpectedDioRole, SchcError};
use crate::fragment::{
    AuthenticatedFragmentationPermit, FragmentError, FragmentSender, FragmentationPolicy,
    RULE_ID_A_TO_B, RULE_ID_B_TO_A,
};

const MAX_LIVE_SCHC_PEERS: usize = 32;

#[derive(Clone, Copy)]
struct LivePeerPolicy {
    signer: [u8; 32],
    counter: u32,
    version: u8,
    key_generation: lichen_link::PeerKeyGeneration,
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    receipt_clock_domain: u64,
    receipt_ticks: u64,
    role: ExpectedDioRole,
}

/// Bounded owner of the currently admitted std link-layer SCHC policies.
///
/// A parsed [`AuthenticatedPeerSchcContext`] is only a candidate capability.
/// Callers install it here after DIO admission, then pass this registry to
/// compression and ingress. A newer DIO for one signer replaces its entry;
/// admitting a different root also retires the previous root policy.
pub struct AuthenticatedSchcPolicy {
    entries: [Option<LivePeerPolicy>; MAX_LIVE_SCHC_PEERS],
    current_root: Option<[u8; 32]>,
}

impl AuthenticatedSchcPolicy {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_LIVE_SCHC_PEERS],
            current_root: None,
        }
    }

    /// Install a strictly newer authenticated DIO policy.
    pub fn install(
        &mut self,
        link: &LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
    ) -> Result<(), SchcError> {
        if !peer.is_current_for(link) {
            return Err(SchcError::InvalidPeerEvidence);
        }
        let frame = peer
            .authenticated_frame()
            .ok_or(SchcError::InvalidPeerEvidence)?;
        let signer = *peer.signer_identity();
        let role = peer.expected_role();
        let existing = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.signer == signer));
        let slot = existing
            .or_else(|| self.entries.iter().position(Option::is_none))
            .ok_or(SchcError::PeerAuthorityFull)?;

        if let Some(current) = self.entries[slot].filter(|entry| entry.signer == signer) {
            if current.key_generation == frame.peer_key_generation()
                && current.durable_key_generation == frame.durable_peer_key_generation()
                && peer.authenticated_counter() <= current.counter
            {
                return Err(SchcError::InvalidPeerEvidence);
            }
            if current.receipt_clock_domain != frame.receipt().clock_domain()
                || frame.receipt().monotonic_ticks() < current.receipt_ticks
            {
                return Err(SchcError::InvalidPeerEvidence);
            }
        }

        self.entries[slot] = Some(LivePeerPolicy {
            signer,
            counter: peer.authenticated_counter(),
            version: peer.remote_version(),
            key_generation: frame.peer_key_generation(),
            durable_key_generation: frame.durable_peer_key_generation(),
            receipt_clock_domain: frame.receipt().clock_domain(),
            receipt_ticks: frame.receipt().monotonic_ticks(),
            role,
        });
        if role == ExpectedDioRole::Root {
            self.current_root = Some(signer);
        }
        Ok(())
    }

    fn is_current(&self, link: &LinkLayer, peer: &AuthenticatedPeerSchcContext) -> bool {
        if !peer.is_current_for(link) {
            return false;
        }
        let Some(frame) = peer.authenticated_frame() else {
            return false;
        };
        self.entries.iter().flatten().any(|entry| {
            entry.signer == *peer.signer_identity()
                && entry.counter == peer.authenticated_counter()
                && entry.version == peer.remote_version()
                && entry.key_generation == frame.peer_key_generation()
                && entry.durable_key_generation == frame.durable_peer_key_generation()
                && (entry.role != ExpectedDioRole::Root || self.current_root == Some(entry.signer))
        })
    }
}

impl Default for AuthenticatedSchcPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Largest unfragmented SCHC packet that fits one extended unicast frame.
///
/// Body budget: [`MAX_FRAME_BODY`] minus the 4-byte fixed header, 8-byte
/// extended destination, 8-byte signer EUI-64, 48-byte Schnorr MIC, and the
/// one-byte L2 SCHC dispatch. Matches Python `MAX_SINGLE_FRAME_SCHC_PACKET`.
pub const MAX_SINGLE_FRAME_SCHC_PACKET: usize = MAX_FRAME_BODY - 4 - 8 - 8 - SIGNATURE_LENGTH - 1;

pub use lichen_core::l2_payload::wrap_schc_payload;

/// Compress one IPv6 datagram under current authenticated peer SCHC policy.
pub fn compress_schc_for_peer(
    link: &LinkLayer,
    policy: &AuthenticatedSchcPolicy,
    peer: &AuthenticatedPeerSchcContext,
    ipv6: &[u8],
    out: &mut [u8],
    single_frame_limit: usize,
    allow_fragmentation: bool,
) -> Result<usize, SchcError> {
    if !policy.is_current(link, peer) {
        return Err(SchcError::InvalidPeerEvidence);
    }
    let length = peer.compress(ipv6, out, single_frame_limit)?;
    if length > single_frame_limit && !allow_fragmentation {
        return Err(SchcError::InvalidPacket(
            "SCHC packet requires authenticated fragmentation",
        ));
    }
    Ok(length)
}

/// Consume one unfragmented authenticated SCHC data frame.
///
/// Uses the same `is_current_for` live-binding as [`compress_schc_for_peer`]:
/// the DIO-issued peer context must belong to this receiving `LinkLayer`,
/// still be present and pinned, and the data-frame signer must match the
/// retained evidence. A replay-accepted in-window seqnum at or below the DIO
/// admission floor is still rejected.
pub fn accept_authenticated_schc_packet(
    link: &LinkLayer,
    policy: &AuthenticatedSchcPolicy,
    peer: &AuthenticatedPeerSchcContext,
    frame: &AuthenticatedFrame,
    out: &mut [u8],
    single_frame_limit: usize,
) -> Result<usize, SchcError> {
    if !policy.is_current(link, peer)
        || !link.accepts_authenticated_frame(frame)
        || peer.authenticated_frame().is_none_or(|evidence| {
            frame.sender().pubkey.as_bytes() != evidence.sender().pubkey.as_bytes()
                || evidence.sender().pubkey.as_bytes() != peer.signer_identity()
        })
    {
        return Err(SchcError::InvalidPeerEvidence);
    }
    match frame.destination_mode() {
        AddrMode::None | AddrMode::Elided => {}
        AddrMode::Extended if frame.destination() == link.local_eui64() => {}
        // LinkLayer does not yet retain an assigned local short address. Fail
        // closed rather than treating any authenticated two-byte destination
        // as local.
        AddrMode::Short | AddrMode::Extended => {
            return Err(SchcError::InvalidPeerEvidence);
        }
    }
    if l2_payload::classify(frame.payload()) != L2PayloadKind::Schc {
        return Err(SchcError::InvalidPacket("missing SCHC L2 dispatch"));
    }
    let body = l2_payload::body(frame.payload());
    match body.first().copied() {
        Some(RULE_ID_A_TO_B | RULE_ID_B_TO_A) => {
            return Err(SchcError::InvalidPacket(
                "fragmentation packets require authenticated reassembly",
            ));
        }
        Some(_) => {}
        None => return Err(SchcError::TooShort(lichen_core::error::TooShort::new(1, 0))),
    }
    // SECURITY: delayed in-window data must not use a newer DIO SCHC policy.
    let counter = (u32::from(frame.epoch()) << 16) | u32::from(u16::from(frame.seqnum()));
    if counter <= peer.authenticated_counter() {
        return Err(SchcError::InvalidPeerEvidence);
    }
    if frame.destination_mode() != AddrMode::Elided {
        return peer.decompress(body, out, single_frame_limit);
    }

    // Elided addressing is admitted from the authenticated inner IPv6
    // destination. Decode into bounded scratch so a foreign packet cannot
    // mutate caller-visible output before it is rejected.
    let mut decoded = [0u8; SCHC_MAX_DECOMPRESSED];
    let length = peer.decompress(body, &mut decoded, single_frame_limit)?;
    if !inner_destination_is_local_or_multicast(link, &decoded[..length]) {
        return Err(SchcError::InvalidPeerEvidence);
    }
    if out.len() < length {
        return Err(BufferTooSmall::new(length, out.len()).into());
    }
    out[..length].copy_from_slice(&decoded[..length]);
    Ok(length)
}

fn inner_destination_is_local_or_multicast(link: &LinkLayer, ipv6: &[u8]) -> bool {
    if ipv6.len() < 40 {
        return false;
    }
    let destination = &ipv6[24..40];
    if destination[0] == 0xff {
        return true;
    }

    let mut link_local = [0u8; 16];
    link_local[..2].copy_from_slice(&[0xfe, 0x80]);
    link_local[8..].copy_from_slice(&link.local_iid());
    let native = lichen_core::addr::ygg_addr_from_pubkey(link.local_public_key().as_bytes());
    destination == link_local || destination == native
}

/// Create the authenticated T=0 SCHC fragment sender for one peer.
pub fn create_fragment_sender<'a, 'policy, const MAX_PEERS: usize>(
    policy: &'policy FragmentationPolicy<MAX_PEERS>,
    permit: &AuthenticatedFragmentationPermit,
    link: &LinkLayer,
    peer: &AuthenticatedPeerSchcContext,
    payload: &'a [u8],
    receiver_limit: usize,
    now_ms: u64,
) -> Result<FragmentSender<'a, 'policy>, FragmentError> {
    let rule = *payload.first().ok_or(FragmentError::EmptyPacket)?;
    if rule > 7 && rule != RULE_UNCOMPRESSED {
        return Err(FragmentError::UnsupportedRule);
    }
    let mut ipv6 = [0u8; SCHC_MAX_DECOMPRESSED];
    let validated = if rule == RULE_UNCOMPRESSED {
        decode_rule255(payload, &mut ipv6, SCHC_FRAG_MAX_PACKET_SIZE).ok()
    } else {
        peer.decompress(payload, &mut ipv6, MAX_SINGLE_FRAME_SCHC_PACKET)
            .ok()
    };
    if validated.is_none() {
        return Err(FragmentError::InvalidPeerEvidence);
    }
    FragmentSender::new(policy, permit, link, peer, payload, receiver_limit, now_ms)
}

/// True when an extended unicast frame must carry this SCHC packet in fragments.
pub fn requires_fragmentation(schc: &[u8]) -> bool {
    schc.len() > MAX_SINGLE_FRAME_SCHC_PACKET
}

/// Wrap compressed SCHC and reject packets that exceed the single-frame ceiling.
pub fn wrap_unfragmented_schc<'a>(schc: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], SchcError> {
    if requires_fragmentation(schc) {
        return Err(SchcError::InvalidPacket(
            "SCHC packet requires authenticated fragmentation",
        ));
    }
    wrap_schc_payload(schc, out).map_err(SchcError::from)
}

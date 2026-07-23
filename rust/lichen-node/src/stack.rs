//! Full protocol stack: TX and RX paths, async radio handling.
//!
//! The `Stack` type owns the radio, link layer, and node state. It provides
//! async methods for sending CoAP requests and receiving frames.

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_core::addr::NodeId;
use lichen_core::constants::{L2_DISPATCH_SCHC, PORT_COAP};
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_hal::Radio;
use lichen_ipv6::{next_header, Addr, Ipv6Header, UdpHeader, IPV6_HEADER_LEN, UDP_HEADER_LEN};
use lichen_link::seqnum::LinkSeqNum;
use lichen_link::{frame::FrameError, link_layer::LinkRxError};
use lichen_schc::codec;
#[cfg(feature = "std")]
use lichen_rpl::routing::SourceRoutingHeader;

use crate::forward_buffer::{ForwardBuffer, ForwardError};
use crate::Node;

/// Maximum wire frame size (LoRa MTU with some headroom).
pub const MAX_FRAME_SIZE: usize = 255;
// 254-byte frame body minus fixed header, EUI-64 destination, 48-byte signature,
// and the L2 SCHC dispatch byte.
const MAX_EXTENDED_SCHC_SIZE: usize = 193;

/// TX path error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxError {
    /// CoAP message encoding failed.
    CoapEncode,
    /// SCHC compression failed.
    SchcCompress,
    /// Link layer frame encoding failed.
    FrameEncode,
    /// Radio transmission failed.
    RadioTx,
    /// Buffer too small for message.
    BufferTooSmall,
    /// Forwarding queue full for source — send NACK upstream.
    QueueFull,
    /// Every link-layer epoch/sequence tuple has been consumed.
    SequenceExhausted,
    /// No next hop is available for the destination.
    NoRoute,
    /// Plaintext CoAP is forbidden on the production transmit path.
    PlaintextCoap,
    /// IPv6 extension headers are unsupported by the production router.
    UnsupportedIpv6Extension,
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CoapEncode => write!(f, "CoAP encoding failed"),
            Self::SchcCompress => write!(f, "SCHC compression failed"),
            Self::FrameEncode => write!(f, "frame encoding failed"),
            Self::RadioTx => write!(f, "radio TX failed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::QueueFull => write!(f, "forwarding queue full"),
            Self::SequenceExhausted => write!(f, "link-layer sequence exhausted"),
            Self::NoRoute => write!(f, "no route to destination"),
            Self::PlaintextCoap => write!(f, "plaintext CoAP is forbidden"),
            Self::UnsupportedIpv6Extension => write!(f, "IPv6 extension header is unsupported"),
        }
    }
}

impl From<ForwardError> for TxError {
    fn from(e: ForwardError) -> Self {
        match e {
            ForwardError::QueueFull => TxError::QueueFull,
            ForwardError::NotFound => TxError::BufferTooSmall, // Shouldn't happen in TX path
        }
    }
}

impl core::error::Error for TxError {}

/// RX path error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RxError {
    /// Radio receive failed.
    RadioRx,
    /// Link layer error (signature, replay, key mismatch, etc.).
    Link(LinkRxError),
    /// SCHC decompression failed.
    SchcDecompress,
    /// Radio reported a packet larger than the supplied receive buffer.
    RadioPacketTooLarge,
    /// CoAP traffic was not protected with OSCORE.
    PlaintextCoap,
    /// OSCORE CoAP framing is malformed.
    MalformedSecureCoap,
    /// RPL source routing failed strict validation.
    InvalidSourceRoute,
    /// IPv6 Hop Limit was exhausted while forwarding.
    HopLimitExceeded,
    /// Timeout waiting for frame.
    Timeout,
}

impl core::fmt::Display for RxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RadioRx => write!(f, "radio RX failed"),
            Self::Link(e) => write!(f, "link error: {}", e),
            Self::SchcDecompress => write!(f, "SCHC decompression failed"),
            Self::RadioPacketTooLarge => write!(f, "radio packet exceeds receive buffer"),
            Self::PlaintextCoap => write!(f, "plaintext CoAP is forbidden"),
            Self::MalformedSecureCoap => write!(f, "malformed secure CoAP"),
            Self::InvalidSourceRoute => write!(f, "invalid RPL source route"),
            Self::HopLimitExceeded => write!(f, "IPv6 Hop Limit exceeded"),
            Self::Timeout => write!(f, "receive timeout"),
        }
    }
}

impl core::error::Error for RxError {}

impl From<LinkRxError> for RxError {
    fn from(e: LinkRxError) -> Self {
        RxError::Link(e)
    }
}

/// A fully processed received packet: authenticated, decompressed, with radio metadata.
///
/// This represents the output of the complete RX path through the stack:
/// 1. Radio reception (provides rssi/snr)
/// 2. Link-layer authentication (see [`lichen_link::link_layer::AuthenticatedFrame`])
/// 3. SCHC decompression (produces the full IPv6 packet)
///
/// The `ipv6` field contains a complete IPv6 packet ready for upper-layer processing.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ReceivedIpv6 {
    /// Decompressed IPv6 packet.
    pub ipv6: Vec<u8>,
    /// Sender IID (from authenticated link-layer identity).
    pub sender_iid: [u8; 8],
    /// RSSI in dBm (if radio provides it).
    pub rssi: Option<i16>,
    /// SNR in dB (if radio provides it).
    pub snr: Option<i8>,
}

/// Full protocol stack integrating radio, link layer, and node.
#[cfg(feature = "std")]
pub struct Stack<R: Radio> {
    radio: R,
    link: lichen_link::link_layer::LinkLayer,
    node: Node,
    /// SECURITY: Per spec section 4.4, epoch MUST be initialized to:
    /// - A persisted value (if available), OR
    /// - A random value in [128, 255] (if no persistence)
    epoch: u8,
    seqnum: LinkSeqNum,
    sequence_exhausted: bool,
    message_id: u16,
    /// Forwarding buffer with per-source backpressure (spec appendix-bufferbloat.md).
    forward_buffer: ForwardBuffer,
}

#[cfg(feature = "std")]
impl<R: Radio> Stack<R> {
    /// Create a new stack with the given radio, identity, and epoch.
    ///
    /// SECURITY: Per spec section 4.4, `epoch` MUST be:
    /// - Read from persisted storage (if available), OR
    /// - A random value uniformly distributed in [128, 255]
    ///
    /// # Panics
    ///
    /// Debug builds panic if `epoch < 128` to catch non-compliant initialization.
    pub fn new(radio: R, identity: lichen_link::identity::Identity, epoch: u8, seq: u16) -> Self {
        debug_assert!(
            epoch >= 128,
            "SECURITY: epoch MUST be in [128, 255] per spec section 4.4"
        );
        let mut eui64 = identity.iid;
        eui64[0] ^= 0x02;
        let node_id = NodeId(eui64);
        Self {
            radio,
            link: lichen_link::link_layer::LinkLayer::new(identity),
            node: Node::new(node_id),
            epoch,
            seqnum: LinkSeqNum::new(seq),
            message_id: 0,
            forward_buffer: ForwardBuffer::new(),
        }
    }

    /// Get the local node ID.
    pub fn node_id(&self) -> NodeId {
        self.node.node_id
    }

    /// Get the local IPv6 link-local address.
    pub fn local_addr(&self) -> Addr {
        Addr::link_local_from_eui64(&self.node.node_id.0)
    }

    pub fn local_public_key(&self) -> lichen_link::keys::PublicKey {
        self.link.local_public_key()
    }

    /// Add a peer for signature verification.
    pub fn add_peer(&mut self, peer: lichen_link::identity::PeerIdentity) {
        self.link.add_peer(peer);
    }

    /// Get the next message ID.
    pub fn next_message_id(&mut self) -> u16 {
        let mid = self.message_id;
        self.message_id = self.message_id.wrapping_add(1);
        mid
    }

    /// Allocate the next epoch and sequence tuple.
    pub fn try_next_link_tuple(&mut self) -> Result<(u8, LinkSeqNum), TxError> {
        if self.sequence_exhausted {
            return Err(TxError::SequenceExhausted);
        }

        let tuple = (self.epoch, self.seqnum);
        if self.epoch == u8::MAX && self.seqnum.get() == u16::MAX {
            self.sequence_exhausted = true;
        } else if self.seqnum.get() == u16::MAX {
            self.epoch += 1;
            self.seqnum = LinkSeqNum::new(0);
        } else {
            self.seqnum.fetch_increment();
        }
        Ok(tuple)
    }

    /// Send an OSCORE-protected CoAP message to destination.
    ///
    /// Path: CoAP → IPv6/UDP → SCHC compress → L2 sign → Radio TX
    pub(crate) async fn send_coap_raw(&mut self, dst: &Addr, coap: &[u8]) -> Result<(), TxError> {
        let src = self.local_addr();
        self.send_coap_raw_to(&src, dst, coap, &[], &[]).await
    }

        // Build IPv6 + UDP + CoAP packet
        let udp_total = UDP_HEADER_LEN + coap.len();
        let mut ipv6 = [0u8; 256];

        // IPv6 header (payload_len = UDP datagram size)
        let ip_hdr = Ipv6Header::new(next_header::UDP, src, *dst);
        ip_hdr
            .write_to(udp_total as u16, &mut ipv6[..IPV6_HEADER_LEN])
            .map_err(|_| TxError::BufferTooSmall)?;

        // UDP datagram (preferred write_packet_to ensures payload placed before checksum use)
        let udp_hdr = UdpHeader::new(PORT_COAP, PORT_COAP);
        udp_hdr
            .write_packet_to(
                &src,
                dst,
                coap,
                &mut ipv6[IPV6_HEADER_LEN..IPV6_HEADER_LEN + udp_total],
            )
            .map_err(|_| TxError::BufferTooSmall)?;

        let ipv6_len = IPV6_HEADER_LEN + udp_total;

        let mut routed = [0u8; 512];
        let ipv6 = if source_route.len() > 1 {
            let routed_len = add_rpl_source_route(&ipv6[..ipv6_len], source_route, &mut routed)?;
            &routed[..routed_len]
        } else {
            &ipv6[..ipv6_len]
        };

        // SCHC compress
        let mut schc = [0u8; 200];
        let schc_len = codec::compress(ipv6, &mut schc).map_err(|_| TxError::SchcCompress)?;

        let mut l2_payload = [0u8; 201];
        let l2_data = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        // L2 sign and frame
        let (epoch, seqnum) = self.try_next_link_tuple()?;
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let wire_len = self
            .link
            .build_frame(self.epoch, seqnum, &[], l2_data, &mut wire)
            .map_err(|e| match e {
                FrameError::BufferTooSmall => TxError::BufferTooSmall,
                _ => TxError::FrameEncode,
            })?;

        // Radio TX
        self.radio
            .transmit(&wire[..wire_len])
            .await
            .map_err(|_| TxError::RadioTx)?;

        Ok(())
    }

    /// Send a raw IPv6 packet (already constructed).
    ///
    /// Path: IPv6 → SCHC compress → L2 sign → Radio TX
    pub async fn send_ipv6_raw(&mut self, ipv6: &[u8]) -> Result<(), TxError> {
        self.send_ipv6_to(ipv6, &[]).await
    }

    pub(crate) async fn send_ipv6_to(
        &mut self,
        ipv6: &[u8],
        dst_addr: &[u8],
    ) -> Result<(), TxError> {
        let mut schc = [0u8; 200];
        let schc_len = codec::compress(ipv6, &mut schc).map_err(|_| TxError::SchcCompress)?;
        let mut l2_payload = [0u8; 201];
        let l2_data = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        self.send_l2_payload_to(l2_data, dst_addr).await
    }

    pub(crate) async fn send_ipv6_to_route(
        &mut self,
        ipv6: &[u8],
        dst_addr: &[u8],
        source_route: &[[u8; 16]],
    ) -> Result<(), TxError> {
        if source_route.len() <= 1 {
            return self.send_ipv6_to(ipv6, dst_addr).await;
        }
        let mut routed = [0u8; 512];
        let routed_len = add_rpl_source_route(ipv6, source_route, &mut routed)?;
        self.send_ipv6_to(&routed[..routed_len], dst_addr).await
    }

    pub(crate) async fn send_l2_payload_to(
        &mut self,
        l2_payload: &[u8],
        dst_addr: &[u8],
    ) -> Result<(), TxError> {
        let max_payload = if dst_addr.len() == 8 {
            MAX_EXTENDED_SCHC_SIZE + 1
        } else {
            202
        };
        if l2_payload.len() > max_payload {
            return Err(TxError::FrameEncode);
        }
        let (epoch, seqnum) = self.try_next_link_tuple()?;
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let wire_len = self
            .link
            .build_frame(self.epoch, seqnum, &[], l2_data, &mut wire)
            .map_err(|e| match e {
                FrameError::BufferTooSmall => TxError::BufferTooSmall,
                _ => TxError::FrameEncode,
            })?;

        self.radio
            .transmit(&wire[..wire_len])
            .await
            .map_err(|_| TxError::RadioTx)?;

        Ok(())
    }

    /// Receive a frame with timeout.
    ///
    /// Path: Radio RX → L2 verify → SCHC decompress → IPv6
    pub async fn receive(&mut self, timeout_ms: u32) -> Result<Option<ReceivedIpv6>, RxError> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let rx = self
            .radio
            .receive(&mut buf, timeout_ms)
            .await
            .map_err(|_| RxError::RadioRx)?;

        let Some(pkt) = rx else {
            return Ok(None);
        };
        if pkt.len > buf.len() {
            return Err(RxError::RadioPacketTooLarge);
        }

        let wire = &buf[..pkt.len];
        let l2 = self.link.receive_frame(wire)?;

        if classify_l2_payload(&l2.payload) != L2PayloadKind::Schc {
            return Err(RxError::SchcDecompress);
        }

        let mut ipv6 = vec![0u8; 256];
        let n = codec::decompress(l2_payload_body(&l2.payload), &mut ipv6)
            .map_err(|_| RxError::SchcDecompress)?;
        ipv6.truncate(n);

        Ok(Some(ReceivedIpv6 {
            ipv6,
            sender_iid: l2.sender.iid,
            rssi: pkt.rssi,
            snr: pkt.snr,
        }))
    }

    /// Handle a received frame and generate a reply if applicable.
    ///
    /// For ICMPv6 Echo Requests, automatically sends Echo Reply.
    pub async fn handle_and_reply(&mut self, frame: &ReceivedIpv6) -> Result<bool, TxError> {
        let mut reply_ipv6 = [0u8; 256];
        let reply_len = self.node.handle_ipv6(&frame.ipv6, &mut reply_ipv6);

        if reply_len > 0 {
            self.send_ipv6_raw(&reply_ipv6[..reply_len]).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Run the receive loop, handling incoming frames.
    ///
    /// Calls the provided callback for each received frame. Returns when
    /// the callback returns `false` or on error.
    pub async fn run<F>(&mut self, mut callback: F) -> Result<(), RxError>
    where
        F: FnMut(&ReceivedIpv6) -> bool,
    {
        loop {
            match self.receive(1000).await? {
                Some(frame) => {
                    // Try to auto-reply (e.g., ping)
                    let _ = self.handle_and_reply(&frame).await;
                    if !callback(&frame) {
                        break;
                    }
                }
                None => {
                    // Timeout, keep listening
                }
            }
        }
        Ok(())
    }

    /// Access the underlying radio.
    pub fn radio(&mut self) -> &mut R {
        &mut self.radio
    }

    /// Internal authenticated-link access for the production RPL owner.
    pub(crate) fn link(&mut self) -> &mut lichen_link::link_layer::LinkLayer {
        &mut self.link
    }

    /// Access the node state.
    pub fn node(&self) -> &Node {
        &self.node
    }

    // --- Forwarding Buffer API (spec appendix-bufferbloat.md) ---

    /// Queue a packet for forwarding with backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::QueueFull`] if the source already has
    /// `MAX_PACKETS_PER_SOURCE` packets queued. The caller SHOULD send
    /// a NACK upstream when this occurs.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IPv6 packet to forward
    /// * `source_iid` - 8-byte Interface Identifier of the original sender
    /// * `now_ms` - Current monotonic time in milliseconds
    /// * `deadline_ms` - Optional deadline; packets past deadline are dropped
    /// * `priority` - Priority level (0=highest, 3=lowest per spec)
    pub fn queue_forward(
        &mut self,
        packet: Vec<u8>,
        source_iid: [u8; 8],
        now_ms: u32,
        deadline_ms: Option<u32>,
        priority: u8,
    ) -> Result<(), TxError> {
        self.forward_buffer
            .queue(packet, source_iid, now_ms, deadline_ms, priority)
            .map_err(TxError::from)
    }

    /// Transmit the highest-priority queued forwarding packet.
    ///
    /// Returns `true` if a packet was transmitted, `false` if the buffer was empty.
    pub async fn transmit_forward(&mut self, now_ms: u32) -> Result<bool, TxError> {
        let Some(entry) = self.forward_buffer.dequeue(now_ms) else {
            return Ok(false);
        };

        self.send_ipv6_raw(&entry.packet).await?;
        Ok(true)
    }

    /// Check how many packets are queued for a specific source.
    pub fn forward_count_for_source(&self, source_iid: &[u8; 8]) -> usize {
        self.forward_buffer.count_for_source(source_iid)
    }

    /// Get forwarding buffer statistics.
    pub fn forward_stats(&self) -> crate::forward_buffer::ForwardStats {
        self.forward_buffer.stats()
    }

    /// Expire old packets from the forwarding buffer.
    ///
    /// Call this periodically to clean up packets past their deadline.
    pub fn expire_forwards(&mut self, now_ms: u32) -> usize {
        self.forward_buffer.expire(now_ms)
    }

    /// Clear all forwarding packets for a source (e.g., on link failure).
    pub fn clear_forward_source(&mut self, source_iid: &[u8; 8]) -> usize {
        self.forward_buffer.clear_source(source_iid)
    }

    /// Access the forwarding buffer directly for advanced operations.
    pub fn forward_buffer(&mut self) -> &mut ForwardBuffer {
        &mut self.forward_buffer
    }
}

pub fn add_rpl_source_route(
    ipv6: &[u8],
    route: &[[u8; 16]],
    out: &mut [u8],
) -> Result<usize, TxError> {
    let remaining = route.len().checked_sub(1).ok_or(TxError::NoRoute)?;
    if remaining == 0 || remaining > u8::MAX as usize {
        return Err(TxError::NoRoute);
    }
    let routing_len = 8usize
        .checked_add(remaining.checked_mul(16).ok_or(TxError::BufferTooSmall)?)
        .ok_or(TxError::BufferTooSmall)?;
    let total_len = ipv6
        .len()
        .checked_add(routing_len)
        .ok_or(TxError::BufferTooSmall)?;
    if ipv6.len() < IPV6_HEADER_LEN || total_len > out.len() {
        return Err(TxError::BufferTooSmall);
    }
    let payload_len = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let routed_payload_len = payload_len
        .checked_add(routing_len)
        .and_then(|len| u16::try_from(len).ok())
        .ok_or(TxError::BufferTooSmall)?;

    out[..IPV6_HEADER_LEN].copy_from_slice(&ipv6[..IPV6_HEADER_LEN]);
    out[4..6].copy_from_slice(&routed_payload_len.to_be_bytes());
    let transport = out[6];
    out[6] = 43;
    out[24..40].copy_from_slice(&route[0]);
    out[40] = transport;
    out[41] = (routing_len / 8 - 1) as u8;
    #[cfg(feature = "std")]
    {
        let srh = SourceRoutingHeader {
            segments_left: remaining as u8,
            addresses: route[1..].to_vec(),
        };
        let _ = srh.write_to(&mut out[42..]).map_err(|_| TxError::BufferTooSmall)?;
    }
    #[cfg(not(feature = "std"))]
    {
        out[42] = 3;
        out[43] = remaining as u8;
        out[44..48].fill(0);
        for (index, address) in route[1..].iter().enumerate() {
            let start = 48 + index * 16;
            out[start..start + 16].copy_from_slice(address);
        }
    }
    out[IPV6_HEADER_LEN + routing_len..total_len].copy_from_slice(&ipv6[IPV6_HEADER_LEN..]);
    Ok(total_len)
}

fn wrap_schc_payload<'a>(schc: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], TxError> {
    if out.len() < schc.len() + 1 {
        return Err(TxError::BufferTooSmall);
    }
    out[0] = L2_DISPATCH_SCHC;
    out[1..1 + schc.len()].copy_from_slice(schc);
    Ok(&out[..1 + schc.len()])
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use lichen_hal::loopback::LoopbackRadio;
    use lichen_link::identity::{Identity, PeerIdentity};
    use lichen_link::Seed;

    // NOTE: CoAP tests use SecureStack (see secure.rs::secure_stack_oscore_roundtrip).
    // Per spec section 8.7, all CoAP traffic MUST use OSCORE encryption.
    // The plaintext Stack is only for ICMPv6 and diagnostics.

    fn test_stack(epoch: u8) -> Stack<LoopbackRadio> {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let (radio, _) = LoopbackRadio::pair();
        Stack::new(radio, identity, epoch)
    }

    #[test]
    fn link_tuple_rollover_advances_epoch() {
        let mut stack = test_stack(128);
        stack.seqnum = LinkSeqNum::new(u16::MAX);

        assert_eq!(
            stack.try_next_link_tuple(),
            Ok((128, LinkSeqNum::new(u16::MAX)))
        );
        assert_eq!(stack.try_next_link_tuple(), Ok((129, LinkSeqNum::new(0))));
    }

    #[test]
    fn terminal_link_tuple_is_allocated_once() {
        let mut stack = test_stack(u8::MAX);
        stack.seqnum = LinkSeqNum::new(u16::MAX);

        assert_eq!(
            stack.try_next_link_tuple(),
            Ok((u8::MAX, LinkSeqNum::new(u16::MAX)))
        );
        assert_eq!(stack.try_next_link_tuple(), Err(TxError::SequenceExhausted));
        assert_eq!(stack.try_next_link_tuple(), Err(TxError::SequenceExhausted));
    }

    /// ICMPv6 ping-pong test using plaintext Stack.
    ///
    /// SECURITY: This uses plaintext Stack because OSCORE (RFC 8613) is CoAP-specific.
    /// ICMPv6 does not use OSCORE, so plaintext Stack is appropriate here.
    /// For CoAP traffic, use SecureStack per spec section 8.7.
    #[tokio::test]
    async fn stack_ping_pong() {
        let alice_id = Identity::from_seed(Seed::new([0x01; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x02; 32]));
        let alice_iid = alice_id.iid;
        let bob_iid = bob_id.iid;

        let alice_peer = PeerIdentity::from_pubkey(alice_id.pubkey);
        let bob_peer = PeerIdentity::from_pubkey(bob_id.pubkey);

        let (radio_a, radio_b) = LoopbackRadio::pair();

        let mut alice = Stack::new(radio_a, alice_id, 128, 0);
        alice.add_peer(bob_peer);

        let mut bob = Stack::new(radio_b, bob_id, 128, 0);
        bob.add_peer(alice_peer);

        // Build and send ICMPv6 Echo Request from Alice to Bob
        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();
        assert_eq!(&alice_addr.0[8..], &alice_iid);
        assert_eq!(&bob_addr.0[8..], &bob_iid);

        let echo = lichen_ipv6::Icmpv6Echo { id: 42, seq: 1 };
        let icmp = echo.build_request(&alice_addr, &bob_addr, b"ping").unwrap();
        let ip_hdr = Ipv6Header::new(next_header::ICMPV6, alice_addr, bob_addr);
        let mut ipv6 = vec![0u8; IPV6_HEADER_LEN];
        ip_hdr
            .write_to(icmp.len() as u16, &mut ipv6[..IPV6_HEADER_LEN])
            .unwrap();
        ipv6.extend_from_slice(&icmp);

        alice.send_ipv6_raw(&ipv6).await.unwrap();

        // Bob receives and auto-replies
        let frame = bob.receive(1000).await.unwrap().unwrap();
        let replied = bob.handle_and_reply(&frame).await.unwrap();
        assert!(replied, "Bob should reply to ping");

        // Alice receives reply
        let reply = alice.receive(1000).await.unwrap().unwrap();
        assert_eq!(reply.ipv6[40], 129); // ICMPv6 Echo Reply
    }

    #[tokio::test]
    async fn raw_coap_rejects_payload_beyond_ipv6_buffer() {
        let mut stack = test_stack(128);
        let dst = stack.local_addr();
        let coap = [0u8; 209];

        assert_ne!(
            stack.send_coap_raw(&dst, &coap[..208]).await,
            Err(TxError::BufferTooSmall)
        );
        let tuple_state = (stack.epoch, stack.seqnum, stack.sequence_exhausted);
        assert_eq!(
            stack.send_coap_raw(&dst, &coap).await,
            Err(TxError::BufferTooSmall)
        );
        assert_eq!(
            (stack.epoch, stack.seqnum, stack.sequence_exhausted),
            tuple_state
        );
    }
}

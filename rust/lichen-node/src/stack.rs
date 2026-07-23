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

use lichen_coap::codec::CoapBuilder;
use lichen_coap::message::{MessageCode, MessageType};
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

use crate::forward_buffer::{ForwardBuffer, ForwardError};
use crate::Node;

/// Maximum wire frame size (LoRa MTU with some headroom).
pub const MAX_FRAME_SIZE: usize = 255;

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
    /// Timeout waiting for frame.
    Timeout,
}

impl core::fmt::Display for RxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RadioRx => write!(f, "radio RX failed"),
            Self::Link(e) => write!(f, "link error: {}", e),
            Self::SchcDecompress => write!(f, "SCHC decompression failed"),
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
        let node_id = NodeId(identity.iid);
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

    /// Get the next sequence number.
    pub fn next_seqnum(&mut self) -> LinkSeqNum {
        self.seqnum.fetch_increment()
    }

    /// Set the epoch counter (for reboot resilience).
    ///
    /// Callers with persisted epoch should call this after construction.
    /// Without persistence, callers should pass a random value in [128, 255]
    /// so half-space replay arithmetic treats new frames as "ahead" of stale
    /// receiver windows.
    pub fn set_epoch(&mut self, epoch: u8) {
        self.epoch = epoch;
    }

    /// Build and send a CoAP request.
    ///
    /// Common helper for GET/POST/PUT. Returns the message ID for matching responses.
    async fn send_coap_request(
        &mut self,
        dst: &Addr,
        method: MessageCode,
        uri_path: &[&str],
        token: &[u8],
        content_format: Option<u16>,
        payload: Option<&[u8]>,
    ) -> Result<u16, TxError> {
        let mid = self.next_message_id();
        let mut coap = [0u8; 192];
        let mut builder = CoapBuilder::new(&mut coap, MessageType::Confirmable, method, mid, token)
            .map_err(|_| TxError::CoapEncode)?;
        for seg in uri_path {
            builder.uri_path(seg).map_err(|_| TxError::CoapEncode)?;
        }
        if let Some(cf) = content_format {
            builder
                .content_format(cf)
                .map_err(|_| TxError::CoapEncode)?;
        }
        if let Some(p) = payload {
            builder.payload(p).map_err(|_| TxError::CoapEncode)?;
        }
        let coap_len = builder.finish();

        self.send_coap_raw(dst, &coap[..coap_len]).await?;
        Ok(mid)
    }

    /// Build a CoAP GET request and transmit it.
    ///
    /// Returns the message ID for matching responses.
    pub async fn send_get(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
    ) -> Result<u16, TxError> {
        self.send_coap_request(dst, MessageCode::GET, uri_path, token, None, None)
            .await
    }

    /// Build a CoAP POST request and transmit it.
    ///
    /// Returns the message ID for matching responses.
    pub async fn send_post(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
        content_format: Option<u16>,
        payload: &[u8],
    ) -> Result<u16, TxError> {
        self.send_coap_request(
            dst,
            MessageCode::POST,
            uri_path,
            token,
            content_format,
            Some(payload),
        )
        .await
    }

    /// Build a CoAP PUT request and transmit it.
    ///
    /// Returns the message ID for matching responses.
    pub async fn send_put(
        &mut self,
        dst: &Addr,
        uri_path: &[&str],
        token: &[u8],
        content_format: Option<u16>,
        payload: &[u8],
    ) -> Result<u16, TxError> {
        self.send_coap_request(
            dst,
            MessageCode::PUT,
            uri_path,
            token,
            content_format,
            Some(payload),
        )
        .await
    }

    /// Send a raw CoAP message to destination.
    ///
    /// Path: CoAP → IPv6/UDP → SCHC compress → L2 sign → Radio TX
    pub async fn send_coap_raw(&mut self, dst: &Addr, coap: &[u8]) -> Result<(), TxError> {
        let src = self.local_addr();

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

        // SCHC compress
        let mut schc = [0u8; 200];
        let schc_len =
            codec::compress(&ipv6[..ipv6_len], &mut schc).map_err(|_| TxError::SchcCompress)?;

        let mut l2_payload = [0u8; 201];
        let l2_data = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        // L2 sign and frame
        let seqnum = self.next_seqnum();
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
        let mut schc = [0u8; 200];
        let schc_len = codec::compress(ipv6, &mut schc).map_err(|_| TxError::SchcCompress)?;
        let mut l2_payload = [0u8; 201];
        let l2_data = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        let seqnum = self.next_seqnum();
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

    /// Access the link layer.
    pub fn link(&mut self) -> &mut lichen_link::link_layer::LinkLayer {
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

    /// ICMPv6 ping-pong test using plaintext Stack.
    ///
    /// SECURITY: This uses plaintext Stack because OSCORE (RFC 8613) is CoAP-specific.
    /// ICMPv6 does not use OSCORE, so plaintext Stack is appropriate here.
    /// For CoAP traffic, use SecureStack per spec section 8.7.
    #[tokio::test]
    async fn stack_ping_pong() {
        let alice_id = Identity::from_seed(Seed::new([0x01; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x02; 32]));

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
}

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
use lichen_ipv6::{next_header, Addr, Ipv6Header, IPV6_HEADER_LEN, UDP_HEADER_LEN};
use lichen_link::link_layer::LinkRxError;
use lichen_link::seqnum::LinkSeqNum;
use lichen_schc::codec;

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
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CoapEncode => write!(f, "CoAP encoding failed"),
            Self::SchcCompress => write!(f, "SCHC compression failed"),
            Self::FrameEncode => write!(f, "frame encoding failed"),
            Self::RadioTx => write!(f, "radio TX failed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
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
    epoch: u8,
    seqnum: LinkSeqNum,
    message_id: u16,
}

#[cfg(feature = "std")]
impl<R: Radio> Stack<R> {
    /// Create a new stack with the given radio and identity.
    pub fn new(radio: R, identity: lichen_link::identity::Identity) -> Self {
        let node_id = NodeId(identity.iid);
        Self {
            radio,
            link: lichen_link::link_layer::LinkLayer::new(identity),
            node: Node::new(node_id),
            epoch: 0,
            seqnum: LinkSeqNum::new(0),
            message_id: 0,
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

        // Build IPv6/UDP packet
        let udp_len = (UDP_HEADER_LEN + coap.len()) as u16;
        let mut ipv6 = [0u8; 256];
        let ip_hdr = Ipv6Header::new(next_header::UDP, src, *dst);
        ip_hdr
            .write_to(udp_len, &mut ipv6[..IPV6_HEADER_LEN])
            .map_err(|_| TxError::BufferTooSmall)?;

        // UDP header: src_port, dst_port, length, checksum
        let src_port = PORT_COAP;
        let dst_port = PORT_COAP;
        ipv6[40..42].copy_from_slice(&src_port.to_be_bytes());
        ipv6[42..44].copy_from_slice(&dst_port.to_be_bytes());
        ipv6[44..46].copy_from_slice(&udp_len.to_be_bytes());
        // Checksum computed by SCHC or set to zero (CoAP over UDP allows it)
        let cksum = udp_checksum(&src.0, &dst.0, src_port, dst_port, coap);
        ipv6[46..48].copy_from_slice(&cksum.to_be_bytes());

        // CoAP payload
        let ipv6_len = IPV6_HEADER_LEN + UDP_HEADER_LEN + coap.len();
        ipv6[48..ipv6_len].copy_from_slice(coap);

        // SCHC compress
        let mut schc = [0u8; 200];
        let schc_len =
            codec::compress(&ipv6[..ipv6_len], &mut schc).map_err(|_| TxError::SchcCompress)?;

        let mut l2_payload = [0u8; 201];
        let l2_payload_len = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        // L2 sign and frame
        let seqnum = self.next_seqnum();
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let wire_len = self
            .link
            .build_frame(self.epoch, seqnum, &[], l2_payload_len, &mut wire)
            .map_err(|_| TxError::FrameEncode)?;

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
        let l2_payload_len = wrap_schc_payload(&schc[..schc_len], &mut l2_payload)?;

        let seqnum = self.next_seqnum();
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let wire_len = self
            .link
            .build_frame(self.epoch, seqnum, &[], l2_payload_len, &mut wire)
            .map_err(|_| TxError::FrameEncode)?;

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
            snr: pkt.snr.map(|s| s as i8),
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
}

/// Compute UDP checksum over pseudo-header and payload.
fn udp_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> u16 {
    let udp_len = (8 + payload.len()) as u16;
    let mut sum = pseudo_sum(src, dst, 17, udp_len);
    sum = oc_add(sum, src_port as u32);
    sum = oc_add(sum, dst_port as u32);
    sum = oc_add(sum, udp_len as u32);
    sum = oc_add(sum, checksum_bytes(payload));
    finalize(sum)
}

fn oc_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >> 16 != 0 {
        (s & 0xFFFF) + (s >> 16)
    } else {
        s
    }
}

fn checksum_bytes(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let chunks = data.chunks_exact(2);
    let remainder = chunks.remainder();
    for pair in chunks {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    if let Some(&last) = remainder.first() {
        sum = oc_add(sum, (last as u32) << 8);
    }
    sum
}

fn pseudo_sum(src: &[u8], dst: &[u8], next_header: u8, length: u16) -> u32 {
    let mut sum: u32 = 0;
    for pair in src.chunks_exact(2) {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    for pair in dst.chunks_exact(2) {
        sum = oc_add(sum, u16::from_be_bytes([pair[0], pair[1]]) as u32);
    }
    sum = oc_add(sum, length as u32);
    oc_add(sum, next_header as u32)
}

fn finalize(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
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

    #[tokio::test]
    async fn stack_send_get_loopback() {
        let alice_id = Identity::from_seed(Seed::new([0x01; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x02; 32]));

        let alice_pubkey = alice_id.pubkey;
        let bob_pubkey = bob_id.pubkey;

        let alice_peer = PeerIdentity::from_pubkey(alice_pubkey);
        let bob_peer = PeerIdentity::from_pubkey(bob_pubkey);

        let (radio_a, radio_b) = LoopbackRadio::pair();

        let mut alice = Stack::new(radio_a, alice_id);
        alice.add_peer(bob_peer);

        let mut bob = Stack::new(radio_b, bob_id);
        bob.add_peer(alice_peer);

        let bob_addr = bob.local_addr();

        // Alice sends GET /test to Bob
        let _mid = alice.send_get(&bob_addr, &["test"], &[0xAB]).await.unwrap();

        // Bob receives
        let frame = bob.receive(1000).await.unwrap().unwrap();
        assert!(frame.ipv6.len() >= 40);
        assert_eq!(frame.ipv6[6], next_header::UDP);
    }

    #[tokio::test]
    async fn stack_ping_pong() {
        let alice_id = Identity::from_seed(Seed::new([0x01; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x02; 32]));

        let alice_peer = PeerIdentity::from_pubkey(alice_id.pubkey);
        let bob_peer = PeerIdentity::from_pubkey(bob_id.pubkey);

        let (radio_a, radio_b) = LoopbackRadio::pair();

        let mut alice = Stack::new(radio_a, alice_id);
        alice.add_peer(bob_peer);

        let mut bob = Stack::new(radio_b, bob_id);
        bob.add_peer(alice_peer);

        // Build and send ICMPv6 Echo Request from Alice to Bob
        let alice_addr = alice.local_addr();
        let bob_addr = bob.local_addr();

        let echo = lichen_ipv6::Icmpv6Echo { id: 42, seq: 1 };
        let icmp = echo.build_request(&alice_addr, &bob_addr, b"ping");
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

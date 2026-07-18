//! OSCORE-protected stack: end-to-end encrypted CoAP.
//!
//! Wraps the Stack with OSCORE security contexts for encrypted communication.

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_coap::codec::{CoapBuilder, CoapPacket, MAX_TOKEN_LEN};
use lichen_coap::message::{MessageCode, MessageType};
use lichen_core::constants::PORT_COAP;
use lichen_hal::Radio;
use lichen_ipv6::{next_header, Addr, Ipv6Header, UdpHeader, IPV6_HEADER_LEN, UDP_HEADER_LEN};
use lichen_link::identity::PeerIdentity;
use lichen_oscore::{
    validate_option, Context, ContextId, ContextStoreError, OscoreError, ReservationError,
    SenderStateStore, COAP_OPTION_OSCORE, PIV_MAX_LEN,
};

use crate::stack::{ReceivedIpv6, RxError, Stack, TxError};
use lichen_core::addr::NodeId;

/// OSCORE option number.
const OSCORE_OPTION: u16 = COAP_OPTION_OSCORE;

/// Secure stack error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecureError {
    /// Link-layer epoch is outside the compliant range 128..=255.
    InvalidEpoch,
    /// No OSCORE context for peer.
    NoContext,
    /// OSCORE encryption failed.
    EncryptFailed,
    /// OSCORE sender sequence is exhausted; rotate the context before retrying.
    ContextExhausted,
    /// Another context owner reserved this sender sequence first.
    ReservationConflict,
    /// Persisting the sender-sequence reservation failed.
    PersistenceFailed,
    /// OSCORE decryption failed.
    DecryptFailed,
    /// Response type, MID, token, or OSCORE context does not match the request.
    CorrelationMismatch,
    /// CoAP encoding error.
    CoapEncode,
    /// TX error from underlying stack.
    Tx(TxError),
}

impl core::fmt::Display for SecureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEpoch => write!(f, "link-layer epoch must be in 128..=255"),
            Self::NoContext => write!(f, "no OSCORE context for peer"),
            Self::EncryptFailed => write!(f, "OSCORE encryption failed"),
            Self::ContextExhausted => {
                write!(f, "OSCORE context exhausted; key rotation required")
            }
            Self::ReservationConflict => write!(f, "sender-sequence reservation conflict"),
            Self::PersistenceFailed => write!(f, "sender-sequence persistence failed"),
            Self::DecryptFailed => write!(f, "OSCORE decryption failed"),
            Self::CorrelationMismatch => write!(f, "response correlation mismatch"),
            Self::CoapEncode => write!(f, "CoAP encoding failed"),
            Self::Tx(e) => write!(f, "TX error: {}", e),
        }
    }
}

impl core::error::Error for SecureError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tx(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TxError> for SecureError {
    fn from(e: TxError) -> Self {
        SecureError::Tx(e)
    }
}

fn map_protect_error(error: OscoreError) -> SecureError {
    match error {
        OscoreError::SeqExhausted => SecureError::ContextExhausted,
        _ => SecureError::EncryptFailed,
    }
}

fn map_context_store_error<E>(error: ContextStoreError<E>) -> SecureError {
    match error {
        ContextStoreError::Missing => SecureError::NoContext,
        ContextStoreError::Conflict => SecureError::ReservationConflict,
        ContextStoreError::Storage(_) => SecureError::PersistenceFailed,
        ContextStoreError::Oscore(_) => SecureError::NoContext,
    }
}

/// Correlation state required to authenticate a response to one request.
#[derive(Debug, PartialEq, Eq)]
pub struct RequestCorrelation {
    /// CoAP Message ID of the request.
    message_id: u16,
    token: [u8; MAX_TOKEN_LEN],
    token_len: u8,
    request_piv: [u8; PIV_MAX_LEN],
    request_piv_len: u8,
    context_id: ContextId,
    destination_peer_iid: [u8; 8],
    completed: bool,
}

/// Result of processing a response correlated to a secure request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureResponse {
    /// An empty ACK accepted the confirmable request; a separate response may follow.
    Acknowledged,
    /// The authenticated OSCORE response body.
    Decrypted {
        /// Inner CoAP response code.
        code: MessageCode,
        /// Decrypted Class E options.
        options: Vec<u8>,
        /// Decrypted payload.
        payload: Vec<u8>,
    },
}

/// An authenticated, structurally validated secure CoAP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSecureDatagram {
    coap: Vec<u8>,
    sender_iid: [u8; 8],
    rssi: Option<i16>,
    snr: Option<i8>,
}

impl ReceivedSecureDatagram {
    /// Complete protected CoAP datagram or exact empty ACK.
    pub fn coap(&self) -> &[u8] {
        &self.coap
    }

    /// Sender IID from the authenticated link-layer identity.
    pub fn sender_iid(&self) -> [u8; 8] {
        self.sender_iid
    }

    /// RSSI in dBm, when reported by the radio.
    pub fn rssi(&self) -> Option<i16> {
        self.rssi
    }

    /// SNR in dB, when reported by the radio.
    pub fn snr(&self) -> Option<i8> {
        self.snr
    }
}

/// Decrypted OSCORE request from an authenticated link-layer peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRequest {
    /// Inner CoAP request code.
    pub code: MessageCode,
    /// Decrypted Class E options.
    pub options: Vec<u8>,
    /// Decrypted payload.
    pub payload: Vec<u8>,
    /// Sender IID from the authenticated link-layer identity.
    pub sender_iid: [u8; 8],
}

impl RequestCorrelation {
    /// CoAP Message ID of the request.
    pub fn message_id(&self) -> u16 {
        self.message_id
    }

    /// Canonical request token.
    pub fn token(&self) -> &[u8] {
        &self.token[..self.token_len as usize]
    }

    /// Canonical request Partial IV.
    pub fn request_piv(&self) -> &[u8] {
        &self.request_piv[..self.request_piv_len as usize]
    }

    /// Directional OSCORE context identity used by the request.
    pub fn context_id(&self) -> ContextId {
        self.context_id
    }
}

/// OSCORE-protected stack.
#[cfg(feature = "std")]
pub struct SecureStack<R: Radio> {
    stack: Stack<R>,
    /// OSCORE contexts keyed by peer IID.
    contexts: HashMap<[u8; 8], Context>,
}

#[cfg(feature = "std")]
impl<R: Radio> SecureStack<R> {
    /// Create a new secure stack.
    pub(crate) fn new(stack: Stack<R>) -> Self {
        Self {
            stack,
            contexts: HashMap::new(),
        }
    }

    /// Enroll a peer for link-layer signature verification.
    pub fn add_peer(&mut self, peer: PeerIdentity) {
        self.stack.add_peer(peer);
    }

    /// Create from radio and identity with a persisted or random compliant epoch.
    ///
    /// Returns [`SecureError::InvalidEpoch`] when `epoch` is below 128.
    pub fn from_radio(
        radio: R,
        identity: lichen_link::identity::Identity,
        epoch: u8,
    ) -> Result<Self, SecureError> {
        if epoch < 128 {
            return Err(SecureError::InvalidEpoch);
        }
        Ok(Self::new(Stack::new(radio, identity, epoch)))
    }

    /// Atomically register and install a newly established OSCORE context.
    pub fn register_fresh_context<S: SenderStateStore>(
        &mut self,
        peer_iid: [u8; 8],
        context: Context,
        store: &mut S,
    ) -> Result<(), SecureError> {
        let context = context
            .register_fresh(store)
            .map_err(map_context_store_error)?;
        self.contexts.insert(peer_iid, context);
        Ok(())
    }

    /// Restore authoritative sender state and install an existing OSCORE context.
    pub fn restore_context<S: SenderStateStore>(
        &mut self,
        peer_iid: [u8; 8],
        context: Context,
        store: &mut S,
    ) -> Result<(), SecureError> {
        let context = context
            .restore_existing(store)
            .map_err(map_context_store_error)?;
        self.contexts.insert(peer_iid, context);
        Ok(())
    }

    /// Get mutable context for peer.
    fn get_context_mut(&mut self, peer_iid: &[u8; 8]) -> Option<&mut Context> {
        self.contexts.get_mut(peer_iid)
    }

    /// Get local address.
    pub fn local_addr(&self) -> Addr {
        self.stack.local_addr()
    }

    /// Get local node ID.
    pub fn node_id(&self) -> NodeId {
        self.stack.node_id()
    }

    /// Send an OSCORE-protected GET after atomically reserving its sender sequence.
    pub async fn send_secure_get<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(SecureError::CoapEncode);
        }
        let ctx = self
            .get_context_mut(peer_iid)
            .ok_or(SecureError::NoContext)?;

        // Build inner CoAP (will be encrypted)
        // Inner message: code + Uri-Path options (class E)
        let mut class_e = [0u8; 256];
        let mut class_e_len = 0;

        // Encode Uri-Path options using CoAP delta encoding (RFC 7252 section 3.1).
        // Option delta = current_option_number - previous_option_number.
        // First Uri-Path (option 11): delta = 11 - 0 = 11.
        // Subsequent Uri-Path options: delta = 11 - 11 = 0 (same option number repeats).
        // Length < 13: fits in 4-bit nibble. Length >= 13: use extended form (13 + ext byte).
        for seg in uri_path {
            let delta = if class_e_len == 0 { 11 } else { 0 };
            let seg_bytes = seg.as_bytes();
            // RFC 7252 section 3.1: length encoding
            // < 13: 4-bit nibble; 13-268: nibble=13 + 1 byte; 269-65804: nibble=14 + 2 bytes
            let header_len = if seg_bytes.len() < 13 {
                1
            } else if seg_bytes.len() < 269 {
                2
            } else {
                3
            };
            // Bounds check: ensure we have space for header + segment
            if class_e_len + header_len + seg_bytes.len() > class_e.len() {
                return Err(SecureError::CoapEncode);
            }
            if seg_bytes.len() < 13 {
                class_e[class_e_len] = ((delta as u8) << 4) | (seg_bytes.len() as u8);
                class_e_len += 1;
            } else if seg_bytes.len() < 269 {
                class_e[class_e_len] = (delta as u8) << 4 | 13;
                class_e[class_e_len + 1] = (seg_bytes.len() - 13) as u8;
                class_e_len += 2;
            } else {
                // Extended 2-byte form: nibble=14, value = len - 269 (big-endian)
                let ext_val = (seg_bytes.len() - 269) as u16;
                class_e[class_e_len] = (delta as u8) << 4 | 14;
                class_e[class_e_len + 1] = (ext_val >> 8) as u8;
                class_e[class_e_len + 2] = (ext_val & 0xFF) as u8;
                class_e_len += 3;
            }
            class_e[class_e_len..class_e_len + seg_bytes.len()].copy_from_slice(seg_bytes);
            class_e_len += seg_bytes.len();
        }

        // Reject bounded-output failures before consuming a sender sequence.
        ctx.preflight_protect_request(&class_e[..class_e_len], &[])
            .map_err(map_protect_error)?;

        // Protect request
        let reservation = ctx.reserve_sender(store).map_err(|error| match error {
            ReservationError::SequenceExhausted => SecureError::ContextExhausted,
            ReservationError::Conflict => SecureError::ReservationConflict,
            ReservationError::Storage(_) => SecureError::PersistenceFailed,
        })?;
        let (ciphertext, oscore_opt) = reservation
            .protect_request(MessageCode::GET.0, &class_e[..class_e_len], &[])
            .map_err(map_protect_error)?;

        // Extract PIV from OSCORE option for response decryption
        // Option format: flags(1) | piv(n) | kid(rest), where n = flags & 0x07
        let piv_len = (oscore_opt[0] & 0x07) as usize;
        let mut request_piv = [0; PIV_MAX_LEN];
        request_piv[..piv_len].copy_from_slice(&oscore_opt[1..1 + piv_len]);
        let context_id = ctx.context_id();
        // Build outer CoAP with OSCORE option
        let mid = self.stack.next_message_id();
        let mut outer = [0u8; 192];
        let mut builder = CoapBuilder::new(
            &mut outer,
            MessageType::Confirmable,
            MessageCode::POST, // OSCORE uses POST
            mid,
            token,
        )
        .map_err(|_| SecureError::CoapEncode)?;

        // Add OSCORE option (option number 9)
        builder
            .option(OSCORE_OPTION, oscore_opt.as_slice())
            .map_err(|_| SecureError::CoapEncode)?;

        // Payload is ciphertext
        builder
            .payload(ciphertext.as_slice())
            .map_err(|_| SecureError::CoapEncode)?;

        let outer_len = builder.finish();

        self.stack.send_coap_raw(dst, &outer[..outer_len]).await?;
        let mut correlation_token = [0; MAX_TOKEN_LEN];
        correlation_token[..token.len()].copy_from_slice(token);
        Ok(RequestCorrelation {
            message_id: mid,
            token: correlation_token,
            token_len: token.len() as u8,
            request_piv,
            request_piv_len: piv_len as u8,
            context_id,
            destination_peer_iid: *peer_iid,
            completed: false,
        })
    }

    /// Decrypt an OSCORE-protected response.
    ///
    /// The received datagram must come from [`SecureStack::receive_secure_datagram`].
    pub async fn decrypt_response(
        &mut self,
        received: &ReceivedSecureDatagram,
        correlation: &mut RequestCorrelation,
    ) -> Result<SecureResponse, SecureError> {
        let peer_iid = &received.sender_iid;
        if correlation.completed || *peer_iid != correlation.destination_peer_iid {
            return Err(SecureError::CorrelationMismatch);
        }
        let pkt = CoapPacket::from_bytes(&received.coap).map_err(|_| SecureError::CoapEncode)?;
        if received.coap.len() == 4
            && pkt.msg_type() == MessageType::Acknowledgement
            && pkt.code() == MessageCode::EMPTY
            && pkt.message_id() == correlation.message_id
        {
            return Ok(SecureResponse::Acknowledged);
        }
        if pkt.msg_type() == MessageType::Acknowledgement && pkt.code() == MessageCode::EMPTY {
            return Err(SecureError::CorrelationMismatch);
        }
        if !matches!(pkt.code().class(), 2..=5) {
            return Err(SecureError::DecryptFailed);
        }
        if pkt.token() != correlation.token()
            || matches!(pkt.msg_type(), MessageType::Reset)
            || (pkt.msg_type() == MessageType::Acknowledgement
                && pkt.message_id() != correlation.message_id)
        {
            return Err(SecureError::CorrelationMismatch);
        }

        let (stack, contexts) = (&mut self.stack, &mut self.contexts);
        let ctx = contexts.get_mut(peer_iid).ok_or(SecureError::NoContext)?;
        if ctx.context_id() != correlation.context_id {
            return Err(SecureError::CorrelationMismatch);
        }

        // A protected response has exactly one OSCORE option.
        let mut oscore_opt = None;
        for opt in pkt.options() {
            let opt = opt.map_err(|_| SecureError::DecryptFailed)?;
            if opt.number == OSCORE_OPTION {
                if oscore_opt.is_some() {
                    return Err(SecureError::DecryptFailed);
                }
                oscore_opt = Some(opt.value);
            }
        }

        let oscore_opt = oscore_opt.ok_or(SecureError::DecryptFailed)?;
        let ciphertext = pkt.payload();
        let pending = ctx
            .begin_unprotect_response(oscore_opt, ciphertext, correlation.request_piv())
            .map_err(|_| SecureError::DecryptFailed)?;

        if pkt.msg_type() == MessageType::Confirmable {
            let ack = [
                0x60,
                MessageCode::EMPTY.0,
                (pkt.message_id() >> 8) as u8,
                pkt.message_id() as u8,
            ];
            let destination = Addr::link_local_from_eui64(peer_iid);
            stack.send_coap_raw(&destination, &ack).await?;
        }
        let (code, options, payload) = pending.commit().map_err(|_| SecureError::DecryptFailed)?;
        let code = MessageCode(code);
        correlation.completed = true;

        Ok(SecureResponse::Decrypted {
            code,
            options: options.to_vec(),
            payload: payload.to_vec(),
        })
    }

    /// Receive authenticated ICMPv6 diagnostics without exposing plaintext CoAP.
    pub async fn receive_diagnostic(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<ReceivedIpv6>, RxError> {
        let Some(frame) = self.stack.receive(timeout_ms).await? else {
            return Ok(None);
        };
        let header = lichen_ipv6::Ipv6Header::from_bytes(&frame.ipv6)
            .map_err(|_| RxError::SchcDecompress)?;
        Ok((header.next_header == lichen_ipv6::next_header::ICMPV6).then_some(frame))
    }

    /// Receive an authenticated secure CoAP datagram.
    ///
    /// Non-UDP and non-CoAP diagnostics are ignored. An exact empty ACK or a CoAP
    /// message with exactly one valid OSCORE option is accepted. Nonsecure and malformed
    /// CoAP, IPv6, UDP, or OSCORE candidates are rejected.
    pub async fn receive_secure_datagram(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<ReceivedSecureDatagram>, RxError> {
        let Some(frame) = self.stack.receive(timeout_ms).await? else {
            return Ok(None);
        };
        let header = Ipv6Header::from_bytes(&frame.ipv6).map_err(|_| RxError::SchcDecompress)?;
        let payload_len = usize::from(header.payload_len);
        if IPV6_HEADER_LEN.checked_add(payload_len) != Some(frame.ipv6.len()) {
            return Err(RxError::SchcDecompress);
        }
        if header.next_header != next_header::UDP {
            return Ok(None);
        }
        if payload_len < UDP_HEADER_LEN {
            return Err(RxError::SchcDecompress);
        }

        let udp_bytes = &frame.ipv6[IPV6_HEADER_LEN..];
        let udp = UdpHeader::from_bytes(udp_bytes).map_err(|_| RxError::SchcDecompress)?;
        let udp_len = usize::from(udp.length);
        if udp_len < UDP_HEADER_LEN || udp_len != payload_len {
            return Err(RxError::SchcDecompress);
        }
        if udp.checksum == 0 {
            return Err(RxError::SchcDecompress);
        }
        if udp.dst_port != PORT_COAP {
            return Ok(None);
        }

        let coap = &udp_bytes[UDP_HEADER_LEN..udp_len];
        let mut expected_udp = [0; UDP_HEADER_LEN];
        UdpHeader::new(udp.src_port, udp.dst_port)
            .write_to(&header.src, &header.dst, coap, &mut expected_udp)
            .map_err(|_| RxError::SchcDecompress)?;
        if udp_bytes[6..8] != expected_udp[6..8] {
            return Err(RxError::SchcDecompress);
        }
        let packet = CoapPacket::from_bytes(coap).map_err(|_| RxError::SchcDecompress)?;
        let empty_ack = coap.len() == 4
            && packet.msg_type() == MessageType::Acknowledgement
            && packet.code() == MessageCode::EMPTY;
        let mut oscore_option = None;
        let mut oscore_options = 0;
        for option in packet.options() {
            let option = option.map_err(|_| RxError::SchcDecompress)?;
            if option.number == OSCORE_OPTION {
                oscore_options += 1;
                oscore_option = Some(option.value);
            }
        }
        if empty_ack {
            return Ok(Some(ReceivedSecureDatagram {
                coap: coap.to_vec(),
                sender_iid: frame.sender_iid,
                rssi: frame.rssi,
                snr: frame.snr,
            }));
        }
        if oscore_options != 1 {
            return Err(RxError::SchcDecompress);
        }
        validate_option(oscore_option.unwrap()).map_err(|_| RxError::SchcDecompress)?;

        Ok(Some(ReceivedSecureDatagram {
            coap: coap.to_vec(),
            sender_iid: frame.sender_iid,
            rssi: frame.rssi,
            snr: frame.snr,
        }))
    }

    /// Decrypt a request using only its authenticated sender IID for context selection.
    pub fn decrypt_request(
        &mut self,
        received: &ReceivedSecureDatagram,
    ) -> Result<SecureRequest, SecureError> {
        let packet =
            CoapPacket::from_bytes(&received.coap).map_err(|_| SecureError::DecryptFailed)?;
        if received.coap.len() == 4
            && packet.msg_type() == MessageType::Acknowledgement
            && packet.code() == MessageCode::EMPTY
        {
            return Err(SecureError::DecryptFailed);
        }
        let mut oscore_option = None;
        for option in packet.options() {
            let option = option.map_err(|_| SecureError::DecryptFailed)?;
            if option.number == OSCORE_OPTION {
                if oscore_option.is_some() {
                    return Err(SecureError::DecryptFailed);
                }
                oscore_option = Some(option.value);
            }
        }
        let oscore_option = oscore_option.ok_or(SecureError::DecryptFailed)?;
        validate_option(oscore_option).map_err(|_| SecureError::DecryptFailed)?;
        let context = self
            .get_context_mut(&received.sender_iid)
            .ok_or(SecureError::NoContext)?;
        let (code, options, payload) = context
            .unprotect_request(oscore_option, packet.payload())
            .map_err(|_| SecureError::DecryptFailed)?;
        let code = MessageCode(code);
        if code.class() != 0 || code.detail() == 0 {
            return Err(SecureError::DecryptFailed);
        }

        Ok(SecureRequest {
            code,
            options: options.to_vec(),
            payload: payload.to_vec(),
            sender_iid: received.sender_iid,
        })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use lichen_hal::loopback::LoopbackRadio;
    use lichen_hal::{RadioConfig, RxPacket};
    use lichen_link::identity::{Identity, PeerIdentity};
    use lichen_link::Seed;
    use lichen_oscore::{Context as OscoreContext, ContextId, SenderSequenceState};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn received(coap: &[u8], sender_iid: [u8; 8]) -> ReceivedSecureDatagram {
        ReceivedSecureDatagram {
            coap: coap.to_vec(),
            sender_iid,
            rssi: None,
            snr: None,
        }
    }

    struct RecordingRadio {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct SwitchableRadio {
        fail: Arc<AtomicBool>,
    }

    struct RecordingStore {
        record: Option<(ContextId, SenderSequenceState)>,
        existing: SenderSequenceState,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl SenderStateStore for RecordingStore {
        type Error = ();

        fn load(
            &mut self,
            context_id: &ContextId,
        ) -> Result<Option<SenderSequenceState>, Self::Error> {
            Ok(match self.record {
                Some((stored_id, state)) if stored_id == *context_id => Some(state),
                Some(_) => None,
                None => Some(self.existing),
            })
        }

        fn compare_exchange(
            &mut self,
            context_id: &ContextId,
            expected: Option<SenderSequenceState>,
            next: SenderSequenceState,
        ) -> Result<bool, Self::Error> {
            if self.fail {
                self.events.lock().unwrap().push("persist-failed");
                return Err(());
            }
            let current = match self.record {
                Some((stored_id, state)) if stored_id == *context_id => Some(state),
                Some(_) => None,
                None => Some(self.existing),
            };
            if current != expected {
                return Ok(false);
            }
            self.record = Some((*context_id, next));
            self.events.lock().unwrap().push("persist");
            Ok(true)
        }
    }

    impl Radio for RecordingRadio {
        type Error = Infallible;

        async fn transmit(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
            self.events.lock().unwrap().push("transmit");
            Ok(())
        }

        async fn receive(
            &mut self,
            _buf: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            Ok(None)
        }

        fn configure(&mut self, _config: &RadioConfig) {}
    }

    impl Radio for SwitchableRadio {
        type Error = ();

        async fn transmit(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
            if self.fail.load(Ordering::Relaxed) {
                Err(())
            } else {
                Ok(())
            }
        }

        async fn receive(
            &mut self,
            _buf: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            Ok(None)
        }

        fn configure(&mut self, _config: &RadioConfig) {}
    }

    #[test]
    fn sequence_exhaustion_requires_context_rotation() {
        assert_eq!(
            map_protect_error(OscoreError::SeqExhausted),
            SecureError::ContextExhausted
        );
        assert_eq!(
            map_protect_error(OscoreError::EncryptFailed),
            SecureError::EncryptFailed
        );
    }

    #[test]
    fn from_radio_rejects_noncompliant_epoch() {
        let (invalid_radio, _) = LoopbackRadio::pair();
        let invalid_identity = Identity::from_seed(Seed::new([0x71; 32]));
        assert!(matches!(
            SecureStack::from_radio(invalid_radio, invalid_identity, 127),
            Err(SecureError::InvalidEpoch)
        ));

        let (valid_radio, _) = LoopbackRadio::pair();
        let valid_identity = Identity::from_seed(Seed::new([0x72; 32]));
        assert!(SecureStack::from_radio(valid_radio, valid_identity, 128).is_ok());
    }

    #[tokio::test]
    async fn reservation_is_persisted_before_transmit_and_failure_stops_send() {
        let alice_id = Identity::from_seed(Seed::new([0x11; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x22; 32]));
        let bob_iid = bob_id.iid;
        let bob_addr = Addr::link_local_from_eui64(&bob_iid);
        let events = Arc::new(Mutex::new(Vec::new()));
        let radio = RecordingRadio {
            events: Arc::clone(&events),
        };
        let mut stack = Stack::new_default_epoch(radio, alice_id);
        stack.add_peer(PeerIdentity::from_pubkey(bob_id.pubkey));
        let mut secure = SecureStack::new(stack);
        let mut store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 7,
                exhausted: false,
            },
            events: Arc::clone(&events),
            fail: false,
        };
        let context =
            OscoreContext::load_existing(&[0xab; 16], None, None, &[0], &[1], &mut store).unwrap();
        secure
            .restore_context(bob_iid, context, &mut store)
            .unwrap();
        events.lock().unwrap().clear();

        let oversized_path = "x".repeat(129);
        assert_eq!(
            secure
                .send_secure_get(
                    &bob_addr,
                    &bob_iid,
                    &[oversized_path.as_str()],
                    &[1],
                    &mut store,
                )
                .await
                .unwrap_err(),
            SecureError::EncryptFailed
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(
            store
                .record
                .map_or(store.existing, |(_, state)| state)
                .next_sequence,
            7
        );

        store.fail = true;
        assert_eq!(
            secure
                .send_secure_get(&bob_addr, &bob_iid, &["sensors"], &[1], &mut store,)
                .await
                .unwrap_err(),
            SecureError::PersistenceFailed
        );
        assert_eq!(&*events.lock().unwrap(), &["persist-failed"]);
        assert_eq!(
            store
                .record
                .map_or(store.existing, |(_, state)| state)
                .next_sequence,
            7
        );

        store.fail = false;
        secure
            .send_secure_get(&bob_addr, &bob_iid, &["sensors"], &[1], &mut store)
            .await
            .unwrap();
        assert_eq!(
            &*events.lock().unwrap(),
            &["persist-failed", "persist", "transmit"]
        );
    }

    #[tokio::test]
    async fn secure_stack_oscore_roundtrip() {
        let alice_id = Identity::from_seed(Seed::new([0x01; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x02; 32]));

        let alice_pubkey = alice_id.pubkey;
        let bob_pubkey = bob_id.pubkey;
        let alice_iid = alice_id.iid;
        let bob_iid = bob_id.iid;

        let alice_peer = PeerIdentity::from_pubkey(alice_pubkey);
        let bob_peer = PeerIdentity::from_pubkey(bob_pubkey);

        let (radio_a, radio_b) = LoopbackRadio::pair();

        let mut alice = SecureStack::from_radio(radio_a, alice_id, 201).unwrap();
        alice.add_peer(bob_peer);
        let mut bob = SecureStack::from_radio(radio_b, bob_id, 202).unwrap();
        bob.add_peer(alice_peer);

        // Create OSCORE contexts with shared master secret
        let master_secret = [0xAB; 16];
        let mut alice_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let mut bob_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let alice_ctx = OscoreContext::load_existing(
            &master_secret,
            None,
            None,
            &alice_iid[..1],
            &bob_iid[..1],
            &mut alice_store,
        )
        .unwrap();
        let bob_ctx = OscoreContext::load_existing(
            &master_secret,
            None,
            None,
            &bob_iid[..1],
            &alice_iid[..1],
            &mut bob_store,
        )
        .unwrap();

        alice
            .restore_context(bob_iid, alice_ctx, &mut alice_store)
            .unwrap();
        bob.restore_context(alice_iid, bob_ctx, &mut bob_store)
            .unwrap();

        let bob_addr = bob.local_addr();
        // Alice sends encrypted GET
        let correlation = alice
            .send_secure_get(&bob_addr, &bob_iid, &["sensors"], &[0xAB], &mut alice_store)
            .await
            .unwrap();
        assert!(correlation.message_id() < 0xFFFF);
        assert!(!correlation.request_piv().is_empty());

        // Bob receives the exact protected CoAP datagram and can decrypt it.
        let received = bob.receive_secure_datagram(1000).await.unwrap().unwrap();
        assert_eq!(received.sender_iid(), alice_iid);
        assert_eq!(received.rssi(), Some(-50));
        assert_eq!(received.snr(), Some(10));
        assert!(!received.coap().is_empty());
        let request = bob.decrypt_request(&received).unwrap();
        assert_eq!(request.code, MessageCode::GET);
        assert_eq!(request.options, b"\xb7sensors");
        assert!(request.payload.is_empty());
        assert_eq!(request.sender_iid, alice_iid);
    }

    #[tokio::test]
    async fn receive_secure_datagram_accepts_empty_ack_and_rejects_malformed_option() {
        let alice_id = Identity::from_seed(Seed::new([0x21; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x22; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice_id.pubkey);
        let (radio_a, radio_b) = LoopbackRadio::pair();
        let mut alice = Stack::new_default_epoch(radio_a, alice_id);
        let mut bob = SecureStack::from_radio(radio_b, bob_id, 128).unwrap();
        bob.add_peer(alice_peer);

        let empty_ack = [0x60, 0x00, 0x12, 0x34];
        alice
            .send_coap_raw(&bob.local_addr(), &empty_ack)
            .await
            .unwrap();
        let received = bob.receive_secure_datagram(1000).await.unwrap().unwrap();
        assert_eq!(received.coap(), empty_ack);
        assert_eq!(
            bob.decrypt_request(&received).unwrap_err(),
            SecureError::DecryptFailed
        );

        // One OSCORE option with reserved flag bit 5 set.
        alice
            .send_coap_raw(&bob.local_addr(), &[0x40, 0x02, 0x12, 0x34, 0x91, 0x20])
            .await
            .unwrap();

        assert_eq!(
            bob.receive_secure_datagram(1000).await.unwrap_err(),
            RxError::SchcDecompress
        );
    }

    #[tokio::test]
    async fn ordinary_response_correlation_follows_coap_message_semantics() {
        let identity = Identity::from_seed(Seed::new([0x31; 32]));
        let identity_pubkey = identity.pubkey;
        let peer_identity = Identity::from_seed(Seed::new([0x32; 32]));
        let peer_iid = peer_identity.iid;
        let (radio, peer_radio) = LoopbackRadio::pair();
        let mut secure = SecureStack::new(Stack::new_default_epoch(radio, identity));
        let mut peer_stack = Stack::new_default_epoch(peer_radio, peer_identity);
        peer_stack.add_peer(PeerIdentity::from_pubkey(identity_pubkey));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events,
            fail: false,
        };
        let client = OscoreContext::load_existing(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some(&[0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]),
            None,
            &[],
            &[1],
            &mut store,
        )
        .unwrap();
        let context_id = client.context_id();
        secure
            .restore_context(peer_iid, client, &mut store)
            .unwrap();

        // RFC 8613 C.7 ciphertext in a piggybacked ACK with token aa.
        let packet = [
            0x61, 0x44, 0x12, 0x34, 0xaa, 0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7, 0xb2,
            0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11, 0x91,
            0x06,
        ];
        let mut correlation = RequestCorrelation {
            message_id: 0x1234,
            token: [0xaa, 0, 0, 0, 0, 0, 0, 0],
            token_len: 1,
            request_piv: [0x14, 0, 0, 0, 0],
            request_piv_len: 1,
            context_id,
            destination_peer_iid: peer_iid,
            completed: false,
        };

        let empty_ack = [0x60, 0x00, 0x12, 0x34];
        let spoof_iid = [0x33; 8];
        assert_eq!(
            secure
                .decrypt_response(&received(&empty_ack, spoof_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
        assert_eq!(
            secure
                .decrypt_response(&received(&empty_ack, peer_iid), &mut correlation)
                .await
                .unwrap(),
            SecureResponse::Acknowledged
        );

        let malformed_ack = [0x60, 0x00, 0x12, 0x34, 0xff, 0x01];
        assert!(secure
            .decrypt_response(&received(&malformed_ack, peer_iid), &mut correlation)
            .await
            .is_err());

        let mut wrong_mid = packet;
        wrong_mid[2..4].copy_from_slice(&0x9999u16.to_be_bytes());
        assert_eq!(
            secure
                .decrypt_response(&received(&wrong_mid, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );

        let mut wrong_token = packet;
        wrong_token[4] = 0xbb;
        assert_eq!(
            secure
                .decrypt_response(&received(&wrong_token, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );

        let mut reset = packet;
        reset[0] = 0x71;
        assert_eq!(
            secure
                .decrypt_response(&received(&reset, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );

        let mut duplicate_oscore = packet.to_vec();
        duplicate_oscore.insert(6, 0x00);
        assert_eq!(
            secure
                .decrypt_response(&received(&duplicate_oscore, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::DecryptFailed
        );

        let mut separate = packet;
        separate[0] = 0x41;
        separate[2..4].copy_from_slice(&0x9999u16.to_be_bytes());
        separate[1] = MessageCode::GET.0;
        assert_eq!(
            secure
                .decrypt_response(&received(&separate, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::DecryptFailed
        );
        assert!(peer_stack.receive(0).await.unwrap().is_none());

        separate[1] = MessageCode::CHANGED.0;
        assert!(matches!(
            secure
                .decrypt_response(&received(&separate, peer_iid), &mut correlation)
                .await,
            Ok(SecureResponse::Decrypted { .. })
        ));
        let ack_frame = peer_stack.receive(1000).await.unwrap().unwrap();
        assert_eq!(&ack_frame.ipv6[48..], &[0x60, 0x00, 0x99, 0x99]);
        let ack = CoapPacket::from_bytes(&ack_frame.ipv6[48..]).unwrap();
        assert_eq!(ack.msg_type(), MessageType::Acknowledgement);
        assert_eq!(ack.code(), MessageCode::EMPTY);
        assert_eq!(ack.message_id(), 0x9999);
        assert!(ack.token().is_empty());
        assert_eq!(
            secure
                .decrypt_response(&received(&separate, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
    }

    #[tokio::test]
    async fn ack_send_failure_leaves_authenticated_response_retryable() {
        let identity = Identity::from_seed(Seed::new([0x35; 32]));
        let peer_iid = [0x36; 8];
        let fail = Arc::new(AtomicBool::new(true));
        let radio = SwitchableRadio {
            fail: Arc::clone(&fail),
        };
        let mut secure = SecureStack::new(Stack::new_default_epoch(radio, identity));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut client_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::clone(&events),
            fail: false,
        };
        let mut server_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events,
            fail: false,
        };
        let secret = [0x37; 16];
        let client =
            OscoreContext::load_existing(&secret, None, None, &[0], &[1], &mut client_store)
                .unwrap();
        let mut server =
            OscoreContext::load_existing(&secret, None, None, &[1], &[0], &mut server_store)
                .unwrap();
        let context_id = client.context_id();
        secure
            .restore_context(peer_iid, client, &mut client_store)
            .unwrap();
        let prior_piv = [0];
        let current_piv = [64];
        let prior = server
            .reserve_sender(&mut server_store)
            .unwrap()
            .protect_response_with_piv(0x45, &[], b"prior", &[0], &prior_piv)
            .unwrap();
        let current = server
            .reserve_sender(&mut server_store)
            .unwrap()
            .protect_response_with_piv(0x45, &[], b"current", &[0], &current_piv)
            .unwrap();
        secure
            .contexts
            .get_mut(&peer_iid)
            .unwrap()
            .unprotect_response(&prior.1, &prior.0, &prior_piv)
            .unwrap();

        let mut packet = [0; 64];
        let mut builder = CoapBuilder::new(
            &mut packet,
            MessageType::Confirmable,
            MessageCode(0x44),
            0x9999,
            &[0xaa],
        )
        .unwrap();
        builder.option(OSCORE_OPTION, &current.1).unwrap();
        builder.payload(&current.0).unwrap();
        let packet_len = builder.finish();
        let mut correlation = RequestCorrelation {
            message_id: 0x1234,
            token: [0xaa, 0, 0, 0, 0, 0, 0, 0],
            token_len: 1,
            request_piv: [64, 0, 0, 0, 0],
            request_piv_len: 1,
            context_id,
            destination_peer_iid: peer_iid,
            completed: false,
        };

        assert_eq!(
            secure
                .decrypt_response(&received(&packet[..packet_len], peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::Tx(TxError::RadioTx)
        );
        assert!(!correlation.completed);
        assert_eq!(
            secure
                .contexts
                .get_mut(&peer_iid)
                .unwrap()
                .unprotect_response(&prior.1, &prior.0, &prior_piv)
                .unwrap_err(),
            OscoreError::Replay
        );

        fail.store(false, Ordering::Relaxed);
        assert!(matches!(
            secure
                .decrypt_response(&received(&packet[..packet_len], peer_iid), &mut correlation)
                .await,
            Ok(SecureResponse::Decrypted { payload, .. }) if payload == b"current"
        ));
        assert!(correlation.completed);
        assert_eq!(
            secure
                .contexts
                .get_mut(&peer_iid)
                .unwrap()
                .unprotect_response(&current.1, &current.0, &current_piv)
                .unwrap_err(),
            OscoreError::Replay
        );
    }

    #[tokio::test]
    async fn explicit_piv_nonconfirmable_response_completes_correlation() {
        let identity = Identity::from_seed(Seed::new([0x41; 32]));
        let (radio, _) = LoopbackRadio::pair();
        let mut secure = SecureStack::new(Stack::new_default_epoch(radio, identity));
        let secret = [0x42; 16];
        let peer_iid = [0x43; 8];
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut client_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::clone(&events),
            fail: false,
        };
        let mut server_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events,
            fail: false,
        };
        let mut client =
            OscoreContext::load_existing(&secret, None, None, &[0], &[1], &mut client_store)
                .unwrap();
        let mut server =
            OscoreContext::load_existing(&secret, None, None, &[1], &[0], &mut server_store)
                .unwrap();
        let (_, request_option) = client
            .reserve_sender(&mut client_store)
            .unwrap()
            .protect_request(MessageCode::GET.0, &[], &[])
            .unwrap();
        let request_piv = request_option[1];
        let (ciphertext, response_option) = server
            .reserve_sender(&mut server_store)
            .unwrap()
            .protect_response_with_piv(0x45, &[], b"response", &[0], &[request_piv])
            .unwrap();
        assert_eq!(response_option.as_slice(), &[1, 0]);
        let context_id = client.context_id();
        secure
            .restore_context(peer_iid, client, &mut client_store)
            .unwrap();

        // A NON response MID is independent of the request MID.
        let mut packet = Vec::from([0x51, 0x44, 0x99, 0x99, 0x5a, 0x92, 0x01, 0x00, 0xff]);
        packet.extend_from_slice(&ciphertext);
        let mut correlation = RequestCorrelation {
            message_id: 0x1234,
            token: [0x5a, 0, 0, 0, 0, 0, 0, 0],
            token_len: 1,
            request_piv: [request_piv, 0, 0, 0, 0],
            request_piv_len: 1,
            context_id,
            destination_peer_iid: peer_iid,
            completed: false,
        };

        assert!(secure
            .decrypt_response(&received(&packet, peer_iid), &mut correlation)
            .await
            .is_ok());
        assert_eq!(
            secure
                .decrypt_response(&received(&packet, peer_iid), &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
    }
}

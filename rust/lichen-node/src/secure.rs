//! OSCORE-protected stack: end-to-end encrypted CoAP.
//!
//! Wraps the Stack with OSCORE security contexts for encrypted communication.

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_coap::codec::{CoapBuilder, CoapPacket};
use lichen_coap::message::{MessageCode, MessageType};
use lichen_hal::Radio;
use lichen_oscore::{Context, OscoreError, SenderSequenceState, COAP_OPTION_OSCORE};

use crate::stack::{ReceivedIpv6, RxError, Stack, TxError};
use lichen_core::addr::NodeId;
use lichen_ipv6::Addr;

/// OSCORE option number.
const OSCORE_OPTION: u16 = COAP_OPTION_OSCORE;

/// Secure stack error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecureError {
    /// No OSCORE context for peer.
    NoContext,
    /// OSCORE encryption failed.
    EncryptFailed,
    /// OSCORE sender sequence is exhausted; rotate the context before retrying.
    ContextExhausted,
    /// Restored contexts require durable sender-sequence reservation.
    PersistenceRequired,
    /// Persisting the sender-sequence reservation failed.
    PersistenceFailed,
    /// OSCORE decryption failed.
    DecryptFailed,
    /// CoAP encoding error.
    CoapEncode,
    /// TX error from underlying stack.
    Tx(TxError),
}

impl core::fmt::Display for SecureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoContext => write!(f, "no OSCORE context for peer"),
            Self::EncryptFailed => write!(f, "OSCORE encryption failed"),
            Self::ContextExhausted => {
                write!(f, "OSCORE context exhausted; key rotation required")
            }
            Self::PersistenceRequired => write!(f, "sender-sequence persistence required"),
            Self::PersistenceFailed => write!(f, "sender-sequence persistence failed"),
            Self::DecryptFailed => write!(f, "OSCORE decryption failed"),
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
    pub fn new(stack: Stack<R>) -> Self {
        Self {
            stack,
            contexts: HashMap::new(),
        }
    }

    /// Create from radio and identity directly with default epoch.
    ///
    /// SECURITY: Uses minimum compliant epoch (128). For production, prefer
    /// constructing a Stack with a random epoch in [128, 255].
    pub fn from_radio(radio: R, identity: lichen_link::identity::Identity) -> Self {
        Self::new(Stack::new_default_epoch(radio, identity))
    }

    /// Add an OSCORE security context for a peer.
    ///
    /// The peer_iid is the 8-byte IID of the peer (from their pubkey hash).
    pub fn add_context(&mut self, peer_iid: [u8; 8], context: Context) {
        self.contexts.insert(peer_iid, context);
    }

    /// Get read-only context state for a peer.
    pub fn context(&self, peer_iid: &[u8; 8]) -> Option<&Context> {
        self.contexts.get(peer_iid)
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

    /// Send an OSCORE-protected GET using a fresh, ephemeral context.
    ///
    /// This convenience API does not provide crash-safe sequence persistence and
    /// therefore rejects contexts created with [`Context::restore`].
    pub async fn send_secure_get(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
    ) -> Result<(u16, Vec<u8>), SecureError> {
        if self
            .context(peer_iid)
            .ok_or(SecureError::NoContext)?
            .is_restored()
        {
            return Err(SecureError::PersistenceRequired);
        }

        self.send_secure_get_inner(dst, peer_iid, uri_path, token, |_| Ok::<(), ()>(()))
            .await
    }

    /// Send an OSCORE-protected GET after durably reserving its sender sequence.
    ///
    /// `persist` receives the advanced sender state and MUST make it durable before
    /// returning success. A persistence error prevents transmission; the consumed
    /// sequence remains skipped so retrying cannot reuse its nonce.
    pub async fn send_secure_get_with_reservation<F, E>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        persist: F,
    ) -> Result<(u16, Vec<u8>), SecureError>
    where
        F: FnOnce(SenderSequenceState) -> Result<(), E>,
    {
        self.send_secure_get_inner(dst, peer_iid, uri_path, token, persist)
            .await
    }

    async fn send_secure_get_inner<F, E>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        persist: F,
    ) -> Result<(u16, Vec<u8>), SecureError>
    where
        F: FnOnce(SenderSequenceState) -> Result<(), E>,
    {
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

        // Protect request
        let (ciphertext, oscore_opt) = ctx
            .protect_request(MessageCode::GET.0, &class_e[..class_e_len], &[])
            .map_err(map_protect_error)?;

        // Extract PIV from OSCORE option for response decryption
        // Option format: flags(1) | piv(n) | kid(rest), where n = flags & 0x07
        let piv_len = (oscore_opt[0] & 0x07) as usize;
        let request_piv = oscore_opt[1..1 + piv_len].to_vec();
        let sender_state = ctx.sender_sequence_state();

        persist(sender_state).map_err(|_| SecureError::PersistenceFailed)?;

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
        Ok((mid, request_piv))
    }

    /// Decrypt an OSCORE-protected response.
    ///
    /// # Parameters
    /// - `peer_iid`: The IID of the peer who sent the response
    /// - `coap`: The raw CoAP packet
    /// - `request_piv`: The PIV from the original request (returned by send_secure_get)
    pub fn decrypt_response(
        &mut self,
        peer_iid: &[u8; 8],
        coap: &[u8],
        request_piv: &[u8],
    ) -> Result<(MessageCode, Vec<u8>), SecureError> {
        let pkt = CoapPacket::from_bytes(coap).map_err(|_| SecureError::CoapEncode)?;

        // Find OSCORE option
        let mut oscore_opt = None;
        for opt in pkt.options().flatten() {
            if opt.number == OSCORE_OPTION {
                oscore_opt = Some(opt.value);
                break;
            }
        }

        let oscore_opt = oscore_opt.ok_or(SecureError::DecryptFailed)?;
        let ciphertext = pkt.payload();

        let ctx = self
            .get_context_mut(peer_iid)
            .ok_or(SecureError::NoContext)?;

        // SECURITY: Use unprotect_response for proper response semantics per RFC 8613.
        // Responses may omit PIV (using request_piv instead) and don't need replay protection.
        let (code, _options, payload) = ctx
            .unprotect_response(oscore_opt, ciphertext, request_piv)
            .map_err(|_| SecureError::DecryptFailed)?;

        Ok((MessageCode(code), payload.to_vec()))
    }

    /// Receive and auto-decrypt if OSCORE protected.
    pub async fn receive(&mut self, timeout_ms: u32) -> Result<Option<ReceivedIpv6>, RxError> {
        self.stack.receive(timeout_ms).await
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
    use lichen_oscore::Context as OscoreContext;
    use std::sync::{Arc, Mutex};

    struct RecordingRadio {
        events: Arc<Mutex<Vec<&'static str>>>,
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
        secure.add_context(
            bob_iid,
            OscoreContext::restore(&[0xab; 16], None, &[0], &[1], 7, false).unwrap(),
        );

        assert_eq!(
            secure
                .send_secure_get(&bob_addr, &bob_iid, &["sensors"], &[1])
                .await
                .unwrap_err(),
            SecureError::PersistenceRequired
        );
        assert!(events.lock().unwrap().is_empty());

        let failed_events = Arc::clone(&events);
        assert_eq!(
            secure
                .send_secure_get_with_reservation(
                    &bob_addr,
                    &bob_iid,
                    &["sensors"],
                    &[1],
                    move |state| {
                        assert_eq!(state.next_sequence, 8);
                        failed_events.lock().unwrap().push("persist-failed");
                        Err(())
                    },
                )
                .await
                .unwrap_err(),
            SecureError::PersistenceFailed
        );
        assert_eq!(&*events.lock().unwrap(), &["persist-failed"]);

        let persisted_events = Arc::clone(&events);
        secure
            .send_secure_get_with_reservation(
                &bob_addr,
                &bob_iid,
                &["sensors"],
                &[1],
                move |state| {
                    assert_eq!(state.next_sequence, 9);
                    persisted_events.lock().unwrap().push("persist");
                    Ok::<(), ()>(())
                },
            )
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

        let mut alice_stack = Stack::new_default_epoch(radio_a, alice_id);
        alice_stack.add_peer(bob_peer);

        let mut bob_stack = Stack::new_default_epoch(radio_b, bob_id);
        bob_stack.add_peer(alice_peer);

        let mut alice = SecureStack::new(alice_stack);
        let mut bob = SecureStack::new(bob_stack);

        // Create OSCORE contexts with shared master secret
        let master_secret = [0xAB; 16];
        let alice_ctx =
            OscoreContext::new(&master_secret, None, &alice_iid[..1], &bob_iid[..1]).unwrap();
        let bob_ctx =
            OscoreContext::new(&master_secret, None, &bob_iid[..1], &alice_iid[..1]).unwrap();

        alice.add_context(bob_iid, alice_ctx);
        bob.add_context(alice_iid, bob_ctx);

        let bob_addr = bob.local_addr();

        // Alice sends encrypted GET
        let (mid, request_piv) = alice
            .send_secure_get(&bob_addr, &bob_iid, &["sensors"], &[0xAB])
            .await
            .unwrap();
        assert!(mid < 0xFFFF);
        assert!(!request_piv.is_empty());

        // Bob receives
        let frame = bob.receive(1000).await.unwrap().unwrap();
        assert!(frame.ipv6.len() >= 40);
    }
}

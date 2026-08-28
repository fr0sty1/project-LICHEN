//! OSCORE-protected stack: end-to-end encrypted CoAP.
//!
//! Wraps the Stack with OSCORE security contexts for encrypted communication.

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_coap::block::{BlockOption, BlockReceiver, BlockSender};
use lichen_coap::codec::{CoapBuilder, CoapError, CoapPacket, OptionIterator, MAX_TOKEN_LEN};
use lichen_coap::message::{MessageCode, MessageType};
use lichen_coap::observe::{
    ClientEvent, ClientNotification, ObserveClient, ObserveError, ObserveKey, ObserveRequest,
};
use lichen_coap::option::OptionNumber;
use lichen_core::constants::PORT_COAP;
use lichen_hal::Radio;
use lichen_ipv6::{next_header, Addr, Ipv6Header, UdpHeader, IPV6_HEADER_LEN, UDP_HEADER_LEN};
use lichen_link::identity::PeerIdentity;
use lichen_link::link_layer::LinkLayer;
use lichen_oscore::{
    request_identifiers, validate_option, Context, ContextId, ContextStoreError, OscoreError,
    RequestIdentifiers, ReservationError, SenderStateStore, COAP_OPTION_OSCORE, PIV_MAX_LEN,
    TAG_LEN,
};

use crate::stack::{Priority, ReceivedIpv6, RxError, Stack, TxError};
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
    /// Malformed OSCORE option.
    MalformedOscore,
    /// Invalid or inconsistent CoAP Observe state.
    Observe(ObserveError),
    /// Invalid or inconsistent RFC 7959 blockwise state.
    Blockwise(CoapError),
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
            Self::MalformedOscore => write!(f, "malformed OSCORE option"),
            Self::Observe(error) => write!(f, "Observe error: {error}"),
            Self::Blockwise(error) => write!(f, "blockwise error: {error}"),
            Self::Tx(e) => write!(f, "TX error: {}", e),
        }
    }
}

impl core::error::Error for SecureError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tx(e) => Some(e),
            Self::Observe(e) => Some(e),
            Self::Blockwise(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TxError> for SecureError {
    fn from(e: TxError) -> Self {
        SecureError::Tx(e)
    }
}

impl From<ObserveError> for SecureError {
    fn from(error: ObserveError) -> Self {
        Self::Observe(error)
    }
}

impl From<CoapError> for SecureError {
    fn from(error: CoapError) -> Self {
        Self::Blockwise(error)
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
    completed_confirmable: Option<(u16, Vec<u8>)>,
}

/// Client state for one OSCORE-protected RFC 7641 relationship.
///
/// The original request PIV remains bound to the token for the lifetime of this value. Each
/// accepted notification must carry a fresh responder PIV; ordinary one-shot correlations use
/// [`RequestCorrelation`] and are unaffected.
pub struct SecureObserveCorrelation {
    request: RequestCorrelation,
    client: ObserveClient<[u8; 8], 1>,
    key: ObserveKey<[u8; 8]>,
    active: bool,
    completed_confirmable: Option<(u16, Vec<u8>)>,
}

impl SecureObserveCorrelation {
    /// Canonical CoAP token bound to this protected subscription.
    pub fn token(&self) -> &[u8] {
        self.key.token()
    }

    /// Whether the relationship remains active locally.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Cancel the local relationship. Send GET Observe=1 separately when the peer is reachable.
    pub fn cancel(&mut self) -> bool {
        let removed = self.client.cancel(&self.key);
        self.active = false;
        self.completed_confirmable = None;
        removed
    }

    /// Remove an expired registration/relationship.
    pub fn cleanup(&mut self, now_ms: u64) -> bool {
        let removed = self.client.cleanup(now_ms) != 0;
        if removed {
            self.active = false;
            self.completed_confirmable = None;
        }
        removed
    }
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

/// Result of processing an OSCORE-protected Observe response or notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureObserveResponse {
    /// Empty ACK for the registration request; a separate response may follow.
    Acknowledged,
    /// Exact retransmission of an already accepted CON notification; it was ACKed again without
    /// reusing or advancing either OSCORE or Observe state.
    Duplicate,
    /// Tokenless RST terminated the relationship.
    Reset,
    /// Authenticated notification and its RFC 7641 classification.
    Decrypted {
        event: ClientEvent,
        code: MessageCode,
        options: Vec<u8>,
        payload: Vec<u8>,
    },
}

/// A structurally validated OSCORE CoAP candidate or exact empty ACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSecureDatagram {
    coap: Vec<u8>,
    sender_iid: [u8; 8],
    source: Addr,
    destination: Addr,
    source_port: u16,
    destination_port: u16,
    rssi: Option<i16>,
    snr: Option<i8>,
}

impl ReceivedSecureDatagram {
    /// Complete protected CoAP datagram or exact empty ACK.
    pub fn coap(&self) -> &[u8] {
        &self.coap
    }

    /// Claimed IPv6 origin IID. It is authenticated only after OSCORE decryption.
    pub fn sender_iid(&self) -> [u8; 8] {
        self.sender_iid
    }

    pub(crate) fn source(&self) -> Addr {
        self.source
    }

    pub(crate) fn destination(&self) -> Addr {
        self.destination
    }

    pub(crate) fn requires_ack(&self) -> bool {
        CoapPacket::from_bytes(&self.coap)
            .is_ok_and(|packet| packet.msg_type() == MessageType::Confirmable)
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

/// Decrypted OSCORE request from an authenticated end-to-end peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRequest {
    /// Inner CoAP request code.
    pub code: MessageCode,
    /// Decrypted Class E options.
    pub options: Vec<u8>,
    /// Decrypted payload.
    pub payload: Vec<u8>,
    /// Sender IID authenticated by the OSCORE context.
    pub sender_iid: [u8; 8],
}

#[derive(Clone, Copy)]
struct RequestMetadata {
    message_id: u16,
    token: [u8; MAX_TOKEN_LEN],
    token_len: u8,
    confirmable: bool,
    identifiers: RequestIdentifiers,
}

impl RequestMetadata {
    fn token(&self) -> &[u8] {
        &self.token[..self.token_len as usize]
    }
}

struct PendingRequest {
    request: SecureRequest,
    metadata: RequestMetadata,
}

/// Plaintext response fields to protect with OSCORE.
#[derive(Debug, Clone, Copy)]
pub struct SecureResponseData<'a> {
    /// Inner CoAP response code.
    pub code: MessageCode,
    /// Encoded Class E response options.
    pub options: &'a [u8],
    /// Response payload.
    pub payload: &'a [u8],
}

/// Plaintext request fields to protect with OSCORE.
#[derive(Debug, Clone, Copy)]
pub struct SecureRequestData<'a> {
    /// URI-Path segments in wire order.
    pub uri_path: &'a [&'a str],
    /// CoAP token used to correlate the protected response.
    pub token: &'a [u8],
    /// Inner CoAP request method.
    pub method: MessageCode,
    /// Inner request payload.
    pub payload: &'a [u8],
}

/// Bounded client state for an OSCORE-protected Block1 upload.
#[derive(Debug)]
pub struct SecureBlock1Transfer {
    sender: BlockSender,
    in_flight: Option<BlockOption>,
}

impl SecureBlock1Transfer {
    pub fn new(payload: &[u8], block_size: usize) -> Result<Self, SecureError> {
        if payload.is_empty() {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        }
        Ok(Self {
            sender: BlockSender::new(payload, block_size)?,
            in_flight: None,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.sender.is_complete()
    }

    pub fn total_size(&self) -> usize {
        self.sender.total_size()
    }
}

/// Bounded client state for an OSCORE-protected Block2 download.
#[derive(Debug)]
pub struct SecureBlock2Transfer {
    receiver: BlockReceiver,
    in_flight: Option<BlockOption>,
}

/// Authenticated progress of one blockwise exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBlockwiseProgress {
    /// Empty ACK accepted the CON; the protected response is still pending.
    Acknowledged,
    /// The authenticated block was accepted and another block is required.
    More,
    /// The final authenticated block was accepted.
    Complete,
}

impl SecureBlock2Transfer {
    pub fn new(block_size: usize) -> Self {
        Self {
            receiver: BlockReceiver::new(block_size),
            in_flight: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.receiver.is_complete()
    }

    pub fn payload(&self) -> &[u8] {
        self.receiver.payload()
    }
}

#[derive(Debug, Clone, Copy)]
enum BlockRequestOption {
    Block1 { block: BlockOption, size1: u32 },
    Block2(BlockOption),
}

/// Inputs for one protected Observe registration.
#[derive(Debug, Clone, Copy)]
pub struct SecureObserveRegistration<'a> {
    pub uri_path: &'a [&'a str],
    pub token: &'a [u8],
    pub now_ms: u64,
    pub registration_timeout_ms: u64,
}

pub(crate) struct SecureRoute<'a> {
    pub(crate) source: &'a Addr,
    pub(crate) destination: &'a Addr,
    pub(crate) l2_destination: &'a [u8],
    pub(crate) source_route: &'a [[u8; 16]],
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
    pending_requests: Vec<PendingRequest>,
}

#[cfg(feature = "std")]
impl<R: Radio> SecureStack<R> {
    /// Create a new secure stack.
    pub(crate) fn new(stack: Stack<R>) -> Self {
        Self {
            stack,
            contexts: HashMap::new(),
            pending_requests: Vec::new(),
        }
    }

    pub(crate) fn radio(&mut self) -> &mut R {
        self.stack.radio()
    }

    /// Get the CCP operating channel.
    pub(crate) fn channel(&self) -> u8 {
        self.stack.channel()
    }

    pub(crate) fn link(&mut self) -> &mut LinkLayer {
        self.stack.link()
    }

    pub(crate) fn link_ref(&self) -> &LinkLayer {
        self.stack.link_ref()
    }

    pub(crate) fn forget_peer(&mut self, iid: &[u8; 8]) {
        self.stack.forget_peer(iid);
    }

    pub(crate) fn decompress_authenticated_frame(
        &mut self,
        frame: &lichen_link::link_layer::AuthenticatedFrame,
        out: &mut [u8],
    ) -> Result<usize, lichen_schc::SchcError> {
        self.stack.decompress_authenticated_frame(frame, out)
    }

    pub(crate) async fn send_l2_payload_to(
        &mut self,
        payload: &[u8],
        destination: &[u8],
    ) -> Result<(), TxError> {
        self.stack.send_l2_payload_to(payload, destination).await
    }

    pub(crate) async fn send_ipv6_to(
        &mut self,
        ipv6: &[u8],
        destination: &[u8],
        priority: Priority,
    ) -> Result<(), TxError> {
        self.stack.send_ipv6_to(ipv6, destination, priority).await
    }

    pub(crate) async fn send_ipv6_to_route(
        &mut self,
        ipv6: &[u8],
        destination: &[u8],
        source_route: &[[u8; 16]],
        priority: Priority,
    ) -> Result<(), TxError> {
        self.stack
            .send_ipv6_to_route(ipv6, destination, source_route, priority)
            .await
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
        seq: u16,
    ) -> Result<Self, SecureError> {
        if epoch < 128 {
            return Err(SecureError::InvalidEpoch);
        }
        Ok(Self::new(Stack::new(radio, identity, epoch, seq)))
    }

    /// Atomically register and install a newly established OSCORE context.
    ///
    /// `peer_iid` is the authoritative binding between the IPv6 peer identity and
    /// this context. Installing a context under the wrong IID authenticates that
    /// incorrect binding after otherwise valid OSCORE decryption.
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

    /// Restore and install an existing OSCORE context.
    ///
    /// Unlike [`register_fresh_context`], this does not perform atomic registration
    /// since the context was previously registered with the store.
    pub fn restore_context<S: SenderStateStore>(
        &mut self,
        peer_iid: [u8; 8],
        context: Context,
        _store: &mut S,
    ) -> Result<(), SecureError> {
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

    /// Get local public key.
    pub fn local_public_key(&self) -> lichen_link::keys::PublicKey {
        self.stack.local_public_key()
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
        let source = self.stack.local_addr();
        self.send_secure_get_to(
            SecureRoute {
                source: &source,
                destination: dst,
                l2_destination: &[],
                source_route: &[],
            },
            peer_iid,
            uri_path,
            token,
            store,
        )
        .await
    }

    /// Send an OSCORE-protected CoAP request with an explicit inner method and
    /// payload. This is the authenticated client boundary used by gateway
    /// coordination integration.
    pub async fn send_secure_request<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        request: SecureRequestData<'_>,
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        let source = self.stack.local_addr();
        self.send_secure_request_to(
            SecureRoute {
                source: &source,
                destination: dst,
                l2_destination: &[],
                source_route: &[],
            },
            peer_iid,
            request,
            None,
            None,
            store,
        )
        .await
    }

    /// Send the next independently protected Block1 request.
    pub async fn send_secure_block1<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        method: MessageCode,
        transfer: &mut SecureBlock1Transfer,
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        if transfer.in_flight.is_some() || transfer.sender.is_complete() {
            return Err(SecureError::Blockwise(CoapError::BlockOutOfOrder));
        }
        let (block, payload) = transfer
            .sender
            .next_block()
            .ok_or(SecureError::Blockwise(CoapError::BlockOutOfOrder))?;
        let payload = Vec::from(payload);
        let size1 = u32::try_from(transfer.sender.total_size())
            .map_err(|_| SecureError::Blockwise(CoapError::PayloadTooLarge))?;
        let source = self.stack.local_addr();
        let correlation = self
            .send_secure_request_to(
                SecureRoute {
                    source: &source,
                    destination: dst,
                    l2_destination: &[],
                    source_route: &[],
                },
                peer_iid,
                SecureRequestData {
                    uri_path,
                    token,
                    method,
                    payload: &payload,
                },
                None,
                Some(BlockRequestOption::Block1 { block, size1 }),
                store,
            )
            .await?;
        transfer.in_flight = Some(block);
        Ok(correlation)
    }

    /// Authenticate and apply one Block1 acknowledgement/terminal response.
    pub async fn accept_secure_block1_response(
        &mut self,
        received: &ReceivedSecureDatagram,
        correlation: &mut RequestCorrelation,
        transfer: &mut SecureBlock1Transfer,
    ) -> Result<SecureBlockwiseProgress, SecureError> {
        let response = self.decrypt_response(received, correlation).await?;
        let SecureResponse::Decrypted {
            code,
            options,
            payload,
        } = response
        else {
            return Ok(SecureBlockwiseProgress::Acknowledged);
        };
        if !payload.is_empty() {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        }
        let sent = transfer
            .in_flight
            .ok_or(SecureError::Blockwise(CoapError::BlockOutOfOrder))?;
        if (sent.more && code != MessageCode::CONTINUE)
            || (!sent.more && (code.class() != 2 || code == MessageCode::CONTINUE))
        {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        }
        let (ack, size) = parse_block_response(&options, OptionNumber::Block1)?;
        if size.is_some() {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        }
        let complete = transfer.sender.acknowledge(sent, ack)?;
        transfer.in_flight = None;
        Ok(if complete {
            SecureBlockwiseProgress::Complete
        } else {
            SecureBlockwiseProgress::More
        })
    }

    /// Send the next independently protected Block2 request.
    pub async fn send_secure_block2<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        transfer: &mut SecureBlock2Transfer,
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        if transfer.in_flight.is_some() || transfer.receiver.is_complete() {
            return Err(SecureError::Blockwise(CoapError::BlockOutOfOrder));
        }
        let block = transfer.receiver.next_request_block();
        let source = self.stack.local_addr();
        let correlation = self
            .send_secure_request_to(
                SecureRoute {
                    source: &source,
                    destination: dst,
                    l2_destination: &[],
                    source_route: &[],
                },
                peer_iid,
                SecureRequestData {
                    uri_path,
                    token,
                    method: MessageCode::GET,
                    payload: &[],
                },
                None,
                Some(BlockRequestOption::Block2(block)),
                store,
            )
            .await?;
        transfer.in_flight = Some(block);
        Ok(correlation)
    }

    /// Authenticate, order-check, and assemble one Block2 response.
    pub async fn accept_secure_block2_response(
        &mut self,
        received: &ReceivedSecureDatagram,
        correlation: &mut RequestCorrelation,
        transfer: &mut SecureBlock2Transfer,
    ) -> Result<SecureBlockwiseProgress, SecureError> {
        let response = self.decrypt_response(received, correlation).await?;
        let SecureResponse::Decrypted {
            code,
            options,
            payload,
        } = response
        else {
            return Ok(SecureBlockwiseProgress::Acknowledged);
        };
        if code != MessageCode::CONTENT {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        }
        let requested = transfer
            .in_flight
            .ok_or(SecureError::Blockwise(CoapError::BlockOutOfOrder))?;
        let (block, size2) = parse_block_response(&options, OptionNumber::Block2)?;
        if block.num != requested.num || block.szx > requested.szx {
            return Err(SecureError::Blockwise(CoapError::BlockOutOfOrder));
        }
        if let Some(size2) = size2 {
            transfer.receiver.set_expected_size(size2)?;
        }
        let complete = transfer.receiver.receive_block(block, &payload)?;
        transfer.in_flight = None;
        Ok(if complete {
            SecureBlockwiseProgress::Complete
        } else {
            SecureBlockwiseProgress::More
        })
    }

    /// Register one OSCORE-protected CoAP Observe relationship.
    ///
    /// The encrypted request carries GET + Observe=0 + Uri-Path. `registration_timeout_ms`
    /// bounds the registering state until the first authenticated response arrives.
    pub async fn send_secure_observe<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        registration: SecureObserveRegistration<'_>,
        store: &mut S,
    ) -> Result<SecureObserveCorrelation, SecureError> {
        let key = ObserveKey::new(*peer_iid, registration.token)?;
        let mut client = ObserveClient::new();
        client.subscribe(
            key,
            0,
            registration.now_ms,
            registration.registration_timeout_ms,
        )?;
        let source = self.stack.local_addr();
        let request = self
            .send_secure_request_to(
                SecureRoute {
                    source: &source,
                    destination: dst,
                    l2_destination: &[],
                    source_route: &[],
                },
                peer_iid,
                SecureRequestData {
                    uri_path: registration.uri_path,
                    token: registration.token,
                    method: MessageCode::GET,
                    payload: &[],
                },
                Some(ObserveRequest::Register),
                None,
                store,
            )
            .await?;
        Ok(SecureObserveCorrelation {
            request,
            client,
            key,
            active: true,
            completed_confirmable: None,
        })
    }

    /// Send an authenticated GET Observe=1 cancellation request.
    ///
    /// On successful transmission, call [`SecureObserveCorrelation::cancel`] on the existing
    /// relationship. Its response uses ordinary one-shot correlation semantics.
    pub async fn send_secure_observe_cancel<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        let source = self.stack.local_addr();
        self.send_secure_request_to(
            SecureRoute {
                source: &source,
                destination: dst,
                l2_destination: &[],
                source_route: &[],
            },
            peer_iid,
            SecureRequestData {
                uri_path,
                token,
                method: MessageCode::GET,
                payload: &[],
            },
            Some(ObserveRequest::Deregister),
            None,
            store,
        )
        .await
    }

    pub(crate) async fn send_secure_get_to<S: SenderStateStore>(
        &mut self,
        route: SecureRoute<'_>,
        peer_iid: &[u8; 8],
        uri_path: &[&str],
        token: &[u8],
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        self.send_secure_request_to(
            route,
            peer_iid,
            SecureRequestData {
                uri_path,
                token,
                method: MessageCode::GET,
                payload: &[],
            },
            None,
            None,
            store,
        )
        .await
    }

    async fn send_secure_request_to<S: SenderStateStore>(
        &mut self,
        route: SecureRoute<'_>,
        peer_iid: &[u8; 8],
        request: SecureRequestData<'_>,
        observe_request: Option<ObserveRequest>,
        block_request: Option<BlockRequestOption>,
        store: &mut S,
    ) -> Result<RequestCorrelation, SecureError> {
        if request.token.len() > MAX_TOKEN_LEN {
            return Err(SecureError::CoapEncode);
        }
        let ctx = self
            .get_context_mut(peer_iid)
            .ok_or(SecureError::NoContext)?;

        // Build inner CoAP (will be encrypted)
        // Inner message: code + Uri-Path options (class E)
        let mut class_e = [0u8; 256];
        let mut class_e_len = 0;

        // Observe (option 6) precedes Uri-Path (option 11) in the encrypted Class E options.
        let mut previous_option = 0u16;
        if let Some(observe) = observe_request {
            class_e[class_e_len] = match observe {
                ObserveRequest::Register => 0x60,
                ObserveRequest::Deregister => 0x61,
            };
            class_e_len += 1;
            if observe == ObserveRequest::Deregister {
                class_e[class_e_len] = 1;
                class_e_len += 1;
            }
            previous_option = OptionNumber::Observe as u16;
        }

        // Encode Uri-Path options using CoAP delta encoding (RFC 7252 section 3.1).
        // Option delta = current_option_number - previous_option_number.
        // First Uri-Path (option 11): delta = 11 - 0 = 11.
        // Subsequent Uri-Path options: delta = 11 - 11 = 0 (same option number repeats).
        // Length < 13: fits in 4-bit nibble. Length >= 13: use extended form (13 + ext byte).
        for seg in request.uri_path {
            let delta = (OptionNumber::UriPath as u16 - previous_option) as u8;
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
                class_e[class_e_len] = (delta << 4) | (seg_bytes.len() as u8);
                class_e_len += 1;
            } else if seg_bytes.len() < 269 {
                class_e[class_e_len] = delta << 4 | 13;
                class_e[class_e_len + 1] = (seg_bytes.len() - 13) as u8;
                class_e_len += 2;
            } else {
                // Extended 2-byte form: nibble=14, value = len - 269 (big-endian)
                let ext_val = (seg_bytes.len() - 269) as u16;
                class_e[class_e_len] = delta << 4 | 14;
                class_e[class_e_len + 1] = (ext_val >> 8) as u8;
                class_e[class_e_len + 2] = (ext_val & 0xFF) as u8;
                class_e_len += 3;
            }
            class_e[class_e_len..class_e_len + seg_bytes.len()].copy_from_slice(seg_bytes);
            class_e_len += seg_bytes.len();
            previous_option = OptionNumber::UriPath as u16;
        }

        if let Some(block_request) = block_request {
            match block_request {
                BlockRequestOption::Block1 { block, size1 } => {
                    let mut block_value = [0u8; 3];
                    let block_len = block.write_to(&mut block_value)?;
                    append_class_e_option(
                        &mut class_e,
                        &mut class_e_len,
                        &mut previous_option,
                        OptionNumber::Block1 as u16,
                        &block_value[..block_len],
                    )?;
                    let size_bytes = size1.to_be_bytes();
                    let first = size_bytes.iter().position(|byte| *byte != 0).unwrap_or(4);
                    append_class_e_option(
                        &mut class_e,
                        &mut class_e_len,
                        &mut previous_option,
                        OptionNumber::Size1 as u16,
                        &size_bytes[first..],
                    )?;
                }
                BlockRequestOption::Block2(block) => {
                    let mut block_value = [0u8; 3];
                    let block_len = block.write_to(&mut block_value)?;
                    append_class_e_option(
                        &mut class_e,
                        &mut class_e_len,
                        &mut previous_option,
                        OptionNumber::Block2 as u16,
                        &block_value[..block_len],
                    )?;
                }
            }
        }

        // Reject bounded-output failures before consuming a sender sequence.
        ctx.preflight_protect_request(&class_e[..class_e_len], request.payload)
            .map_err(map_protect_error)?;
        let oscore_option_len = ctx.next_request_option_len().map_err(map_protect_error)?;
        let context_id = ctx.context_id();
        let protected_payload_len = 1usize
            .checked_add(class_e_len)
            .and_then(|length| length.checked_add(request.payload.len()))
            .and_then(|length| length.checked_add(TAG_LEN))
            .ok_or(SecureError::CoapEncode)?;
        preflight_secure_frame(
            route.source,
            route.destination,
            route.l2_destination,
            route.source_route,
            request.token.len(),
            protected_payload_len,
            oscore_option_len,
        )?;

        // Protect request
        let reservation = ctx.reserve_sender(store).map_err(|error| match error {
            ReservationError::SequenceExhausted => SecureError::ContextExhausted,
            ReservationError::Conflict => SecureError::ReservationConflict,
            ReservationError::Storage(_) => SecureError::PersistenceFailed,
        })?;
        let (ciphertext, oscore_opt) = reservation
            .protect_request(request.method.0, &class_e[..class_e_len], request.payload)
            .map_err(map_protect_error)?;

        let piv_len = (oscore_opt[0] & 0x07) as usize;
        if oscore_opt.len() < 1 + piv_len || piv_len > PIV_MAX_LEN {
            return Err(SecureError::MalformedOscore);
        }
        let mut request_piv = [0u8; PIV_MAX_LEN];
        request_piv[..piv_len].copy_from_slice(&oscore_opt[1..1 + piv_len]);

        // Build outer CoAP with OSCORE option
        let mid = self.stack.next_message_id();
        let mut outer = [0u8; 192];
        let mut builder = CoapBuilder::new(
            &mut outer,
            MessageType::Confirmable,
            MessageCode::POST, // OSCORE uses POST
            mid,
            request.token,
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

        self.stack
            .send_coap_raw_to(
                route.source,
                route.destination,
                &outer[..outer_len],
                route.l2_destination,
                route.source_route,
                Priority::Normal,
            )
            .await?;
        let mut correlation_token = [0; MAX_TOKEN_LEN];
        correlation_token[..request.token.len()].copy_from_slice(request.token);
        Ok(RequestCorrelation {
            message_id: mid,
            token: correlation_token,
            token_len: request.token.len() as u8,
            request_piv,
            request_piv_len: piv_len as u8,
            context_id,
            destination_peer_iid: *peer_iid,
            completed: false,
            completed_confirmable: None,
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
        let source = received.destination();
        let destination = received.source();
        let mut l2_destination: [u8; 8] = destination.0[8..].try_into().unwrap();
        l2_destination[0] ^= 0x02;
        self.decrypt_response_to(
            Some(SecureRoute {
                source: &source,
                destination: &destination,
                l2_destination: &l2_destination,
                source_route: &[],
            }),
            received,
            correlation,
        )
        .await
    }

    pub(crate) async fn decrypt_response_to(
        &mut self,
        route: Option<SecureRoute<'_>>,
        received: &ReceivedSecureDatagram,
        correlation: &mut RequestCorrelation,
    ) -> Result<SecureResponse, SecureError> {
        let peer_iid = &received.sender_iid;
        if *peer_iid != correlation.destination_peer_iid {
            return Err(SecureError::CorrelationMismatch);
        }
        let pkt = CoapPacket::from_bytes(&received.coap).map_err(|_| SecureError::CoapEncode)?;
        if received.source_port != PORT_COAP || received.destination_port != PORT_COAP {
            return Err(SecureError::CorrelationMismatch);
        }
        if correlation.completed {
            let duplicate =
                correlation
                    .completed_confirmable
                    .as_ref()
                    .is_some_and(|(mid, coap)| {
                        pkt.msg_type() == MessageType::Confirmable
                            && pkt.message_id() == *mid
                            && received.coap == *coap
                    });
            if !duplicate {
                return Err(SecureError::CorrelationMismatch);
            }
            let route = route.ok_or(SecureError::Tx(TxError::NoRoute))?;
            let ack = [
                0x60,
                MessageCode::EMPTY.0,
                (pkt.message_id() >> 8) as u8,
                pkt.message_id() as u8,
            ];
            self.stack
                .send_coap_raw_to(
                    route.source,
                    route.destination,
                    &ack,
                    route.l2_destination,
                    route.source_route,
                    Priority::Normal,
                )
                .await?;
            return Ok(SecureResponse::Acknowledged);
        }
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
        if pkt.code() != MessageCode::CHANGED {
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
            let route = route.ok_or(SecureError::Tx(TxError::NoRoute))?;
            let ack = [
                0x60,
                MessageCode::EMPTY.0,
                (pkt.message_id() >> 8) as u8,
                pkt.message_id() as u8,
            ];
            stack
                .send_coap_raw_to(
                    route.source,
                    route.destination,
                    &ack,
                    route.l2_destination,
                    route.source_route,
                    Priority::Normal,
                )
                .await?;
        }
        let (code, options, payload) = pending.commit().map_err(|_| SecureError::DecryptFailed)?;
        let code = MessageCode(code);
        correlation.completed = true;
        if pkt.msg_type() == MessageType::Confirmable {
            correlation.completed_confirmable = Some((pkt.message_id(), received.coap.clone()));
        }

        Ok(SecureResponse::Decrypted {
            code,
            options: options.to_vec(),
            payload: payload.to_vec(),
        })
    }

    /// Authenticate and classify one response on an OSCORE-protected Observe relationship.
    pub async fn decrypt_observe_response(
        &mut self,
        received: &ReceivedSecureDatagram,
        correlation: &mut SecureObserveCorrelation,
        now_ms: u64,
    ) -> Result<SecureObserveResponse, SecureError> {
        let source = received.destination();
        let destination = received.source();
        let mut l2_destination: [u8; 8] = destination.0[8..].try_into().unwrap();
        l2_destination[0] ^= 0x02;
        self.decrypt_observe_response_to(
            Some(SecureRoute {
                source: &source,
                destination: &destination,
                l2_destination: &l2_destination,
                source_route: &[],
            }),
            received,
            correlation,
            now_ms,
        )
        .await
    }

    async fn decrypt_observe_response_to(
        &mut self,
        route: Option<SecureRoute<'_>>,
        received: &ReceivedSecureDatagram,
        correlation: &mut SecureObserveCorrelation,
        now_ms: u64,
    ) -> Result<SecureObserveResponse, SecureError> {
        let peer_iid = &received.sender_iid;
        if *peer_iid != correlation.request.destination_peer_iid
            || received.source_port != PORT_COAP
            || received.destination_port != PORT_COAP
        {
            return Err(SecureError::CorrelationMismatch);
        }
        let pkt = CoapPacket::from_bytes(&received.coap).map_err(|_| SecureError::CoapEncode)?;

        if pkt.msg_type() == MessageType::Reset {
            if received.coap.len() != 4
                || pkt.code() != MessageCode::EMPTY
                || !pkt.token().is_empty()
                || !correlation.client.reset(*peer_iid, pkt.message_id())
            {
                return Err(SecureError::CorrelationMismatch);
            }
            correlation.active = false;
            correlation.completed_confirmable = None;
            return Ok(SecureObserveResponse::Reset);
        }
        if !correlation.active {
            return Err(SecureError::CorrelationMismatch);
        }

        let exact_retransmission =
            correlation
                .completed_confirmable
                .as_ref()
                .is_some_and(|(message_id, wire)| {
                    pkt.msg_type() == MessageType::Confirmable
                        && pkt.message_id() == *message_id
                        && received.coap == *wire
                });
        if exact_retransmission {
            send_empty_ack(&mut self.stack, route, pkt.message_id()).await?;
            return Ok(SecureObserveResponse::Duplicate);
        }

        if received.coap.len() == 4
            && pkt.msg_type() == MessageType::Acknowledgement
            && pkt.code() == MessageCode::EMPTY
            && pkt.message_id() == correlation.request.message_id
        {
            return Ok(SecureObserveResponse::Acknowledged);
        }
        if pkt.code() != MessageCode::CHANGED
            || pkt.token() != correlation.key.token()
            || (pkt.msg_type() == MessageType::Acknowledgement
                && pkt.message_id() != correlation.request.message_id)
        {
            return Err(SecureError::CorrelationMismatch);
        }

        let (stack, contexts) = (&mut self.stack, &mut self.contexts);
        let ctx = contexts.get_mut(peer_iid).ok_or(SecureError::NoContext)?;
        if ctx.context_id() != correlation.request.context_id {
            return Err(SecureError::CorrelationMismatch);
        }
        let mut oscore_option = None;
        for option in pkt.options() {
            let option = option.map_err(|_| SecureError::DecryptFailed)?;
            if option.number == OSCORE_OPTION {
                if oscore_option.is_some() {
                    return Err(SecureError::DecryptFailed);
                }
                oscore_option = Some(option.value);
            }
        }
        let pending = ctx
            .begin_unprotect_observe_response(
                oscore_option.ok_or(SecureError::DecryptFailed)?,
                pkt.payload(),
                correlation.request.request_piv(),
            )
            .map_err(|_| SecureError::DecryptFailed)?;

        if pkt.msg_type() == MessageType::Confirmable {
            send_empty_ack(stack, route, pkt.message_id()).await?;
        }
        let (code, options, payload) = pending.commit().map_err(|_| SecureError::DecryptFailed)?;
        let notification = observe_notification(&options, pkt.msg_type(), pkt.message_id())?;
        let event = correlation
            .client
            .process(&correlation.key, 0, notification, now_ms)?;
        if event == ClientEvent::Terminated {
            correlation.active = false;
        }
        if pkt.msg_type() == MessageType::Confirmable {
            correlation.completed_confirmable = Some((pkt.message_id(), received.coap.clone()));
        }

        Ok(SecureObserveResponse::Decrypted {
            event,
            code: MessageCode(code),
            options: options.to_vec(),
            payload: payload.to_vec(),
        })
    }

    /// Protect and send a response bound to a decrypted request.
    pub async fn send_secure_response<S: SenderStateStore>(
        &mut self,
        dst: &Addr,
        peer_iid: &[u8; 8],
        request: &SecureRequest,
        response: SecureResponseData<'_>,
        store: &mut S,
    ) -> Result<(), SecureError> {
        let source = self.stack.local_addr();
        self.send_secure_response_to(
            SecureRoute {
                source: &source,
                destination: dst,
                l2_destination: &[],
                source_route: &[],
            },
            peer_iid,
            request,
            response,
            store,
        )
        .await
    }

    pub(crate) async fn send_secure_response_to<S: SenderStateStore>(
        &mut self,
        route: SecureRoute<'_>,
        peer_iid: &[u8; 8],
        request: &SecureRequest,
        response: SecureResponseData<'_>,
        store: &mut S,
    ) -> Result<(), SecureError> {
        if request.sender_iid != *peer_iid {
            return Err(SecureError::CorrelationMismatch);
        }
        let pending_index = self
            .pending_requests
            .iter()
            .position(|pending| pending.request == *request)
            .ok_or(SecureError::CorrelationMismatch)?;
        let metadata = self.pending_requests[pending_index].metadata;
        if !matches!(response.code.class(), 2..=5) {
            return Err(SecureError::EncryptFailed);
        }
        let context = self
            .get_context_mut(peer_iid)
            .ok_or(SecureError::NoContext)?;
        context
            .preflight_protect_response(
                response.options,
                response.payload,
                metadata.identifiers.kid(),
                metadata.identifiers.piv(),
            )
            .map_err(map_protect_error)?;
        let ciphertext_len = 1
            + response.options.len()
            + usize::from(!response.payload.is_empty())
            + response.payload.len()
            + TAG_LEN;
        preflight_secure_frame(
            route.source,
            route.destination,
            route.l2_destination,
            route.source_route,
            metadata.token().len(),
            ciphertext_len,
            1 + PIV_MAX_LEN,
        )?;
        let reservation = context.reserve_sender(store).map_err(|error| match error {
            ReservationError::SequenceExhausted => SecureError::ContextExhausted,
            ReservationError::Conflict => SecureError::ReservationConflict,
            ReservationError::Storage(_) => SecureError::PersistenceFailed,
        })?;
        let (ciphertext, oscore_option) = reservation
            .protect_response_with_piv(
                response.code.0,
                response.options,
                response.payload,
                metadata.identifiers.kid(),
                metadata.identifiers.piv(),
            )
            .map_err(map_protect_error)?;
        let message_type = if metadata.confirmable {
            MessageType::Acknowledgement
        } else {
            MessageType::NonConfirmable
        };
        let message_id = if metadata.confirmable {
            metadata.message_id
        } else {
            self.stack.next_message_id()
        };
        let mut outer = [0u8; 384];
        let mut builder = CoapBuilder::new(
            &mut outer,
            message_type,
            MessageCode::CHANGED,
            message_id,
            metadata.token(),
        )
        .map_err(|_| SecureError::CoapEncode)?;
        builder
            .option(OSCORE_OPTION, oscore_option.as_slice())
            .map_err(|_| SecureError::CoapEncode)?;
        builder
            .payload(ciphertext.as_slice())
            .map_err(|_| SecureError::CoapEncode)?;
        let outer_len = builder.finish();
        self.stack
            .send_coap_raw_to(
                route.source,
                route.destination,
                &outer[..outer_len],
                route.l2_destination,
                route.source_route,
                Priority::Normal,
            )
            .await?;
        self.pending_requests.remove(pending_index);
        Ok(())
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
        secure_datagram_from_received(&frame)
    }

    /// Decrypt a request using its claimed sender IID for context selection, then
    /// authenticate that identity through the matching OSCORE context.
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
        if packet.code() != MessageCode::POST
            || !matches!(
                packet.msg_type(),
                MessageType::Confirmable | MessageType::NonConfirmable
            )
        {
            return Err(SecureError::DecryptFailed);
        }
        if received.destination_port != PORT_COAP {
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
        let identifiers =
            request_identifiers(oscore_option).map_err(|_| SecureError::DecryptFailed)?;
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

        let mut token = [0; MAX_TOKEN_LEN];
        token[..packet.token().len()].copy_from_slice(packet.token());
        let request = SecureRequest {
            code,
            options: options.to_vec(),
            payload: payload.to_vec(),
            sender_iid: received.sender_iid,
        };
        let metadata = RequestMetadata {
            message_id: packet.message_id(),
            token,
            token_len: packet.token().len() as u8,
            confirmable: packet.msg_type() == MessageType::Confirmable,
            identifiers,
        };
        const MAX_PENDING_REQUESTS: usize = 16;
        if self.pending_requests.len() == MAX_PENDING_REQUESTS {
            self.pending_requests.remove(0);
        }
        self.pending_requests.push(PendingRequest {
            request: request.clone(),
            metadata,
        });
        Ok(request)
    }
}

fn append_class_e_option(
    out: &mut [u8],
    length: &mut usize,
    previous: &mut u16,
    number: u16,
    value: &[u8],
) -> Result<(), SecureError> {
    if number < *previous {
        return Err(SecureError::CoapEncode);
    }
    let delta = usize::from(number - *previous);
    let (delta_nibble, delta_ext, delta_ext_len) = option_component(delta)?;
    let (length_nibble, length_ext, length_ext_len) = option_component(value.len())?;
    let needed = 1usize
        .checked_add(delta_ext_len)
        .and_then(|n| n.checked_add(length_ext_len))
        .and_then(|n| n.checked_add(value.len()))
        .and_then(|n| length.checked_add(n))
        .ok_or(SecureError::CoapEncode)?;
    if needed > out.len() {
        return Err(SecureError::CoapEncode);
    }

    let mut cursor = *length;
    out[cursor] = (delta_nibble << 4) | length_nibble;
    cursor += 1;
    out[cursor..cursor + delta_ext_len].copy_from_slice(&delta_ext[..delta_ext_len]);
    cursor += delta_ext_len;
    out[cursor..cursor + length_ext_len].copy_from_slice(&length_ext[..length_ext_len]);
    cursor += length_ext_len;
    out[cursor..cursor + value.len()].copy_from_slice(value);
    *length = needed;
    *previous = number;
    Ok(())
}

fn parse_block_response(
    options: &[u8],
    expected: OptionNumber,
) -> Result<(BlockOption, Option<usize>), SecureError> {
    let mut block = None;
    let mut size2 = None;
    for option in OptionIterator::from_bytes(options) {
        let option = option.map_err(|_| SecureError::Blockwise(CoapError::InvalidBlockOption))?;
        if option.number == expected as u16 {
            if block.is_some() {
                return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
            }
            block = Some(BlockOption::from_bytes(option.value)?);
        } else if option.number == OptionNumber::Block1 as u16
            || option.number == OptionNumber::Block2 as u16
        {
            return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
        } else if option.number == OptionNumber::Size2 as u16 {
            if expected != OptionNumber::Block2 || size2.is_some() {
                return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
            }
            if option.value.len() > 4 || option.value.first() == Some(&0) {
                return Err(SecureError::Blockwise(CoapError::InvalidBlockOption));
            }
            size2 = Some(
                usize::try_from(option.as_uint()?)
                    .map_err(|_| SecureError::Blockwise(CoapError::PayloadTooLarge))?,
            );
        }
    }
    Ok((
        block.ok_or(SecureError::Blockwise(CoapError::InvalidBlockOption))?,
        size2,
    ))
}

fn option_component(value: usize) -> Result<(u8, [u8; 2], usize), SecureError> {
    if value < 13 {
        Ok((value as u8, [0; 2], 0))
    } else if value < 269 {
        Ok((13, [(value - 13) as u8, 0], 1))
    } else if value <= 65_804 {
        let extended = (value - 269) as u16;
        Ok((14, extended.to_be_bytes(), 2))
    } else {
        Err(SecureError::CoapEncode)
    }
}

async fn send_empty_ack<R: Radio>(
    stack: &mut Stack<R>,
    route: Option<SecureRoute<'_>>,
    message_id: u16,
) -> Result<(), SecureError> {
    let route = route.ok_or(SecureError::Tx(TxError::NoRoute))?;
    let ack = [
        0x60,
        MessageCode::EMPTY.0,
        (message_id >> 8) as u8,
        message_id as u8,
    ];
    stack
        .send_coap_raw_to(
            route.source,
            route.destination,
            &ack,
            route.l2_destination,
            route.source_route,
            Priority::Normal,
        )
        .await?;
    Ok(())
}

fn observe_notification(
    options: &[u8],
    message_type: MessageType,
    message_id: u16,
) -> Result<ClientNotification, SecureError> {
    let mut observe = None;
    let mut block2_num = None;
    let mut max_age_ms = 60_000u64;
    let mut max_age_seen = false;
    for option in OptionIterator::from_bytes(options) {
        let option = option.map_err(|_| SecureError::CoapEncode)?;
        match option.number {
            number if number == OptionNumber::Observe as u16 => {
                if observe.is_some() {
                    return Err(SecureError::Observe(ObserveError::InvalidObserveValue));
                }
                observe = Some(option.as_observe()?);
            }
            number if number == OptionNumber::MaxAge as u16 => {
                if max_age_seen {
                    return Err(SecureError::CoapEncode);
                }
                max_age_seen = true;
                max_age_ms = u64::from(option.as_uint().map_err(|_| SecureError::CoapEncode)?)
                    .checked_mul(1_000)
                    .ok_or(SecureError::CoapEncode)?;
            }
            number if number == OptionNumber::Block2 as u16 => {
                if block2_num.is_some() {
                    return Err(SecureError::CoapEncode);
                }
                block2_num = Some(
                    BlockOption::from_bytes(option.value)
                        .map_err(|_| SecureError::CoapEncode)?
                        .num,
                );
            }
            _ => {}
        }
    }
    Ok(ClientNotification {
        message_type,
        message_id,
        observe,
        block2_num,
        max_age_ms,
    })
}

fn preflight_secure_frame(
    source: &Addr,
    destination: &Addr,
    l2_destination: &[u8],
    source_route: &[[u8; 16]],
    token_len: usize,
    ciphertext_len: usize,
    oscore_option_len: usize,
) -> Result<(), SecureError> {
    let option_header_len = if oscore_option_len < 13 {
        1
    } else if oscore_option_len < 269 {
        2
    } else {
        3
    };
    let coap_len = 4usize
        .checked_add(token_len)
        .and_then(|n| n.checked_add(option_header_len))
        .and_then(|n| n.checked_add(oscore_option_len))
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(ciphertext_len))
        .ok_or(SecureError::CoapEncode)?;
    if coap_len > 256 - IPV6_HEADER_LEN - UDP_HEADER_LEN {
        return Err(SecureError::CoapEncode);
    }
    // Account for the authenticated frame's mandatory signer EUI-64. Extended
    // addressing additionally carries the eight-byte link destination.
    let max_schc_len = if l2_destination.len() == 8 { 185 } else { 193 };
    let schc_len = if source_route.len() > 1 {
        let routing_len = 8usize
            .checked_add(
                source_route
                    .len()
                    .checked_sub(1)
                    .and_then(|n| n.checked_mul(16))
                    .ok_or(SecureError::CoapEncode)?,
            )
            .ok_or(SecureError::CoapEncode)?;
        1usize
            .checked_add(IPV6_HEADER_LEN + UDP_HEADER_LEN)
            .and_then(|n| n.checked_add(coap_len))
            .and_then(|n| n.checked_add(routing_len))
            .ok_or(SecureError::CoapEncode)?
    } else if is_link_local(&source.0) && is_link_local(&destination.0) {
        coap_len.checked_add(22).ok_or(SecureError::CoapEncode)?
    } else if is_global(&source.0) && is_global(&destination.0) {
        coap_len.checked_add(38).ok_or(SecureError::CoapEncode)?
    } else {
        1usize
            .checked_add(IPV6_HEADER_LEN + UDP_HEADER_LEN)
            .and_then(|n| n.checked_add(coap_len))
            .ok_or(SecureError::CoapEncode)?
    };
    if schc_len > max_schc_len {
        return Err(SecureError::CoapEncode);
    }
    Ok(())
}

fn is_link_local(address: &[u8; 16]) -> bool {
    address[0] == 0xfe && address[1] & 0xc0 == 0x80
}

fn is_global(address: &[u8; 16]) -> bool {
    address[0] >> 5 == 0b001
}

pub(crate) fn secure_datagram_from_received(
    frame: &ReceivedIpv6,
) -> Result<Option<ReceivedSecureDatagram>, RxError> {
    let header = Ipv6Header::from_bytes(&frame.ipv6).map_err(|_| RxError::SchcDecompress)?;
    let payload_len = usize::from(header.payload_len);
    if IPV6_HEADER_LEN.checked_add(payload_len) != Some(frame.ipv6.len()) {
        return Err(RxError::SchcDecompress);
    }
    let (transport, transport_offset, transport_len, final_destination) =
        secure_transport(&frame.ipv6, &header)?;
    if transport != next_header::UDP {
        return Ok(None);
    }
    if transport_len < UDP_HEADER_LEN {
        return Err(RxError::SchcDecompress);
    }

    let udp_bytes = &frame.ipv6[transport_offset..];
    let udp = UdpHeader::from_bytes(udp_bytes).map_err(|_| RxError::SchcDecompress)?;
    let udp_len = usize::from(udp.length);
    if udp_len < UDP_HEADER_LEN || udp_len != transport_len {
        return Err(RxError::SchcDecompress);
    }
    if udp.checksum == 0 {
        return Err(RxError::SchcDecompress);
    }
    if udp.dst_port != PORT_COAP && udp.src_port != PORT_COAP {
        return Ok(None);
    }

    let coap = &udp_bytes[UDP_HEADER_LEN..udp_len];
    let mut expected_udp = [0; UDP_HEADER_LEN];
    UdpHeader::new(udp.src_port, udp.dst_port)
        .write_header_to(&header.src, &final_destination, coap, &mut expected_udp)
        .map_err(|_| RxError::SchcDecompress)?;
    if udp_bytes[6..8] != expected_udp[6..8] {
        return Err(RxError::SchcDecompress);
    }
    let packet = CoapPacket::from_bytes(coap).map_err(|_| RxError::MalformedSecureCoap)?;
    let empty_ack = coap.len() == 4
        && packet.msg_type() == MessageType::Acknowledgement
        && packet.code() == MessageCode::EMPTY;
    let mut oscore_option = None;
    let mut oscore_options = 0;
    for option in packet.options() {
        let option = option.map_err(|_| RxError::MalformedSecureCoap)?;
        if option.number == OSCORE_OPTION {
            oscore_options += 1;
            oscore_option = Some(option.value);
        }
    }
    let sender_iid: [u8; 8] = header.src.0[8..].try_into().unwrap();
    if empty_ack {
        return Ok(Some(ReceivedSecureDatagram {
            coap: coap.to_vec(),
            sender_iid,
            source: Addr(header.src.0),
            destination: final_destination,
            source_port: udp.src_port,
            destination_port: udp.dst_port,
            rssi: frame.rssi,
            snr: frame.snr,
        }));
    }
    if oscore_options != 1 {
        return Err(RxError::PlaintextCoap);
    }
    if packet.payload().is_empty() {
        return Err(RxError::MalformedSecureCoap);
    }
    validate_option(oscore_option.unwrap()).map_err(|_| RxError::MalformedSecureCoap)?;

    Ok(Some(ReceivedSecureDatagram {
        coap: coap.to_vec(),
        sender_iid,
        source: Addr(header.src.0),
        destination: final_destination,
        source_port: udp.src_port,
        destination_port: udp.dst_port,
        rssi: frame.rssi,
        snr: frame.snr,
    }))
}

fn secure_transport(ipv6: &[u8], header: &Ipv6Header) -> Result<(u8, usize, usize, Addr), RxError> {
    let payload_len = usize::from(header.payload_len);
    if header.next_header != 43 {
        if matches!(header.next_header, 0 | 44 | 50 | 51 | 60) {
            return Err(RxError::SchcDecompress);
        }
        return Ok((header.next_header, IPV6_HEADER_LEN, payload_len, header.dst));
    }
    if payload_len < 24 || ipv6.len() < 48 {
        return Err(RxError::SchcDecompress);
    }
    let routing_len = (usize::from(ipv6[41]) + 1) * 8;
    if routing_len < 24
        || routing_len > payload_len
        || (routing_len - 8) % 16 != 0
        || IPV6_HEADER_LEN + routing_len > ipv6.len()
        || ipv6[42] != 3
        || ipv6[44..48] != [0, 0, 0, 0]
    {
        return Err(RxError::SchcDecompress);
    }
    let address_count = (routing_len - 8) / 16;
    let segments_left = usize::from(ipv6[43]);
    if segments_left > address_count {
        return Err(RxError::SchcDecompress);
    }
    // SECURITY: RFC 6554 + LICHEN spec §5 line 418: Segments Left MUST be
    // strictly less than Hop Limit. If equal or greater, the packet cannot
    // complete the source route before TTL expiry.
    if segments_left > 0 && segments_left >= usize::from(header.hop_limit) {
        return Err(RxError::SchcDecompress);
    }
    let final_destination = if segments_left == 0 {
        header.dst
    } else {
        let start = 48 + (address_count - 1) * 16;
        Addr(ipv6[start..start + 16].try_into().unwrap())
    };
    Ok((
        ipv6[40],
        IPV6_HEADER_LEN + routing_len,
        payload_len - routing_len,
        final_destination,
    ))
}

impl<R: Radio> From<Stack<R>> for SecureStack<R> {
    fn from(stack: Stack<R>) -> Self {
        Self::new(stack)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use lichen_coap::{ObserveSequence, ObserveServer, ServerNotification};
    use lichen_hal::loopback::LoopbackRadio;
    use lichen_hal::{ChannelConfig, RadioConfig, RxPacket, TxResult};
    use lichen_link::identity::{Identity, PeerIdentity};
    use lichen_link::Seed;
    use lichen_oscore::{Context as OscoreContext, ContextId, SenderSequenceState};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::vec;

    fn received(coap: &[u8], sender_iid: [u8; 8]) -> ReceivedSecureDatagram {
        let mut sender_eui64 = sender_iid;
        sender_eui64[0] ^= 0x02;
        ReceivedSecureDatagram {
            coap: coap.to_vec(),
            sender_iid,
            source: Addr::link_local_from_eui64(&sender_eui64),
            destination: Addr::link_local_from_eui64(&[0; 8]),
            source_port: PORT_COAP,
            destination_port: PORT_COAP,
            rssi: None,
            snr: None,
        }
    }

    fn protected_response_packet(
        message_type: MessageType,
        message_id: u16,
        token: &[u8],
        oscore_option: &[u8],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut wire = [0u8; 384];
        let mut builder = CoapBuilder::new(
            &mut wire,
            message_type,
            MessageCode::CHANGED,
            message_id,
            token,
        )
        .unwrap();
        builder.option(OSCORE_OPTION, oscore_option).unwrap();
        builder.payload(ciphertext).unwrap();
        let length = builder.finish();
        wire[..length].to_vec()
    }

    fn block_options(number: OptionNumber, block: BlockOption, size2: Option<u32>) -> Vec<u8> {
        let mut encoded = [0u8; 16];
        let mut length = 0;
        let mut previous = 0;
        let mut block_value = [0u8; 3];
        let block_len = block.write_to(&mut block_value).unwrap();
        append_class_e_option(
            &mut encoded,
            &mut length,
            &mut previous,
            number as u16,
            &block_value[..block_len],
        )
        .unwrap();
        if let Some(size2) = size2 {
            let value = size2.to_be_bytes();
            let first = value.iter().position(|byte| *byte != 0).unwrap_or(4);
            append_class_e_option(
                &mut encoded,
                &mut length,
                &mut previous,
                OptionNumber::Size2 as u16,
                &value[first..],
            )
            .unwrap();
        }
        encoded[..length].to_vec()
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

        async fn transmit(
            &mut self,
            _channel: u8,
            payload: &[u8],
        ) -> Result<TxResult, Self::Error> {
            self.events.lock().unwrap().push("transmit");
            let airtime_us = 12_000 + (payload.len() as u32) * 66;
            Ok(TxResult { airtime_us })
        }

        async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn receive(
            &mut self,
            _channel: u8,
            _buf: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            Ok(None)
        }

        fn configure(&mut self, _config: &RadioConfig) {}

        async fn configure_channels(
            &mut self,
            _channels: &[ChannelConfig],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl Radio for SwitchableRadio {
        type Error = ();

        async fn transmit(
            &mut self,
            _channel: u8,
            payload: &[u8],
        ) -> Result<TxResult, Self::Error> {
            if self.fail.load(Ordering::Relaxed) {
                Err(())
            } else {
                let airtime_us = 12_000 + (payload.len() as u32) * 66;
                Ok(TxResult { airtime_us })
            }
        }

        async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn receive(
            &mut self,
            _channel: u8,
            _buf: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<Option<RxPacket>, Self::Error> {
            Ok(None)
        }

        fn configure(&mut self, _config: &RadioConfig) {}

        async fn configure_channels(
            &mut self,
            _channels: &[ChannelConfig],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
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
            SecureStack::from_radio(invalid_radio, invalid_identity, 127, 0),
            Err(SecureError::InvalidEpoch)
        ));

        let (valid_radio, _) = LoopbackRadio::pair();
        let valid_identity = Identity::from_seed(Seed::new([0x72; 32]));
        assert!(SecureStack::from_radio(valid_radio, valid_identity, 128, 0).is_ok());
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
        let mut stack = Stack::new(radio, alice_id, 128, 0);
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
        let context = OscoreContext::new(&[0xab; 16], None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut store)
            .unwrap();
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

        let mut alice_stack = Stack::new(radio_a, alice_id, 128, 0);
        alice_stack.add_peer(bob_peer);

        let mut bob_stack = Stack::new(radio_b, bob_id, 128, 0);
        bob_stack.add_peer(alice_peer);

        let mut alice = SecureStack::new(alice_stack);
        let mut bob = SecureStack::new(bob_stack);

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
        let alice_ctx =
            OscoreContext::new(&master_secret, None, None, &alice_iid[..1], &bob_iid[..1])
                .unwrap()
                .restore_existing(&mut alice_store)
                .unwrap();
        let bob_ctx =
            OscoreContext::new(&master_secret, None, None, &bob_iid[..1], &alice_iid[..1])
                .unwrap()
                .restore_existing(&mut bob_store)
                .unwrap();

        alice
            .restore_context(bob_iid, alice_ctx, &mut alice_store)
            .unwrap();
        bob.restore_context(alice_iid, bob_ctx, &mut bob_store)
            .unwrap();

        let bob_addr = bob.local_addr();
        // Alice sends encrypted GET
        let mut correlation = alice
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
        let mut wrong_request_port = received.clone();
        wrong_request_port.destination_port = 49_152;
        assert_eq!(
            bob.decrypt_request(&wrong_request_port).unwrap_err(),
            SecureError::DecryptFailed
        );
        let request = bob.decrypt_request(&received).unwrap();
        assert_eq!(request.code, MessageCode::GET);
        assert_eq!(request.options, b"\xb7sensors");
        assert!(request.payload.is_empty());
        assert_eq!(request.sender_iid, alice_iid);

        let alice_addr = alice.local_addr();
        let sender_before = bob_store.record;
        assert_eq!(
            bob.send_secure_response(
                &alice_addr,
                &alice_iid,
                &request,
                SecureResponseData {
                    code: MessageCode::GET,
                    options: &[],
                    payload: b"invalid",
                },
                &mut bob_store,
            )
            .await
            .unwrap_err(),
            SecureError::EncryptFailed
        );
        assert_eq!(bob_store.record, sender_before);
        let oversized_payload = [0u8; 129];
        assert_eq!(
            bob.send_secure_response(
                &alice_addr,
                &alice_iid,
                &request,
                SecureResponseData {
                    code: MessageCode::CONTENT,
                    options: &[],
                    payload: &oversized_payload,
                },
                &mut bob_store,
            )
            .await
            .unwrap_err(),
            SecureError::EncryptFailed
        );
        assert_eq!(bob_store.record, sender_before);
        bob.send_secure_response(
            &alice_addr,
            &alice_iid,
            &request,
            SecureResponseData {
                code: MessageCode::CONTENT,
                options: &[],
                payload: b"ok",
            },
            &mut bob_store,
        )
        .await
        .unwrap();
        let response = alice.receive_secure_datagram(1000).await.unwrap().unwrap();
        assert_eq!(
            CoapPacket::from_bytes(response.coap()).unwrap().code(),
            MessageCode::CHANGED
        );
        let mut wrong_response_port = response.clone();
        wrong_response_port.source_port = 49_152;
        assert_eq!(
            alice
                .decrypt_response(&wrong_response_port, &mut correlation)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
        assert!(matches!(
            alice
                .decrypt_response(&response, &mut correlation)
                .await
                .unwrap(),
            SecureResponse::Decrypted { code, payload, .. }
                if code == MessageCode::CONTENT && payload == b"ok"
        ));
    }

    #[tokio::test]
    async fn secure_block1_and_block2_roundtrip_replay_order_and_pivs() {
        let alice_id = Identity::from_seed(Seed::new([0x71; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x72; 32]));
        let alice_iid = alice_id.iid;
        let bob_iid = bob_id.iid;
        let (radio_a, radio_b) = LoopbackRadio::pair();
        let mut alice_stack = Stack::new(radio_a, alice_id, 128, 0);
        alice_stack.add_peer(PeerIdentity::from_pubkey(bob_id.pubkey));
        let mut bob_stack = Stack::new(radio_b, bob_id, 128, 0);
        bob_stack.add_peer(PeerIdentity::from_pubkey(alice_stack.local_public_key()));
        let mut alice = SecureStack::new(alice_stack);
        let mut bob = SecureStack::new(bob_stack);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut alice_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::clone(&events),
            fail: false,
        };
        let mut bob_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events,
            fail: false,
        };
        let secret = [0x73; 16];
        let alice_ctx = OscoreContext::new(&secret, None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut alice_store)
            .unwrap();
        let bob_ctx = OscoreContext::new(&secret, None, None, &[1], &[0])
            .unwrap()
            .restore_existing(&mut bob_store)
            .unwrap();
        alice
            .restore_context(bob_iid, alice_ctx, &mut alice_store)
            .unwrap();
        bob.restore_context(alice_iid, bob_ctx, &mut bob_store)
            .unwrap();
        let bob_addr = bob.local_addr();
        let alice_addr = alice.local_addr();
        let upload_payload: Vec<u8> = (0..100).collect();
        let mut upload = SecureBlock1Transfer::new(&upload_payload, 64).unwrap();
        let mut request_pivs = Vec::new();

        for expected_num in 0..2 {
            let mut correlation = alice
                .send_secure_block1(
                    &bob_addr,
                    &bob_iid,
                    &["ota"],
                    &[0xa1],
                    MessageCode::PUT,
                    &mut upload,
                    &mut alice_store,
                )
                .await
                .unwrap();
            request_pivs.push(correlation.request_piv().to_vec());
            let received = bob.receive_secure_datagram(1_000).await.unwrap().unwrap();
            let replay = received.clone();
            let request = bob.decrypt_request(&received).unwrap();
            assert_eq!(request.code, MessageCode::PUT);
            let block = OptionIterator::from_bytes(&request.options)
                .map(Result::unwrap)
                .find(|option| option.number == OptionNumber::Block1 as u16)
                .unwrap()
                .as_block()
                .unwrap();
            assert_eq!(block.num, expected_num);
            assert_eq!(block.more, expected_num == 0);
            let upload_start = expected_num as usize * 64;
            let upload_end = (upload_start + 64).min(upload_payload.len());
            assert_eq!(request.payload, upload_payload[upload_start..upload_end]);

            let response_options = block_options(OptionNumber::Block1, block, None);
            bob.send_secure_response(
                &alice_addr,
                &alice_iid,
                &request,
                SecureResponseData {
                    code: if block.more {
                        MessageCode::CONTINUE
                    } else {
                        MessageCode::CHANGED
                    },
                    options: &response_options,
                    payload: &[],
                },
                &mut bob_store,
            )
            .await
            .unwrap();
            assert_eq!(
                bob.decrypt_request(&replay).unwrap_err(),
                SecureError::DecryptFailed
            );
            let response = alice.receive_secure_datagram(1_000).await.unwrap().unwrap();
            let progress = alice
                .accept_secure_block1_response(&response, &mut correlation, &mut upload)
                .await
                .unwrap();
            assert_eq!(
                progress,
                if block.more {
                    SecureBlockwiseProgress::More
                } else {
                    SecureBlockwiseProgress::Complete
                }
            );
        }
        assert!(upload.is_complete());
        assert_ne!(request_pivs[0], request_pivs[1]);

        let download_payload: Vec<u8> = (100..200).collect();
        let mut download = SecureBlock2Transfer::new(64);
        for expected_num in 0..2 {
            let mut correlation = alice
                .send_secure_block2(
                    &bob_addr,
                    &bob_iid,
                    &["firmware"],
                    &[0xb2],
                    &mut download,
                    &mut alice_store,
                )
                .await
                .unwrap();
            request_pivs.push(correlation.request_piv().to_vec());
            let received = bob.receive_secure_datagram(1_000).await.unwrap().unwrap();
            let request = bob.decrypt_request(&received).unwrap();
            let requested = OptionIterator::from_bytes(&request.options)
                .map(Result::unwrap)
                .find(|option| option.number == OptionNumber::Block2 as u16)
                .unwrap()
                .as_block()
                .unwrap();
            assert_eq!(requested.num, expected_num);
            let start = expected_num as usize * 64;
            let end = (start + 64).min(download_payload.len());
            let response_block =
                BlockOption::new(expected_num, end < download_payload.len(), 2).unwrap();
            let response_options = block_options(
                OptionNumber::Block2,
                response_block,
                (expected_num == 0).then_some(download_payload.len() as u32),
            );
            bob.send_secure_response(
                &alice_addr,
                &alice_iid,
                &request,
                SecureResponseData {
                    code: MessageCode::CONTENT,
                    options: &response_options,
                    payload: &download_payload[start..end],
                },
                &mut bob_store,
            )
            .await
            .unwrap();
            let response = alice.receive_secure_datagram(1_000).await.unwrap().unwrap();
            let replay = response.clone();
            let progress = alice
                .accept_secure_block2_response(&response, &mut correlation, &mut download)
                .await
                .unwrap();
            assert_eq!(
                progress,
                if response_block.more {
                    SecureBlockwiseProgress::More
                } else {
                    SecureBlockwiseProgress::Complete
                }
            );
            assert_eq!(
                alice
                    .accept_secure_block2_response(&replay, &mut correlation, &mut download)
                    .await
                    .unwrap_err(),
                SecureError::CorrelationMismatch
            );
        }
        assert!(download.is_complete());
        assert_eq!(download.payload(), download_payload);
        for pair in request_pivs.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }

    #[tokio::test]
    async fn receive_secure_datagram_accepts_empty_ack_and_rejects_malformed_option() {
        let alice_id = Identity::from_seed(Seed::new([0x21; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x22; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice_id.pubkey);
        let (radio_a, radio_b) = LoopbackRadio::pair();
        let mut alice = Stack::new(radio_a, alice_id, 128, 0);
        let mut bob = SecureStack::from_radio(radio_b, bob_id, 128, 0).unwrap();
        bob.add_peer(alice_peer);

        let empty_ack = [0x60, 0x00, 0x12, 0x34];
        alice
            .send_coap_raw(&bob.local_addr(), &empty_ack, Priority::Normal)
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
            .send_coap_raw(
                &bob.local_addr(),
                &[0x40, 0x02, 0x12, 0x34, 0x91, 0x20],
                Priority::Normal,
            )
            .await
            .unwrap();

        assert_eq!(
            bob.receive_secure_datagram(1000).await.unwrap_err(),
            RxError::MalformedSecureCoap
        );
    }

    #[test]
    fn secure_classification_rejects_extension_headers() {
        let mut ipv6 = vec![0u8; IPV6_HEADER_LEN + 8];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv6[6] = 44;
        ipv6[7] = 64;
        let received = ReceivedIpv6 {
            ipv6,
            sender_iid: [0x11; 8],
            rssi: None,
            snr: None,
        };

        assert_eq!(
            secure_datagram_from_received(&received),
            Err(RxError::SchcDecompress)
        );
    }

    #[test]
    fn plaintext_coap_source_port_is_rejected() {
        let source = Addr([0xfd, 0, 0, 0, 0, 0, 0, 1, 0x11, 0, 0, 0, 0, 0, 0, 1]);
        let destination = Addr([0xfd, 0, 0, 0, 0, 0, 0, 1, 0x22, 0, 0, 0, 0, 0, 0, 2]);
        let coap = [0x40, 0x45, 0x12, 0x34];
        let mut ipv6 = vec![0u8; IPV6_HEADER_LEN + UDP_HEADER_LEN + coap.len()];
        Ipv6Header::new(next_header::UDP, source, destination)
            .write_to(
                (UDP_HEADER_LEN + coap.len()) as u16,
                &mut ipv6[..IPV6_HEADER_LEN],
            )
            .unwrap();
        UdpHeader::new(PORT_COAP, 49_152)
            .write_header_to(
                &source,
                &destination,
                &coap,
                &mut ipv6[IPV6_HEADER_LEN..IPV6_HEADER_LEN + UDP_HEADER_LEN],
            )
            .unwrap();
        ipv6[IPV6_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(&coap);
        let received = ReceivedIpv6 {
            ipv6,
            sender_iid: [0x11; 8],
            rssi: None,
            snr: None,
        };

        assert_eq!(
            secure_datagram_from_received(&received),
            Err(RxError::PlaintextCoap)
        );
    }

    #[tokio::test]
    async fn ordinary_response_correlation_follows_coap_message_semantics() {
        let identity = Identity::from_seed(Seed::new([0x31; 32]));
        let identity_pubkey = identity.pubkey;
        let peer_identity = Identity::from_seed(Seed::new([0x32; 32]));
        let peer_iid = peer_identity.iid;
        let (radio, peer_radio) = LoopbackRadio::pair();
        let mut secure = SecureStack::new(Stack::new(radio, identity, 128, 0));
        let mut peer_stack = Stack::new(peer_radio, peer_identity, 128, 0);
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
        let client = OscoreContext::new(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some(&[0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]),
            None,
            &[],
            &[1],
        )
        .unwrap()
        .restore_existing(&mut store)
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
            completed_confirmable: None,
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
        separate[0] = MessageCode::CREATED.0;
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
                .unwrap(),
            SecureResponse::Acknowledged
        );
        let duplicate_ack = peer_stack.receive(1000).await.unwrap().unwrap();
        assert_eq!(&duplicate_ack.ipv6[48..], &[0x60, 0x00, 0x99, 0x99]);
    }

    #[tokio::test]
    async fn ack_send_failure_leaves_authenticated_response_retryable() {
        let identity = Identity::from_seed(Seed::new([0x35; 32]));
        let peer_iid = [0x36; 8];
        let fail = Arc::new(AtomicBool::new(true));
        let radio = SwitchableRadio {
            fail: Arc::clone(&fail),
        };
        let mut secure = SecureStack::new(Stack::new(radio, identity, 128, 0));
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
        let client = OscoreContext::new(&secret, None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut client_store)
            .unwrap();
        let mut server = OscoreContext::new(&secret, None, None, &[1], &[0])
            .unwrap()
            .restore_existing(&mut server_store)
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
            .protect_response_with_piv(MessageCode::CONTENT.0, &[], b"prior", &[0], &prior_piv)
            .unwrap();
        let current = server
            .reserve_sender(&mut server_store)
            .unwrap()
            .protect_response_with_piv(MessageCode::CONTENT.0, &[], b"current", &[0], &current_piv)
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
            MessageCode::CHANGED,
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
            completed_confirmable: None,
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
        let mut secure = SecureStack::new(Stack::new(radio, identity, 128, 0));
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
        let mut client = OscoreContext::new(&secret, None, None, &[0], &[1])
            .unwrap()
            .restore_existing(&mut client_store)
            .unwrap();
        let mut server = OscoreContext::new(&secret, None, None, &[1], &[0])
            .unwrap()
            .restore_existing(&mut server_store)
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
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                &[],
                b"response",
                &[0],
                &[request_piv],
            )
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
            completed_confirmable: None,
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

    #[tokio::test]
    async fn protected_observe_registration_notifications_retries_blocks_and_reset() {
        let alice_id = Identity::from_seed(Seed::new([0x51; 32]));
        let bob_id = Identity::from_seed(Seed::new([0x52; 32]));
        let alice_iid = alice_id.iid;
        let bob_iid = bob_id.iid;
        let alice_peer = PeerIdentity::from_pubkey(alice_id.pubkey);
        let bob_peer = PeerIdentity::from_pubkey(bob_id.pubkey);
        let (radio_a, radio_b) = LoopbackRadio::pair();
        let mut alice_stack = Stack::new(radio_a, alice_id, 128, 0);
        alice_stack.add_peer(bob_peer);
        let mut peer_stack = Stack::new(radio_b, bob_id, 128, 0);
        peer_stack.add_peer(alice_peer);
        let mut alice = SecureStack::new(alice_stack);

        let events = Arc::new(Mutex::new(Vec::new()));
        let mut alice_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events: Arc::clone(&events),
            fail: false,
        };
        let mut bob_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: 0,
                exhausted: false,
            },
            events,
            fail: false,
        };
        let secret = [0x53; 16];
        let alice_context = OscoreContext::new(&secret, None, None, &alice_iid[..1], &bob_iid[..1])
            .unwrap()
            .restore_existing(&mut alice_store)
            .unwrap();
        let mut bob_context =
            OscoreContext::new(&secret, None, None, &bob_iid[..1], &alice_iid[..1])
                .unwrap()
                .restore_existing(&mut bob_store)
                .unwrap();
        alice
            .restore_context(bob_iid, alice_context, &mut alice_store)
            .unwrap();

        let bob_addr = peer_stack.local_addr();
        let token = [0xa5];
        let mut correlation = alice
            .send_secure_observe(
                &bob_addr,
                &bob_iid,
                SecureObserveRegistration {
                    uri_path: &["sensors"],
                    token: &token,
                    now_ms: 0,
                    registration_timeout_ms: 10_000,
                },
                &mut alice_store,
            )
            .await
            .unwrap();
        assert!(correlation.is_active());
        assert_eq!(correlation.token(), &token);

        // The protected registration contains canonical Observe=0 followed by Uri-Path.
        let registration_frame = peer_stack.receive(1_000).await.unwrap().unwrap();
        let registration = CoapPacket::from_bytes(&registration_frame.ipv6[48..]).unwrap();
        let registration_oscore = registration
            .options()
            .map(Result::unwrap)
            .find(|option| option.number == OSCORE_OPTION)
            .unwrap();
        let (request_code, request_options, _) = bob_context
            .unprotect_request(registration_oscore.value, registration.payload())
            .unwrap();
        assert_eq!(request_code, MessageCode::GET.0);
        assert_eq!(request_options.as_slice(), b"\x60\x57sensors");

        let observer_key = ObserveKey::new(alice_iid, &token).unwrap();
        let mut observer = ObserveServer::<[u8; 8], 1, 128>::new(60_000, 1_000, 2).unwrap();
        observer.register(observer_key, 0, 0).unwrap();

        let first = bob_context
            .reserve_sender(&mut bob_store)
            .unwrap()
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                b"\x60",
                b"first",
                &alice_iid[..1],
                correlation.request.request_piv(),
            )
            .unwrap();
        let first_wire =
            protected_response_packet(MessageType::Confirmable, 0x2222, &token, &first.1, &first.0);
        observer
            .queue_notification(
                &observer_key,
                ServerNotification {
                    resource: 0,
                    sequence: ObserveSequence::new(0).unwrap(),
                    message_id: 0x2222,
                    confirmable: true,
                    wire: &first_wire,
                    now_ms: 0,
                },
            )
            .unwrap();
        let initial = observer.next_due(0).unwrap();
        let retry = observer.next_due(1_000).unwrap();
        assert_eq!(initial.wire(), retry.wire());
        assert!(!initial.retransmission);
        assert!(retry.retransmission);

        assert!(matches!(
            alice
                .decrypt_observe_response(&received(initial.wire(), bob_iid), &mut correlation, 1)
                .await
                .unwrap(),
            SecureObserveResponse::Decrypted {
                event: ClientEvent::Registered(sequence),
                payload,
                ..
            } if sequence.value() == 0 && payload == b"first"
        ));
        let first_ack = peer_stack.receive(1_000).await.unwrap().unwrap();
        assert_eq!(&first_ack.ipv6[48..], b"\x60\x00\x22\x22");
        assert_eq!(
            alice
                .decrypt_observe_response(&received(retry.wire(), bob_iid), &mut correlation, 2)
                .await
                .unwrap(),
            SecureObserveResponse::Duplicate
        );
        let retry_ack = peer_stack.receive(1_000).await.unwrap().unwrap();
        assert_eq!(&retry_ack.ipv6[48..], b"\x60\x00\x22\x22");
        assert!(observer.acknowledge(alice_iid, 0x2222, 2));

        let second = bob_context
            .reserve_sender(&mut bob_store)
            .unwrap()
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                b"\x61\x01",
                b"second",
                &alice_iid[..1],
                correlation.request.request_piv(),
            )
            .unwrap();
        let second_wire = protected_response_packet(
            MessageType::NonConfirmable,
            0x2223,
            &token,
            &second.1,
            &second.0,
        );
        let wrong_token = protected_response_packet(
            MessageType::NonConfirmable,
            0x2223,
            &[0xb6],
            &second.1,
            &second.0,
        );
        assert_eq!(
            alice
                .decrypt_observe_response(&received(&wrong_token, bob_iid), &mut correlation, 3)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
        let correct_context_id = correlation.request.context_id;
        correlation.request.context_id = bob_context.context_id();
        assert_eq!(
            alice
                .decrypt_observe_response(&received(&second_wire, bob_iid), &mut correlation, 3)
                .await
                .unwrap_err(),
            SecureError::CorrelationMismatch
        );
        correlation.request.context_id = correct_context_id;
        let mut corrupt = second_wire.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            alice
                .decrypt_observe_response(&received(&corrupt, bob_iid), &mut correlation, 3)
                .await
                .unwrap_err(),
            SecureError::DecryptFailed
        );
        assert!(matches!(
            alice
                .decrypt_observe_response(&received(&second_wire, bob_iid), &mut correlation, 3)
                .await
                .unwrap(),
            SecureObserveResponse::Decrypted {
                event: ClientEvent::Notification { sequence, .. },
                payload,
                ..
            } if sequence.value() == 1 && payload == b"second"
        ));
        assert!(peer_stack.receive(0).await.unwrap().is_none());

        // A non-initial Block2 continuation omits Observe and preserves the relationship.
        let continuation = bob_context
            .reserve_sender(&mut bob_store)
            .unwrap()
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                b"\xd1\x0a\x10",
                b"block-1",
                &alice_iid[..1],
                correlation.request.request_piv(),
            )
            .unwrap();
        let continuation_wire = protected_response_packet(
            MessageType::NonConfirmable,
            0x2224,
            &token,
            &continuation.1,
            &continuation.0,
        );
        assert!(matches!(
            alice
                .decrypt_observe_response(
                    &received(&continuation_wire, bob_iid),
                    &mut correlation,
                    4,
                )
                .await
                .unwrap(),
            SecureObserveResponse::Decrypted {
                event: ClientEvent::BlockContinuation,
                ..
            }
        ));

        let invalid_block = bob_context
            .reserve_sender(&mut bob_store)
            .unwrap()
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                b"\x61\x02\xd1\x04\x10",
                b"invalid",
                &alice_iid[..1],
                correlation.request.request_piv(),
            )
            .unwrap();
        let invalid_block_wire = protected_response_packet(
            MessageType::NonConfirmable,
            0x2225,
            &token,
            &invalid_block.1,
            &invalid_block.0,
        );
        assert_eq!(
            alice
                .decrypt_observe_response(
                    &received(&invalid_block_wire, bob_iid),
                    &mut correlation,
                    5,
                )
                .await
                .unwrap_err(),
            SecureError::Observe(ObserveError::InvalidBlockwise)
        );
        assert!(correlation.is_active());

        // The terminal 40-bit responder PIV is valid once; reserving another is forbidden.
        let mut terminal_store = RecordingStore {
            record: None,
            existing: SenderSequenceState {
                next_sequence: lichen_oscore::OscoreSeqNum::MAX,
                exhausted: false,
            },
            events: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let mut terminal_context =
            OscoreContext::new(&secret, None, None, &bob_iid[..1], &alice_iid[..1])
                .unwrap()
                .restore_existing(&mut terminal_store)
                .unwrap();
        let terminal = terminal_context
            .reserve_sender(&mut terminal_store)
            .unwrap()
            .protect_response_with_piv(
                MessageCode::CONTENT.0,
                b"\x61\x03",
                b"terminal",
                &alice_iid[..1],
                correlation.request.request_piv(),
            )
            .unwrap();
        assert_eq!(terminal.1.as_slice(), b"\x05\xff\xff\xff\xff\xff");
        assert!(matches!(
            terminal_context.reserve_sender(&mut terminal_store),
            Err(ReservationError::SequenceExhausted)
        ));
        let terminal_wire = protected_response_packet(
            MessageType::NonConfirmable,
            0x2226,
            &token,
            &terminal.1,
            &terminal.0,
        );
        assert!(matches!(
            alice
                .decrypt_observe_response(&received(&terminal_wire, bob_iid), &mut correlation, 6)
                .await
                .unwrap(),
            SecureObserveResponse::Decrypted {
                event: ClientEvent::Notification { sequence, .. },
                payload,
                ..
            } if sequence.value() == 3 && payload == b"terminal"
        ));

        // Tokenless RST for the last accepted notification cancels the relationship.
        assert_eq!(
            alice
                .decrypt_observe_response(
                    &received(b"\x70\x00\x22\x26", bob_iid),
                    &mut correlation,
                    7,
                )
                .await
                .unwrap(),
            SecureObserveResponse::Reset
        );
        assert!(!correlation.is_active());

        // Reachable peers are cancelled with a separately correlated encrypted Observe=1 GET.
        alice
            .send_secure_observe_cancel(&bob_addr, &bob_iid, &["sensors"], &token, &mut alice_store)
            .await
            .unwrap();
        let cancel_frame = peer_stack.receive(1_000).await.unwrap().unwrap();
        let cancel = CoapPacket::from_bytes(&cancel_frame.ipv6[48..]).unwrap();
        let cancel_oscore = cancel
            .options()
            .map(Result::unwrap)
            .find(|option| option.number == OSCORE_OPTION)
            .unwrap();
        let (cancel_code, cancel_options, _) = bob_context
            .unprotect_request(cancel_oscore.value, cancel.payload())
            .unwrap();
        assert_eq!(cancel_code, MessageCode::GET.0);
        assert_eq!(cancel_options.as_slice(), b"\x61\x01\x57sensors");
    }
}

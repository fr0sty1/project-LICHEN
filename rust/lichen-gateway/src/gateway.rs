//! Gateway state and packet forwarding.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use lichen_coap::codec::{CoapPacket, OptionIterator};
use lichen_coap::message::MessageCode;
#[cfg(test)]
use lichen_core::constants::{L2_DISPATCH_SCHC, SCHC_MAX_DECOMPRESSED};
use lichen_core::ipv6::field;
#[cfg(test)]
use lichen_core::l2_payload::{
    body as l2_payload_body, classify as classify_l2_payload, L2PayloadKind,
};
use lichen_hal::loopback::LoopbackRadio;
use lichen_hal::storage::fs::FileStorage;
use lichen_hal::storage::mem::{MemStorage, MemStorageError};
use lichen_hal::{NonVolatile, Radio};
use lichen_ipv6::Addr;
use lichen_link::identity::{Identity, PeerIdentity};
use lichen_node::{
    announce::AnnounceProcessor,
    gradient::GradientTable,
    rpl_stack::{RplBorderIngressOutcome, RplReceiveError, RplReceiveOutcome, RplStack},
    secure::{SecureError, SecureResponseData, SecureStack},
    stack::{add_rpl_source_route, MAX_FRAME_SIZE},
    RplEvent,
};
use lichen_oscore::{
    Context, ContextId, SenderSequenceState, SenderStateStore, COAP_OPTION_OSCORE,
};
#[cfg(test)]
use lichen_schc::codec::{decompress, SchcError};
#[cfg(test)]
use tracing::info;
use tracing::warn;

use crate::resources::{CoapMethod, CoapResponse, GatewayCoordinator};
use crate::trust::{
    sign, verify, PskError, PskFederation, Seed, TofuResult, TrustError, TrustStore,
    VerifiedGatewayIdentity, SIGNATURE_LEN,
};
use zeroize::Zeroizing;

const MAX_GCP_OSCORE_CONTEXTS: usize = 64;

pub struct Gateway {
    rpl_stack: RplStack<LoopbackRadio, GatewayStorage>,
    radio_peer: LoopbackRadio,
    trust_store: TrustStore,
    trust_persistence: Option<GatewayTrustPersistence>,
    coordinator: GatewayCoordinator,
    oscore_sender_store: GatewayOscoreSenderStore,
    oscore_recipient_store: GatewayOscoreRecipientStore,
    gcp_context_peers: Vec<([u8; 8], ContextId)>,
}

#[derive(Debug)]
struct GatewayOscoreSenderStore {
    records: Vec<(ContextId, SenderSequenceState)>,
    storage: Option<FileStorage>,
    floor_storage: Option<FileStorage>,
    sealing_seed: Option<Zeroizing<[u8; 32]>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayOscoreStoreError {
    Full,
    Io,
    Corrupt,
}

impl GatewayOscoreSenderStore {
    fn ephemeral() -> Self {
        Self {
            records: Vec::new(),
            storage: None,
            floor_storage: None,
            sealing_seed: None,
        }
    }

    fn persistent(
        state_root: &std::path::Path,
        rollback_floor_root: &std::path::Path,
        sealing_seed: &[u8; 32],
    ) -> Result<Self, GatewayOpenError> {
        let storage = FileStorage::new(state_root.join("gcp-oscore-sender"))
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        let floor_storage = FileStorage::new(rollback_floor_root.join("gcp-oscore-sender"))
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        Ok(Self {
            records: Vec::new(),
            storage: Some(storage),
            floor_storage: Some(floor_storage),
            sealing_seed: Some(Zeroizing::new(*sealing_seed)),
        })
    }

    fn key(context_id: &ContextId) -> String {
        format!("sender-{}", hex::encode(context_id.as_bytes()))
    }

    fn floor_key(context_id: &ContextId) -> String {
        format!("{}-floor", Self::key(context_id))
    }

    fn cached(&self, context_id: &ContextId) -> Option<SenderSequenceState> {
        self.records
            .iter()
            .find(|(stored, _)| stored == context_id)
            .map(|(_, state)| *state)
    }

    fn encode_state(state: SenderSequenceState) -> [u8; 9] {
        let mut encoded = [0u8; 9];
        encoded[..8].copy_from_slice(&state.next_sequence.to_be_bytes());
        encoded[8] = u8::from(state.exhausted);
        encoded
    }

    fn decode_state(encoded: &[u8]) -> Result<SenderSequenceState, GatewayOscoreStoreError> {
        if encoded.len() != 9 || encoded[8] > 1 {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        Ok(SenderSequenceState {
            next_sequence: u64::from_be_bytes(
                encoded[..8]
                    .try_into()
                    .expect("checked sender-state length"),
            ),
            exhausted: encoded[8] == 1,
        })
    }

    fn seal(
        &self,
        domain: &[u8],
        context_id: &ContextId,
        state: &[u8; 9],
    ) -> Result<[u8; SIGNATURE_LEN], GatewayOscoreStoreError> {
        let seed = self
            .sealing_seed
            .as_deref()
            .ok_or(GatewayOscoreStoreError::Io)?;
        let transcript = Self::seal_transcript(domain, context_id, state)?;
        let (private, public) = schnorr48::derive_keypair(&Seed::new(*seed));
        Ok(sign(&private, &public, &transcript))
    }

    fn seal_transcript(
        domain: &[u8],
        context_id: &ContextId,
        state: &[u8; 9],
    ) -> Result<Vec<u8>, GatewayOscoreStoreError> {
        let context_len = u16::try_from(context_id.as_bytes().len())
            .map_err(|_| GatewayOscoreStoreError::Corrupt)?;
        let mut transcript = Vec::with_capacity(domain.len() + 2 + context_id.as_bytes().len() + 9);
        transcript.extend_from_slice(domain);
        transcript.extend_from_slice(&context_len.to_be_bytes());
        transcript.extend_from_slice(context_id.as_bytes());
        transcript.extend_from_slice(state);
        Ok(transcript)
    }

    fn read_sealed(
        &self,
        floor: bool,
        key: &str,
        domain: &[u8],
        context_id: &ContextId,
    ) -> Result<Option<SenderSequenceState>, GatewayOscoreStoreError> {
        let storage = if floor {
            self.floor_storage.as_ref()
        } else {
            self.storage.as_ref()
        };
        let Some(storage) = storage else {
            return Ok(None);
        };
        let mut encoded = [0u8; 9 + SIGNATURE_LEN];
        let Some(length) = storage
            .read(key, &mut encoded)
            .map_err(|_| GatewayOscoreStoreError::Io)?
        else {
            return Ok(None);
        };
        if length != encoded.len() {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        let state_bytes: &[u8; 9] = encoded[..9]
            .try_into()
            .expect("fixed sealed sender-state prefix");
        let signature: &[u8; SIGNATURE_LEN] = encoded[9..]
            .try_into()
            .expect("fixed sealed sender-state signature");
        let seed = self
            .sealing_seed
            .as_deref()
            .ok_or(GatewayOscoreStoreError::Io)?;
        let (_, public) = schnorr48::derive_keypair(&Seed::new(*seed));
        let transcript = Self::seal_transcript(domain, context_id, state_bytes)?;
        if !verify(&public, &transcript, signature) {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        Self::decode_state(state_bytes).map(Some)
    }

    fn write_sealed(
        &mut self,
        floor: bool,
        key: &str,
        domain: &[u8],
        context_id: &ContextId,
        state: SenderSequenceState,
    ) -> Result<(), GatewayOscoreStoreError> {
        let state_bytes = Self::encode_state(state);
        let signature = self.seal(domain, context_id, &state_bytes)?;
        let mut encoded = [0u8; 9 + SIGNATURE_LEN];
        encoded[..9].copy_from_slice(&state_bytes);
        encoded[9..].copy_from_slice(&signature);
        let storage = if floor {
            self.floor_storage.as_mut()
        } else {
            self.storage.as_mut()
        };
        storage
            .ok_or(GatewayOscoreStoreError::Io)?
            .write(key, &encoded)
            .map_err(|_| GatewayOscoreStoreError::Io)
    }
}

const OSCORE_STATE_DOMAIN: &[u8] = b"LICHEN-GCP-OSCORE-SENDER-STATE-v1\0";
const OSCORE_FLOOR_DOMAIN: &[u8] = b"LICHEN-GCP-OSCORE-SENDER-FLOOR-v1\0";

fn sender_state_precedes(current: SenderSequenceState, minimum: SenderSequenceState) -> bool {
    (!current.exhausted && minimum.exhausted)
        || (current.exhausted == minimum.exhausted && current.next_sequence < minimum.next_sequence)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecipientReplayState {
    highest: u64,
    window: u32,
    initialized: bool,
}

#[derive(Debug)]
struct GatewayOscoreRecipientStore {
    records: Vec<(ContextId, RecipientReplayState)>,
    storage: Option<FileStorage>,
    floor_storage: Option<FileStorage>,
    sealing_seed: Option<Zeroizing<[u8; 32]>>,
}

const OSCORE_RECIPIENT_STATE_DOMAIN: &[u8] = b"LICHEN-GCP-OSCORE-RECIPIENT-STATE-v1\0";
const OSCORE_RECIPIENT_FLOOR_DOMAIN: &[u8] = b"LICHEN-GCP-OSCORE-RECIPIENT-FLOOR-v1\0";

impl GatewayOscoreRecipientStore {
    fn ephemeral() -> Self {
        Self {
            records: Vec::new(),
            storage: None,
            floor_storage: None,
            sealing_seed: None,
        }
    }

    fn persistent(
        state_root: &std::path::Path,
        rollback_floor_root: &std::path::Path,
        sealing_seed: &[u8; 32],
    ) -> Result<Self, GatewayOpenError> {
        let storage = FileStorage::new(state_root.join("gcp-oscore-recipient"))
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        let floor_storage = FileStorage::new(rollback_floor_root.join("gcp-oscore-recipient"))
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        Ok(Self {
            records: Vec::new(),
            storage: Some(storage),
            floor_storage: Some(floor_storage),
            sealing_seed: Some(Zeroizing::new(*sealing_seed)),
        })
    }

    fn key(context_id: &ContextId, floor: bool) -> String {
        let suffix = if floor { "-floor" } else { "" };
        format!("recipient-{}{}", hex::encode(context_id.as_bytes()), suffix)
    }

    fn encoded(state: RecipientReplayState) -> [u8; 13] {
        let mut bytes = [0u8; 13];
        bytes[..8].copy_from_slice(&state.highest.to_be_bytes());
        bytes[8..12].copy_from_slice(&state.window.to_be_bytes());
        bytes[12] = u8::from(state.initialized);
        bytes
    }

    fn transcript(
        domain: &[u8],
        context_id: &ContextId,
        state: &[u8; 13],
    ) -> Result<Vec<u8>, GatewayOscoreStoreError> {
        let context_len = u16::try_from(context_id.as_bytes().len())
            .map_err(|_| GatewayOscoreStoreError::Corrupt)?;
        let mut transcript =
            Vec::with_capacity(domain.len() + 2 + context_id.as_bytes().len() + state.len());
        transcript.extend_from_slice(domain);
        transcript.extend_from_slice(&context_len.to_be_bytes());
        transcript.extend_from_slice(context_id.as_bytes());
        transcript.extend_from_slice(state);
        Ok(transcript)
    }

    fn read(
        &self,
        context_id: &ContextId,
        floor: bool,
    ) -> Result<Option<RecipientReplayState>, GatewayOscoreStoreError> {
        let storage = if floor {
            self.floor_storage.as_ref()
        } else {
            self.storage.as_ref()
        };
        let Some(storage) = storage else {
            return Ok(None);
        };
        let mut encoded = [0u8; 13 + SIGNATURE_LEN];
        let Some(length) = storage
            .read(&Self::key(context_id, floor), &mut encoded)
            .map_err(|_| GatewayOscoreStoreError::Io)?
        else {
            return Ok(None);
        };
        if length != encoded.len() || encoded[12] > 1 {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        let state_bytes: &[u8; 13] = encoded[..13].try_into().unwrap();
        let signature: &[u8; SIGNATURE_LEN] = encoded[13..].try_into().unwrap();
        let seed = self
            .sealing_seed
            .as_deref()
            .ok_or(GatewayOscoreStoreError::Io)?;
        let (_, public) = schnorr48::derive_keypair(&Seed::new(*seed));
        let domain = if floor {
            OSCORE_RECIPIENT_FLOOR_DOMAIN
        } else {
            OSCORE_RECIPIENT_STATE_DOMAIN
        };
        if !verify(
            &public,
            &Self::transcript(domain, context_id, state_bytes)?,
            signature,
        ) {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        Ok(Some(RecipientReplayState {
            highest: u64::from_be_bytes(state_bytes[..8].try_into().unwrap()),
            window: u32::from_be_bytes(state_bytes[8..12].try_into().unwrap()),
            initialized: state_bytes[12] == 1,
        }))
    }

    fn write(
        &mut self,
        context_id: &ContextId,
        floor: bool,
        state: RecipientReplayState,
    ) -> Result<(), GatewayOscoreStoreError> {
        let state_bytes = Self::encoded(state);
        let seed = self
            .sealing_seed
            .as_deref()
            .ok_or(GatewayOscoreStoreError::Io)?;
        let (private, public) = schnorr48::derive_keypair(&Seed::new(*seed));
        let domain = if floor {
            OSCORE_RECIPIENT_FLOOR_DOMAIN
        } else {
            OSCORE_RECIPIENT_STATE_DOMAIN
        };
        let signature = sign(
            &private,
            &public,
            &Self::transcript(domain, context_id, &state_bytes)?,
        );
        let mut encoded = [0u8; 13 + SIGNATURE_LEN];
        encoded[..13].copy_from_slice(&state_bytes);
        encoded[13..].copy_from_slice(&signature);
        let storage = if floor {
            self.floor_storage.as_mut()
        } else {
            self.storage.as_mut()
        };
        storage
            .ok_or(GatewayOscoreStoreError::Io)?
            .write(&Self::key(context_id, floor), &encoded)
            .map_err(|_| GatewayOscoreStoreError::Io)
    }

    fn precedes(current: RecipientReplayState, floor: RecipientReplayState) -> bool {
        (!current.initialized && floor.initialized)
            || (current.initialized == floor.initialized && current.highest < floor.highest)
            || (floor.initialized
                && current.highest == floor.highest
                && current.window & floor.window != floor.window)
    }

    fn load(
        &mut self,
        context_id: &ContextId,
    ) -> Result<RecipientReplayState, GatewayOscoreStoreError> {
        if let Some((_, state)) = self.records.iter().find(|(stored, _)| stored == context_id) {
            return Ok(*state);
        }
        let empty = RecipientReplayState {
            highest: 0,
            window: 0,
            initialized: false,
        };
        if self.storage.is_none() {
            return Ok(empty);
        }
        let state = self.read(context_id, false)?;
        let floor = self.read(context_id, true)?;
        let state = match (state, floor) {
            (None, None) => empty,
            (None, Some(_)) => return Err(GatewayOscoreStoreError::Corrupt),
            (Some(state), Some(floor)) if Self::precedes(state, floor) => {
                return Err(GatewayOscoreStoreError::Corrupt)
            }
            (Some(state), Some(floor)) if state != floor => {
                self.write(context_id, true, state)?;
                state
            }
            (Some(state), Some(_)) => state,
            (Some(_), None) => return Err(GatewayOscoreStoreError::Corrupt),
        };
        if self.records.len() >= MAX_GCP_OSCORE_CONTEXTS {
            return Err(GatewayOscoreStoreError::Full);
        }
        self.records.push((*context_id, state));
        Ok(state)
    }

    fn is_replay(
        &mut self,
        context_id: &ContextId,
        sequence: u64,
    ) -> Result<bool, GatewayOscoreStoreError> {
        let state = self.load(context_id)?;
        if !state.initialized || sequence > state.highest {
            return Ok(false);
        }
        let difference = state.highest - sequence;
        Ok(difference >= 32 || state.window & (1u32 << difference) != 0)
    }

    fn accept(
        &mut self,
        context_id: &ContextId,
        sequence: u64,
    ) -> Result<(), GatewayOscoreStoreError> {
        if self.is_replay(context_id, sequence)? {
            return Err(GatewayOscoreStoreError::Corrupt);
        }
        let current = self.load(context_id)?;
        let next = if !current.initialized {
            RecipientReplayState {
                highest: sequence,
                window: 1,
                initialized: true,
            }
        } else if sequence > current.highest {
            let shift = sequence - current.highest;
            RecipientReplayState {
                highest: sequence,
                window: if shift >= 32 {
                    1
                } else {
                    (current.window << shift) | 1
                },
                initialized: true,
            }
        } else {
            RecipientReplayState {
                window: current.window | (1u32 << (current.highest - sequence)),
                ..current
            }
        };
        if self.storage.is_some() {
            self.write(context_id, false, next)?;
            self.write(context_id, true, next)?;
        }
        if let Some((_, state)) = self
            .records
            .iter_mut()
            .find(|(stored, _)| stored == context_id)
        {
            *state = next;
        } else {
            if self.records.len() >= MAX_GCP_OSCORE_CONTEXTS {
                return Err(GatewayOscoreStoreError::Full);
            }
            self.records.push((*context_id, next));
        }
        Ok(())
    }
}

impl SenderStateStore for GatewayOscoreSenderStore {
    type Error = GatewayOscoreStoreError;

    fn load(&mut self, context_id: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        if let Some(state) = self.cached(context_id) {
            return Ok(Some(state));
        }
        if self.storage.is_none() {
            return Ok(None);
        }
        let state = self.read_sealed(
            false,
            &Self::key(context_id),
            OSCORE_STATE_DOMAIN,
            context_id,
        )?;
        let floor = self.read_sealed(
            true,
            &Self::floor_key(context_id),
            OSCORE_FLOOR_DOMAIN,
            context_id,
        )?;
        let state = match (state, floor) {
            (None, None) => return Ok(None),
            (None, Some(_)) => return Err(GatewayOscoreStoreError::Corrupt),
            (Some(state), Some(floor)) if sender_state_precedes(state, floor) => {
                return Err(GatewayOscoreStoreError::Corrupt)
            }
            (Some(state), Some(floor)) if state != floor => {
                self.write_sealed(
                    true,
                    &Self::floor_key(context_id),
                    OSCORE_FLOOR_DOMAIN,
                    context_id,
                    state,
                )?;
                state
            }
            (Some(state), Some(_)) => state,
            (Some(_), None) => return Err(GatewayOscoreStoreError::Corrupt),
        };
        if self.records.len() >= MAX_GCP_OSCORE_CONTEXTS {
            return Err(GatewayOscoreStoreError::Full);
        }
        self.records.push((*context_id, state));
        Ok(Some(state))
    }

    fn compare_exchange(
        &mut self,
        context_id: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        let current = self.load(context_id)?;
        if current != expected {
            return Ok(false);
        }
        if current.is_none() && self.records.len() >= MAX_GCP_OSCORE_CONTEXTS {
            return Err(GatewayOscoreStoreError::Full);
        }
        if self.storage.is_some() {
            self.write_sealed(
                false,
                &Self::key(context_id),
                OSCORE_STATE_DOMAIN,
                context_id,
                next,
            )?;
            self.write_sealed(
                true,
                &Self::floor_key(context_id),
                OSCORE_FLOOR_DOMAIN,
                context_id,
                next,
            )?;
        }
        if let Some((_, state)) = self
            .records
            .iter_mut()
            .find(|(stored, _)| stored == context_id)
        {
            *state = next;
        } else {
            if self.records.len() >= MAX_GCP_OSCORE_CONTEXTS {
                return Err(GatewayOscoreStoreError::Full);
            }
            self.records.push((*context_id, next));
        }
        Ok(true)
    }
}

#[derive(Debug)]
struct GatewayTrustPersistence {
    store_path: PathBuf,
    floor_path: PathBuf,
    sealing_seed: Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
enum GatewayStorage {
    Memory(MemStorage),
    File(FileStorage),
}

#[derive(Debug)]
enum GatewayStorageError {
    Memory,
    File,
}

impl NonVolatile for GatewayStorage {
    type Error = GatewayStorageError;

    fn read(&self, key: &str, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self {
            Self::Memory(storage) => storage
                .read(key, buf)
                .map_err(|_: MemStorageError| GatewayStorageError::Memory),
            Self::File(storage) => storage
                .read(key, buf)
                .map_err(|_| GatewayStorageError::File),
        }
    }

    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Memory(storage) => storage
                .write(key, data)
                .map_err(|_: MemStorageError| GatewayStorageError::Memory),
            Self::File(storage) => storage
                .write(key, data)
                .map_err(|_| GatewayStorageError::File),
        }
    }

    fn delete(&mut self, key: &str) -> bool {
        match self {
            Self::Memory(storage) => storage.delete(key),
            Self::File(storage) => storage.delete(key),
        }
    }
}

/// Fail-closed gateway construction error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GatewayOpenError {
    InvalidEpoch,
    RplProvision,
    OscoreStorage,
    InvalidFloorAuthority,
}

/// Durable resources required to open or provision a production gateway.
pub struct GatewayPersistence {
    storage: FileStorage,
    provision: bool,
    state_root: PathBuf,
    rollback_floor_root: PathBuf,
    sealing_seed: Zeroizing<[u8; 32]>,
}

impl GatewayPersistence {
    /// Bind normal state and rollback floors to distinct caller-provisioned
    /// roots. Production callers must additionally verify that the floor root
    /// is backed by an independent monotonic/rollback-resistant authority.
    pub fn new(
        storage: FileStorage,
        provision: bool,
        state_root: PathBuf,
        rollback_floor_root: PathBuf,
        sealing_seed: [u8; 32],
    ) -> Self {
        Self {
            storage,
            provision,
            state_root,
            rollback_floor_root,
            sealing_seed: Zeroizing::new(sealing_seed),
        }
    }
}

struct GatewayBacking {
    storage: GatewayStorage,
    provision: bool,
    trust_persistence: Option<GatewayTrustPersistence>,
    oscore_sender_store: GatewayOscoreSenderStore,
    oscore_recipient_store: GatewayOscoreRecipientStore,
}

impl fmt::Display for GatewayOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEpoch => write!(f, "gateway link epoch must be in 128..=255"),
            Self::RplProvision => write!(f, "gateway RPL root provisioning failed"),
            Self::OscoreStorage => write!(f, "gateway OSCORE sender-state storage failed"),
            Self::InvalidFloorAuthority => write!(
                f,
                "rollback floors require an independent authority outside gateway state"
            ),
        }
    }
}

impl std::error::Error for GatewayOpenError {}

/// Fail-closed federation provisioning error.
#[derive(Debug)]
#[non_exhaustive]
pub enum GatewayFederationError {
    EmptyPeers,
    TooManyPeers,
    DuplicatePeer,
    LocalPeer,
    EphemeralTrustOwner,
    Trust(TrustError),
    Psk(PskError),
    Context(SecureError),
}

impl fmt::Display for GatewayFederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPeers => write!(f, "closed federation requires at least one peer"),
            Self::TooManyPeers => write!(f, "federation exceeds the runtime context capacity"),
            Self::DuplicatePeer => write!(f, "duplicate federation peer"),
            Self::LocalPeer => write!(f, "local gateway cannot be its own federation peer"),
            Self::EphemeralTrustOwner => write!(f, "federation trust owner is not persistent"),
            Self::Trust(error) => write!(f, "federation trust failed: {error}"),
            Self::Psk(error) => write!(f, "federation PSK context failed: {error}"),
            Self::Context(error) => write!(f, "federation OSCORE install failed: {error}"),
        }
    }
}

impl std::error::Error for GatewayFederationError {}

/// Result of one authenticated mesh ingress operation.
#[derive(Debug)]
pub struct GatewayIngress {
    upstream_ipv6: Option<Vec<u8>>,
    mesh_reply: Option<Vec<u8>>,
    rpl_event: RplEvent,
    gcp_dispatched: bool,
}

impl GatewayIngress {
    pub fn upstream_ipv6(&self) -> Option<&[u8]> {
        self.upstream_ipv6.as_deref()
    }

    pub fn into_upstream_ipv6(self) -> Option<Vec<u8>> {
        self.upstream_ipv6
    }

    pub fn mesh_reply(&self) -> Option<&[u8]> {
        self.mesh_reply.as_deref()
    }

    pub fn take_mesh_reply(&mut self) -> Option<Vec<u8>> {
        self.mesh_reply.take()
    }

    pub const fn rpl_event(&self) -> RplEvent {
        self.rpl_event
    }

    /// Whether the runtime recognized and consumed this frame as local GCP
    /// traffic. This is also true for rejected replay/authentication attempts,
    /// which must not be forwarded to the upstream IPv6 interface.
    pub const fn gcp_dispatched(&self) -> bool {
        self.gcp_dispatched
    }
}

impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway")
            .field("node_id", &self.rpl_stack.rpl_node().node().node_id)
            .finish()
    }
}

impl Gateway {
    /// Create a new root gateway with the given identity.
    ///
    /// The root address and DODAG ID are derived from the identity's
    /// public key per spec (unified Ed25519 identity for LICHEN and
    /// Yggdrasil addressing).
    pub fn new(
        identity: Identity,
        safe_epoch: u8,
        trust_store: TrustStore,
        coordinator: GatewayCoordinator,
    ) -> Result<Self, GatewayOpenError> {
        Self::with_storage(
            identity,
            safe_epoch,
            trust_store,
            coordinator,
            GatewayBacking {
                storage: GatewayStorage::Memory(MemStorage::new()),
                provision: true,
                trust_persistence: None,
                oscore_sender_store: GatewayOscoreSenderStore::ephemeral(),
                oscore_recipient_store: GatewayOscoreRecipientStore::ephemeral(),
            },
        )
    }

    /// Open or provision a production gateway using durable RPL state.
    ///
    /// `persistence.provision` is an idempotent provision-or-resume mode: the
    /// RPL owner accepts only missing or matching empty partial state and
    /// rejects mismatched/non-empty remnants. Callers should retain their
    /// first-boot transaction marker until federation provisioning succeeds.
    pub fn new_persistent(
        identity: Identity,
        safe_epoch: u8,
        trust_store: TrustStore,
        coordinator: GatewayCoordinator,
        persistence: GatewayPersistence,
    ) -> Result<Self, GatewayOpenError> {
        let state_root = persistence
            .state_root
            .canonicalize()
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        let rollback_floor_root = persistence
            .rollback_floor_root
            .canonicalize()
            .map_err(|_| GatewayOpenError::OscoreStorage)?;
        if state_root == rollback_floor_root
            || state_root.starts_with(&rollback_floor_root)
            || rollback_floor_root.starts_with(&state_root)
        {
            return Err(GatewayOpenError::InvalidFloorAuthority);
        }
        let oscore_sender_store = GatewayOscoreSenderStore::persistent(
            &state_root,
            &rollback_floor_root,
            &persistence.sealing_seed,
        )?;
        let oscore_recipient_store = GatewayOscoreRecipientStore::persistent(
            &state_root,
            &rollback_floor_root,
            &persistence.sealing_seed,
        )?;
        Self::with_storage(
            identity,
            safe_epoch,
            trust_store,
            coordinator,
            GatewayBacking {
                storage: GatewayStorage::File(persistence.storage),
                provision: persistence.provision,
                trust_persistence: Some(GatewayTrustPersistence {
                    store_path: state_root.join("gateway-trust.bin"),
                    floor_path: rollback_floor_root.join("gateway-trust.generation"),
                    sealing_seed: persistence.sealing_seed,
                }),
                oscore_sender_store,
                oscore_recipient_store,
            },
        )
    }

    fn with_storage(
        identity: Identity,
        safe_epoch: u8,
        trust_store: TrustStore,
        coordinator: GatewayCoordinator,
        backing: GatewayBacking,
    ) -> Result<Self, GatewayOpenError> {
        let root_addr = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
        if coordinator.info.iid != root_addr {
            return Err(GatewayOpenError::RplProvision);
        }
        let dodag_id = root_addr;
        let (radio, radio_peer) = LoopbackRadio::pair();
        let stack = SecureStack::from_radio(radio, identity, safe_epoch, 0)
            .map_err(|_| GatewayOpenError::InvalidEpoch)?;
        let announces =
            AnnounceProcessor::new(GradientTable::new(64), dodag_id[..8].try_into().unwrap());
        let mut rpl_stack = if backing.provision {
            RplStack::provision_root(stack, root_addr, dodag_id, announces, backing.storage)
                .map_err(|_| GatewayOpenError::RplProvision)?
        } else {
            RplStack::open_root(stack, root_addr, dodag_id, announces, backing.storage)
                .map_err(|_| GatewayOpenError::RplProvision)?
        };
        for (_, pinned) in trust_store.entries() {
            let public = lichen_link::keys::PublicKey::new(pinned.pubkey);
            rpl_stack.install_verified_link_peer(PeerIdentity::from_pubkey(public));
        }
        Ok(Self {
            rpl_stack,
            radio_peer,
            trust_store,
            trust_persistence: backing.trust_persistence,
            coordinator,
            oscore_sender_store: backing.oscore_sender_store,
            oscore_recipient_store: backing.oscore_recipient_store,
            gcp_context_peers: Vec::new(),
        })
    }

    /// Explicitly ephemeral constructor for unit tests and simulations that
    /// do not represent a persistent gateway deployment.
    pub fn new_ephemeral(identity: Identity, safe_epoch: u8) -> Result<Self, GatewayOpenError> {
        let root_addr = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
        let trust_store =
            TrustStore::new_ephemeral(64).map_err(|_| GatewayOpenError::RplProvision)?;
        let coordinator = GatewayCoordinator::new_ephemeral(root_addr, 60, 64)
            .map_err(|_| GatewayOpenError::RplProvision)?;
        Self::new(identity, safe_epoch, trust_store, coordinator)
    }

    /// Durable coordination resource owner. Mutations persist their replay
    /// high-water before returning success.
    pub fn coordinator_mut(&mut self) -> &mut GatewayCoordinator {
        &mut self.coordinator
    }

    /// Read-only view of the durable federation trust state.
    pub fn trust_store(&self) -> &TrustStore {
        &self.trust_store
    }

    /// Number of peer-bound GCP OSCORE contexts installed in the runtime.
    pub fn gcp_context_count(&self) -> usize {
        self.gcp_context_peers.len()
    }

    /// Verify, pin, and durably commit a proof-bearing federation identity.
    pub fn admit_gateway(
        &mut self,
        identity: &VerifiedGatewayIdentity,
    ) -> Result<TofuResult, TrustError> {
        let persistence = self
            .trust_persistence
            .as_ref()
            .ok_or_else(|| TrustError::StorageIo("ephemeral gateway trust owner".into()))?;
        let mut candidate = self.trust_store.clone();
        let result = candidate.verify_tofu(identity)?;
        candidate.save_atomic_with_floor(
            &persistence.store_path,
            &persistence.floor_path,
            &persistence.sealing_seed,
        )?;
        let public = lichen_link::keys::PublicKey::new(*identity.pubkey());
        self.rpl_stack
            .install_verified_link_peer(PeerIdentity::from_pubkey(public));
        self.trust_store = candidate;
        Ok(result)
    }

    /// Install one OSCORE context at the exact post-trust runtime boundary.
    /// The peer key must already be durably pinned; otherwise context
    /// installation fails closed and cannot authorize GCP dispatch.
    pub fn install_gcp_context(
        &mut self,
        peer_pubkey: &[u8; 32],
        context: Context,
    ) -> Result<(), SecureError> {
        let peer_iid = lichen_core::addr::iid_from_pubkey_bytes(peer_pubkey);
        if self
            .trust_store
            .get(&peer_iid)
            .is_none_or(|entry| entry.pubkey != *peer_pubkey)
        {
            return Err(SecureError::NoContext);
        }
        let local_iid: [u8; 8] = self.coordinator.info.iid[8..]
            .try_into()
            .map_err(|_| SecureError::NoContext)?;
        const OSCORE_ID_LEN: usize = 7;
        if context.sender_id() != &local_iid[..OSCORE_ID_LEN]
            || context.recipient_id() != &peer_iid[..OSCORE_ID_LEN]
            || self.gcp_context_peers.iter().any(|(installed, _)| {
                installed != &peer_iid && installed[..OSCORE_ID_LEN] == peer_iid[..OSCORE_ID_LEN]
            })
        {
            return Err(SecureError::NoContext);
        }
        let context_id = context.context_id();
        let stored = self
            .oscore_sender_store
            .load(&context_id)
            .map_err(|_| SecureError::PersistenceFailed)?;
        let context = if stored.is_some() {
            context.restore_existing(&mut self.oscore_sender_store)
        } else {
            context.register_fresh(&mut self.oscore_sender_store)
        }
        .map_err(|_| SecureError::PersistenceFailed)?;
        self.rpl_stack
            .restore_context(peer_iid, context, &mut self.oscore_sender_store)?;
        if let Some((_, installed_context)) = self
            .gcp_context_peers
            .iter_mut()
            .find(|(installed, _)| installed == &peer_iid)
        {
            *installed_context = context_id;
        } else {
            self.gcp_context_peers.push((peer_iid, context_id));
        }
        Ok(())
    }

    /// Provision one complete GCP-3.1 closed federation before the daemon
    /// enters its radio loops. Configured public keys are out-of-band trust
    /// anchors; all trust changes are committed once before any context is
    /// installed, and OSCORE sender sequences resume from durable storage.
    pub fn provision_closed_federation(
        &mut self,
        federation: &PskFederation,
        peer_pubkeys: &[[u8; 32]],
    ) -> Result<usize, GatewayFederationError> {
        if peer_pubkeys.is_empty() {
            return Err(GatewayFederationError::EmptyPeers);
        }
        if peer_pubkeys.len() > MAX_GCP_OSCORE_CONTEXTS {
            return Err(GatewayFederationError::TooManyPeers);
        }
        let local_iid: [u8; 8] = self.coordinator.info.iid[8..]
            .try_into()
            .expect("gateway address has a complete IID");
        let mut contexts = Vec::with_capacity(peer_pubkeys.len());
        let mut peer_iids = Vec::with_capacity(peer_pubkeys.len());
        for pubkey in peer_pubkeys {
            let peer_iid = lichen_core::addr::iid_from_pubkey_bytes(pubkey);
            if peer_iid == local_iid {
                return Err(GatewayFederationError::LocalPeer);
            }
            if peer_iids.contains(&peer_iid) {
                return Err(GatewayFederationError::DuplicatePeer);
            }
            let context = federation
                .derive_context(&local_iid, &peer_iid)
                .map_err(GatewayFederationError::Psk)?;
            peer_iids.push(peer_iid);
            contexts.push((*pubkey, context));
        }

        let persistence = self
            .trust_persistence
            .as_ref()
            .ok_or(GatewayFederationError::EphemeralTrustOwner)?;
        let mut candidate = self.trust_store.clone();
        let mut changed = false;
        for pubkey in peer_pubkeys {
            changed |= candidate
                .provision_configured_peer(pubkey)
                .map_err(GatewayFederationError::Trust)?;
        }
        if changed {
            candidate
                .save_atomic_with_floor(
                    &persistence.store_path,
                    &persistence.floor_path,
                    &persistence.sealing_seed,
                )
                .map_err(GatewayFederationError::Trust)?;
        }
        self.trust_store = candidate;
        for (pubkey, context) in contexts {
            let public = lichen_link::keys::PublicKey::new(pubkey);
            self.rpl_stack
                .install_verified_link_peer(PeerIdentity::from_pubkey(public));
            self.install_gcp_context(&pubkey, context)
                .map_err(GatewayFederationError::Context)?;
        }
        Ok(peer_pubkeys.len())
    }

    /// Dispatch one gateway-coordination request through the durable owner.
    /// Mutations require an OSCORE-authenticated public key already pinned in
    /// the trust store; caller-supplied authentication flags alone are not
    /// sufficient.
    pub fn handle_gcp_request(
        &mut self,
        method: CoapMethod,
        path: &str,
        payload: &[u8],
        oscore_verified: bool,
        peer_pubkey: Option<&[u8; 32]>,
        current_superframe: u64,
    ) -> CoapResponse {
        let mutation = matches!(
            method,
            CoapMethod::Post | CoapMethod::Put | CoapMethod::Delete
        );
        if mutation {
            let Some(pubkey) = peer_pubkey else {
                return CoapResponse::unauthorized();
            };
            let iid = lichen_core::addr::iid_from_pubkey_bytes(pubkey);
            if !oscore_verified
                || self
                    .trust_store
                    .get(&iid)
                    .is_none_or(|entry| entry.pubkey != *pubkey)
            {
                return CoapResponse::unauthorized();
            }
        }
        self.coordinator.handle_request(
            method,
            path,
            payload,
            oscore_verified,
            peer_pubkey,
            current_superframe,
        )
    }

    /// Decode a SCHC L2 payload after its enclosing link frame has been
    /// authenticated.  Kept private so transports cannot bypass link replay
    /// and signer checks by presenting a bare L2 payload.
    #[cfg(test)]
    fn decompress_l2_payload(l2_payload: &[u8]) -> Option<Vec<u8>> {
        if classify_l2_payload(l2_payload) != L2PayloadKind::Schc {
            warn!("non-SCHC L2 payload received on upstream gateway path");
            return None;
        }

        let mut out = vec![0u8; SCHC_MAX_DECOMPRESSED];
        match decompress(l2_payload_body(l2_payload), &mut out) {
            Ok(n) => {
                out.truncate(n);
                if out.len() < 40 || out[0] >> 4 != 6 {
                    warn!(len = out.len(), "decompressed frame is not IPv6");
                    return None;
                }
                let payload_len = u16::from_be_bytes([out[4], out[5]]);
                info!(payload_len, "mesh → upstream");
                Some(out)
            }
            Err(SchcError::BufferTooSmall(e)) => {
                warn!(
                    required = e.required,
                    provided = e.provided,
                    "SCHC decompress buffer too small for jumbo packet"
                );
                None
            }
            Err(SchcError::UnknownRuleId(id)) => {
                warn!(rule_id = id, "SCHC: unknown rule — dropping");
                None
            }
            Err(e) => {
                warn!("SCHC decompress: {e:?}");
                None
            }
        }
    }

    /// Admit one complete mesh wire frame through link authentication and
    /// replay protection before any SCHC or RPL processing occurs.
    pub async fn ingest_mesh_frame(
        &mut self,
        wire: &[u8],
        rssi: Option<i16>,
        snr: Option<i8>,
        now_ms: u64,
    ) -> Result<GatewayIngress, RplReceiveError> {
        let current_superframe = self.current_superframe();
        self.ingest_mesh_frame_at_superframe(wire, rssi, snr, now_ms, current_superframe)
            .await
    }

    /// Deterministic runtime ingress with the current synchronized
    /// superframe supplied by the caller/test harness.
    pub async fn ingest_mesh_frame_at_superframe(
        &mut self,
        wire: &[u8],
        rssi: Option<i16>,
        snr: Option<i8>,
        now_ms: u64,
        current_superframe: u64,
    ) -> Result<GatewayIngress, RplReceiveError> {
        self.maintain(now_ms);
        let admitted = self
            .rpl_stack
            .ingest_border_frame(wire, rssi, snr, now_ms)
            .await?;

        let mut gcp_dispatched = false;
        let (upstream_ipv6, rpl_event) = match admitted {
            Some(RplBorderIngressOutcome::Ipv6(received)) => {
                if self
                    .dispatch_runtime_gcp(&received, now_ms, current_superframe)
                    .await
                {
                    gcp_dispatched = true;
                    (None, RplEvent::None)
                } else {
                    (Some(received.ipv6), RplEvent::None)
                }
            }
            Some(RplBorderIngressOutcome::Control(outcome)) => {
                let event = match outcome {
                    RplReceiveOutcome::Rpl(event) => event,
                    RplReceiveOutcome::Dao(_) | RplReceiveOutcome::DaoOriginNotAdmitted => {
                        RplEvent::DaoReceived
                    }
                    _ => RplEvent::None,
                };
                (None, event)
            }
            None => (None, RplEvent::None),
        };

        // The production RPL owner transmits through its radio, so drain the
        // connected endpoint to return the exact signed wire reply/relay to
        // the external HAT, simulator, or serial transport.
        let mesh_reply = if self.radio_peer.has_pending() {
            let mut reply = [0u8; MAX_FRAME_SIZE];
            match self.radio_peer.receive(0, &mut reply, 0).await {
                Ok(Some(packet)) if packet.len <= reply.len() => Some(reply[..packet.len].to_vec()),
                _ => None,
            }
        } else {
            None
        };
        Ok(GatewayIngress {
            upstream_ipv6,
            mesh_reply,
            rpl_event,
            gcp_dispatched,
        })
    }

    /// Exact authenticated post-decryption boundary used by lichend's running
    /// radio ingress loop.
    async fn dispatch_runtime_gcp(
        &mut self,
        received: &lichen_node::stack::ReceivedIpv6,
        now_ms: u64,
        current_superframe: u64,
    ) -> bool {
        let secure = match self.rpl_stack.secure_datagram(received) {
            Ok(Some(secure)) => secure,
            _ => return false,
        };
        let context_id = match self
            .gcp_context_peers
            .iter()
            .find(|(peer_iid, _)| *peer_iid == secure.sender_iid())
            .map(|(_, context_id)| *context_id)
        {
            Some(context_id) => context_id,
            None => return false,
        };
        let partial_iv = match Self::protected_request_sequence(secure.coap()) {
            Some(partial_iv) => partial_iv,
            None => return true,
        };
        match self
            .oscore_recipient_store
            .is_replay(&context_id, partial_iv)
        {
            Ok(false) => {}
            Ok(true) | Err(_) => return true,
        }
        let request = match self.rpl_stack.decrypt_request(&secure) {
            Ok(request) => request,
            // A packet that selected an installed local GCP peer context is
            // control-plane traffic. Authentication/replay failures must be
            // consumed locally, never reclassified as upstream IPv6.
            Err(_) => return true,
        };
        if self
            .oscore_recipient_store
            .accept(&context_id, partial_iv)
            .is_err()
        {
            return true;
        }
        let mut segments: Vec<&[u8]> = Vec::new();
        for option in OptionIterator::from_bytes(&request.options) {
            let Ok(option) = option else {
                return true;
            };
            if option.is_uri_path() {
                segments.push(option.value);
            }
        }
        if segments.len() != 3 || segments[0] != b".well-known" || segments[1] != b"lichen-gw" {
            return true;
        }
        let Ok(resource) = core::str::from_utf8(segments[2]) else {
            return true;
        };
        let method = if request.code == MessageCode::GET {
            CoapMethod::Get
        } else if request.code == MessageCode::POST {
            CoapMethod::Post
        } else if request.code == MessageCode::PUT {
            CoapMethod::Put
        } else if request.code == MessageCode::DELETE {
            CoapMethod::Delete
        } else {
            return true;
        };
        let Some(peer) = self.trust_store.get(&request.sender_iid) else {
            return true;
        };
        let peer_pubkey = peer.pubkey;
        let (response, staged_handoff) = if method == CoapMethod::Post && resource == "handoff" {
            self.coordinator.stage_post_handoff(&request.payload, true)
        } else {
            (
                self.handle_gcp_request(
                    method,
                    resource,
                    &request.payload,
                    true,
                    Some(&peer_pubkey),
                    current_superframe,
                ),
                None,
            )
        };
        // Content-Format is CoAP option 12. It is Class E under OSCORE and
        // therefore belongs in the encrypted inner message. CoAP uint option
        // values use their shortest big-endian representation, including an
        // empty value for zero.
        let mut content_format_option = [0u8; 3];
        let content_format_option_len = if response.content_format == 0 {
            content_format_option[0] = 0xc0;
            1
        } else if response.content_format <= u16::from(u8::MAX) {
            content_format_option[0] = 0xc1;
            content_format_option[1] = response.content_format as u8;
            2
        } else {
            content_format_option[0] = 0xc2;
            content_format_option[1..].copy_from_slice(&response.content_format.to_be_bytes());
            3
        };
        let response_data = SecureResponseData {
            code: MessageCode(response.code),
            options: &content_format_option[..content_format_option_len],
            payload: &response.payload,
        };
        let send_result = self
            .rpl_stack
            .send_secure_response(
                &Addr(
                    received.ipv6[8..24]
                        .try_into()
                        .expect("validated IPv6 source"),
                ),
                &request.sender_iid,
                &request,
                response_data,
                &mut self.oscore_sender_store,
                now_ms,
            )
            .await;
        match (send_result, staged_handoff) {
            (Ok(()), Some(address)) => {
                if !self.coordinator.commit_staged_handoff(&address) {
                    warn!("protected handoff response sent but staged ownership was retained");
                }
            }
            (Err(error), Some(address)) => {
                self.coordinator.rollback_staged_handoff(&address);
                warn!(?error, "authenticated GCP response could not be routed");
            }
            (Err(error), None) => {
                warn!(?error, "authenticated GCP response could not be routed");
            }
            (Ok(()), None) => {}
        }
        true
    }

    /// Extract the request sequence from the single outer OSCORE option.
    /// RFC 8613 encodes the Partial IV length in the low three flag bits and
    /// places the big-endian Partial IV immediately after the flag byte.
    fn protected_request_sequence(coap: &[u8]) -> Option<u64> {
        let packet = CoapPacket::from_bytes(coap).ok()?;
        let mut oscore = None;
        for option in packet.options() {
            let option = option.ok()?;
            if option.number == COAP_OPTION_OSCORE && oscore.replace(option.value).is_some() {
                return None;
            }
        }
        let option = oscore?;
        let flags = *option.first()?;
        let partial_iv_len = usize::from(flags & 0x07);
        if partial_iv_len == 0 || partial_iv_len > 5 || option.len() < 1 + partial_iv_len {
            return None;
        }
        Some(
            option[1..1 + partial_iv_len]
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
        )
    }

    /// Current synchronized GCP superframe from wall-clock epoch and the
    /// coordinator's advertised schedule dimensions.
    pub fn current_superframe(&self) -> u64 {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        Self::superframe_id_at(unix, self.coordinator.info.superframe_duration_s)
    }

    fn superframe_id_at(unix_timestamp: u64, duration_s: u16) -> u64 {
        let duration = u64::from(duration_s);
        if duration == 0 {
            0
        } else {
            unix_timestamp / duration
        }
    }

    /// SCHC-compress an IPv6 packet from the upstream TUN device for the mesh.
    ///
    /// Prefers local RPL mesh (with source routing for Non-Storing mode per
    /// RFC 6554 SRH insertion in local_mesh path). Post-SRH size is accounted
    /// for in buffers and SCHC rules (see lichen-schc and SCHC profile in
    /// spec/drafts/draft-lichen-schc-lora-00.md). Returns the compressed
    /// frame to send via SLIP, or `None` on error.
    pub async fn upstream_to_mesh(&mut self, ipv6_packet: &[u8]) -> Option<Vec<u8>> {
        if ipv6_packet.len() < 40 || ipv6_packet[0] >> 4 != 6 {
            warn!(
                len = ipv6_packet.len(),
                "upstream packet is not IPv6 — dropping"
            );
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6_packet[field::DST_OFFSET..field::DST_OFFSET + 16]);
        if dst[0] == 0xfd {
            warn!("upstream ULA destination is outside the LICHEN native profile");
            return None;
        }
        if self.is_local_mesh(&dst) {
            self.mesh_to_mesh(ipv6_packet).await
        } else {
            self.transmit_ipv6_wire(ipv6_packet, None).await
        }
    }

    /// Check if a destination address is reachable within the local mesh.
    ///
    /// Per spec §7.2, native addresses use the exact `0200::/8` profile.
    /// Local mesh check uses RPL route lookup. Yggdrasil-only addresses
    /// (02xx not in RPL table) are NOT local mesh and should go to the
    /// Yggdrasil TUN.
    pub fn is_local_mesh(&self, dst: &[u8; 16]) -> bool {
        // Link-local: always local
        if dst[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0] {
            return true;
        }

        // GUA (2000::/3): never local mesh — route to upstream
        if dst[0] & 0xe0 == 0x20 {
            return false;
        }

        // Exclude magic discard prefix (NAT64 well-known)
        if dst[0] == 0x00 && dst[1] == 0x64 && dst[2] == 0xff && dst[3] == 0x9b {
            return false;
        }

        // Exact 0200::/8 native profile: local only after DAO admission.
        if dst[0] == 0x02 {
            return self
                .rpl_stack
                .rpl_node()
                .router()
                .lookup_route(dst)
                .is_some();
        }

        // ULA and every other address family are outside the native profile,
        // even if malformed persistent state happens to contain a route.
        false
    }

    /// Run periodic RPL maintenance (prune_neighbors, DAO expiry) using
    /// monotonic time from Instant::elapsed(). Respects defer-external;
    /// does not auto-admit by TOFU (admission requires explicit pin).
    pub fn maintain(&mut self, now_ms: u64) {
        self.rpl_stack.maintain(now_ms, 10_000, &());
    }

    /// Route a packet for a destination that is part of the local RPL mesh.
    ///
    /// Implements RFC 6554 source routing for Non-Storing Mode with two paths:
    ///
    ///   **Root-originated /128 host route** — insert an SRH directly into the
    ///   IPv6 header (swap destination with first hop, list remaining hops in
    ///   the Routing header).
    ///
    ///   **Everything else** (upstream/internet-originated traffic, prefix
    ///   routes shorter than /128) — IPv6-in-IPv6 encapsulation per
    ///   `draft-lichen-rpl-lora-00` §7.4 / RFC 6554 §4.1: the original packet
    ///   is preserved as an inner payload; an outer IPv6+SRH header routes to
    ///   `E`, the last node in the path.
    ///
    /// Link-local destinations are forwarded verbatim. Native 0200::/8
    /// destinations require an admitted RPL route; LICHEN does not use ULA.
    pub async fn mesh_to_mesh(&mut self, ipv6: &[u8]) -> Option<Vec<u8>> {
        if ipv6.len() < 40 || ipv6[0] >> 4 != 6 {
            warn!(len = ipv6.len(), "mesh_to_mesh: not IPv6");
            return None;
        }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ipv6[field::DST_OFFSET..field::DST_OFFSET + 16]);
        let to_compress = if dst[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0] {
            ipv6.to_vec()
        } else {
            if dst[0] != 0x02 {
                return None;
            }
            let route = self
                .rpl_stack
                .rpl_node()
                .router()
                .lookup_route(&dst)?
                .to_vec();
            if route.last() != Some(&dst) {
                return None;
            }
            if route.len() == 1 {
                ipv6.to_vec()
            } else {
                let root_addr = self.rpl_stack.rpl_node().node().node_id.link_local_addr().0;
                let is_root_origin = ipv6[8..24] == root_addr;
                let is_host_route = route.last() == Some(&dst);
                if is_root_origin && is_host_route {
                    let routing_len = 8 + 16 * (route.len() - 1);
                    let total_len = ipv6.len() + routing_len;
                    let mut routed = vec![0u8; total_len];
                    if add_rpl_source_route(ipv6, &route, &mut routed).is_err() {
                        return None;
                    }
                    routed
                } else {
                    let num_addrs = route.len() - 1;
                    let routing_len = 8 + 16 * num_addrs;
                    let outer_payload = routing_len + ipv6.len();
                    let outer_payload_u16 = u16::try_from(outer_payload).ok()?;
                    let outer_hdr = 40 + routing_len;
                    let mut outer = vec![0u8; outer_hdr];
                    outer[0] = 0x60;
                    outer[4..6].copy_from_slice(&outer_payload_u16.to_be_bytes());
                    outer[6] = 43;
                    outer[7] = 64;
                    outer[8..24].copy_from_slice(&root_addr);
                    outer[24..40].copy_from_slice(&route[0]);
                    outer[40] = 41;
                    outer[41] = (routing_len / 8 - 1) as u8;
                    outer[42] = 3;
                    outer[43] = num_addrs as u8;
                    outer[44..48].fill(0);
                    for (i, addr) in route[1..].iter().enumerate() {
                        let start = 48 + i * 16;
                        outer[start..start + 16].copy_from_slice(addr);
                    }
                    let mut encapsulated = Vec::with_capacity(outer_hdr + ipv6.len());
                    encapsulated.extend_from_slice(&outer);
                    encapsulated.extend_from_slice(ipv6);
                    encapsulated
                }
            }
        };
        let destination: [u8; 16] = to_compress[field::DST_OFFSET..field::DST_OFFSET + 16]
            .try_into()
            .ok()?;
        let mut eui64: [u8; 8] = destination[8..].try_into().ok()?;
        eui64[0] ^= 0x02;
        self.transmit_ipv6_wire(&to_compress, Some(eui64)).await
    }

    async fn transmit_ipv6_wire(
        &mut self,
        ipv6: &[u8],
        destination: Option<[u8; 8]>,
    ) -> Option<Vec<u8>> {
        if let Err(error) = self.rpl_stack.send_border_ipv6(ipv6, destination).await {
            warn!(?error, "gateway mesh transmit rejected");
            return None;
        }
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let packet = self
            .radio_peer
            .receive(0, &mut wire, 0)
            .await
            .ok()
            .flatten()?;
        if packet.len > wire.len() {
            return None;
        }
        Some(wire[..packet.len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::{addr::Ipv6Addr, icmpv6};
    use lichen_ipv6::{Addr, UdpHeader};
    use lichen_link::keys::Seed;
    use schnorr48::{derive_keypair, sign};
    use std::sync::atomic::{AtomicU64, Ordering};

    static PERSISTENT_TEST_PATH: AtomicU64 = AtomicU64::new(1);

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    fn test_gateway() -> Gateway {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        Gateway::new_ephemeral(identity, 128).unwrap()
    }

    fn l2_from_wire(wire: &[u8]) -> &[u8] {
        lichen_link::frame::LichenFrame::from_bytes(wire)
            .unwrap()
            .payload
    }

    #[test]
    fn oscore_sender_sequence_store_survives_restart() {
        let suffix = PERSISTENT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lichen-gateway-oscore-restart-{}-{suffix}",
            std::process::id()
        ));
        let floor_path = path.with_extension("floors");
        let context = Context::new(&[0x31; 16], None, None, &[1], &[2]).unwrap();
        let context_id = context.context_id();
        let state = SenderSequenceState {
            next_sequence: 42,
            exhausted: false,
        };
        let sealing_seed = [0x32; 32];
        let mut store =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(store.compare_exchange(&context_id, None, state), Ok(true));
        drop(store);
        let mut reopened =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(reopened.load(&context_id), Ok(Some(state)));
        assert_eq!(
            reopened.compare_exchange(&context_id, None, state),
            Ok(false)
        );
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(floor_path).unwrap();
    }

    #[test]
    fn oscore_sender_sequence_store_rejects_tamper_and_rollback() {
        let suffix = PERSISTENT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lichen-gateway-oscore-rollback-{}-{suffix}",
            std::process::id()
        ));
        let floor_path = path.with_extension("floors");
        let context = Context::new(&[0x41; 16], None, None, &[1], &[2]).unwrap();
        let context_id = context.context_id();
        let sealing_seed = [0x42; 32];
        let first = SenderSequenceState {
            next_sequence: 42,
            exhausted: false,
        };
        let second = SenderSequenceState {
            next_sequence: 43,
            exhausted: false,
        };
        let mut store =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(store.compare_exchange(&context_id, None, first), Ok(true));
        let record_path = path
            .join("gcp-oscore-sender")
            .join(GatewayOscoreSenderStore::key(&context_id));
        let first_record = std::fs::read(&record_path).unwrap();
        assert_eq!(
            store.compare_exchange(&context_id, Some(first), second),
            Ok(true)
        );
        drop(store);
        let second_record = std::fs::read(&record_path).unwrap();

        std::fs::write(&record_path, &first_record).unwrap();
        let mut rolled_back =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(
            rolled_back.load(&context_id),
            Err(GatewayOscoreStoreError::Corrupt)
        );

        let mut tampered_record = second_record.clone();
        tampered_record[0] ^= 0x80;
        std::fs::write(&record_path, &tampered_record).unwrap();
        let mut tampered =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(
            tampered.load(&context_id),
            Err(GatewayOscoreStoreError::Corrupt)
        );

        std::fs::write(&record_path, &second_record).unwrap();
        let mut reopened =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(reopened.load(&context_id), Ok(Some(second)));
        drop(reopened);
        std::fs::remove_file(
            floor_path
                .join("gcp-oscore-sender")
                .join(GatewayOscoreSenderStore::floor_key(&context_id)),
        )
        .unwrap();
        let mut missing_floor =
            GatewayOscoreSenderStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(
            missing_floor.load(&context_id),
            Err(GatewayOscoreStoreError::Corrupt)
        );
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(floor_path).unwrap();
    }

    #[test]
    fn oscore_recipient_replay_store_survives_restart() {
        let suffix = PERSISTENT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lichen-gateway-oscore-recipient-{}-{suffix}",
            std::process::id()
        ));
        let floor_path = path.with_extension("floors");
        let context = Context::new(&[0x51; 16], None, None, &[1], &[2]).unwrap();
        let context_id = context.context_id();
        let sealing_seed = [0x52; 32];
        let mut store =
            GatewayOscoreRecipientStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(store.is_replay(&context_id, 42), Ok(false));
        assert_eq!(store.accept(&context_id, 42), Ok(()));
        assert_eq!(store.accept(&context_id, 40), Ok(()));
        drop(store);

        let mut reopened =
            GatewayOscoreRecipientStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(reopened.is_replay(&context_id, 42), Ok(true));
        assert_eq!(reopened.is_replay(&context_id, 40), Ok(true));
        assert_eq!(reopened.is_replay(&context_id, 41), Ok(false));
        assert_eq!(reopened.is_replay(&context_id, 43), Ok(false));
        assert_eq!(reopened.accept(&context_id, 43), Ok(()));
        drop(reopened);
        std::fs::remove_file(
            floor_path
                .join("gcp-oscore-recipient")
                .join(GatewayOscoreRecipientStore::key(&context_id, true)),
        )
        .unwrap();
        let mut missing_floor =
            GatewayOscoreRecipientStore::persistent(&path, &floor_path, &sealing_seed).unwrap();
        assert_eq!(
            missing_floor.is_replay(&context_id, 44),
            Err(GatewayOscoreStoreError::Corrupt)
        );
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(floor_path).unwrap();
    }

    #[test]
    fn protected_request_sequence_requires_one_nonempty_partial_iv() {
        let request = [0x40, MessageCode::POST.0, 0, 1, 0x92, 0x01, 0x2a];
        assert_eq!(Gateway::protected_request_sequence(&request), Some(42));

        let empty_partial_iv = [0x40, MessageCode::POST.0, 0, 1, 0x91, 0x00];
        assert_eq!(Gateway::protected_request_sequence(&empty_partial_iv), None);

        let duplicate = [
            0x40,
            MessageCode::POST.0,
            0,
            1,
            0x92,
            0x01,
            0x2a,
            0x02,
            0x01,
            0x2b,
        ];
        assert_eq!(Gateway::protected_request_sequence(&duplicate), None);
    }

    #[test]
    fn persistent_gateway_rejects_floor_inside_state_rollback_domain() {
        let suffix = PERSISTENT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lichen-gateway-invalid-floor-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        let identity = Identity::from_seed(Seed::new([0x61; 32]));
        let root = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
        let coordinator = GatewayCoordinator::new_ephemeral(root, 60, 8).unwrap();
        let result = Gateway::new_persistent(
            identity,
            128,
            TrustStore::new_ephemeral(8).unwrap(),
            coordinator,
            GatewayPersistence::new(
                FileStorage::new(&path).unwrap(),
                true,
                path.clone(),
                path.clone(),
                [0x62; 32],
            ),
        );
        assert!(matches!(
            result,
            Err(GatewayOpenError::InvalidFloorAuthority)
        ));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn persistent_gateway_reopens_existing_rpl_root_state() {
        let suffix = PERSISTENT_TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lichen-gateway-rpl-restart-{}-{suffix}",
            std::process::id()
        ));
        let floor_root = path.with_extension("floors");
        let identity = Identity::from_seed(Seed::new([0x71; 32]));
        let root = lichen_core::addr::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
        let replay_path = path.join("gateway-slot-replay.bin");
        let replay_floor_path = floor_root.join("gateway-slot-replay.generation");
        let sealing_seed = [0x72; 32];
        std::fs::create_dir_all(&path).unwrap();
        std::fs::create_dir_all(&floor_root).unwrap();
        let trust = TrustStore::new_ephemeral(8).unwrap();
        let coordinator = GatewayCoordinator::provision_persistent(
            root,
            60,
            64,
            &replay_path,
            &replay_floor_path,
            &sealing_seed,
        )
        .unwrap();
        let storage = FileStorage::new(&path).unwrap();
        let mut gateway = Gateway::new_persistent(
            identity.clone(),
            128,
            trust,
            coordinator,
            GatewayPersistence::new(
                storage,
                true,
                path.clone(),
                floor_root.clone(),
                sealing_seed,
            ),
        )
        .unwrap();

        let challenge = [0x73; 32];
        let (remote_private, remote_public) = derive_keypair(&Seed::new([0x74; 32]));
        let remote_pubkey = *remote_public.as_bytes();
        let remote_iid = crate::trust::iid_from_pubkey(&remote_pubkey);
        let transcript = crate::trust::build_identity_proof_transcript(&remote_iid, &challenge);
        let proof = sign(&remote_private, &remote_public, &transcript);
        let verified = VerifiedGatewayIdentity::verify(
            &remote_pubkey,
            &remote_iid,
            &challenge,
            &challenge,
            &proof,
        )
        .unwrap();
        let mut ephemeral = test_gateway();
        assert!(ephemeral.admit_gateway(&verified).is_err());
        assert!(ephemeral.trust_store().get(&remote_iid).is_none());
        assert_eq!(
            gateway.admit_gateway(&verified),
            Ok(TofuResult::PinAndAccept)
        );
        assert_eq!(
            gateway
                .handle_gcp_request(
                    CoapMethod::Post,
                    "handoff",
                    &[0xff],
                    true,
                    Some(&remote_pubkey),
                    1,
                )
                .code,
            0x80,
            "pinned authenticated peer reaches the durable resource parser"
        );
        assert_eq!(
            gateway
                .handle_gcp_request(
                    CoapMethod::Post,
                    "handoff",
                    &[0xff],
                    true,
                    Some(&[0x75; 32]),
                    1,
                )
                .code,
            0x81
        );
        drop(gateway);

        let trust_floor_bytes: [u8; 8] = std::fs::read(floor_root.join("gateway-trust.generation"))
            .unwrap()
            .try_into()
            .unwrap();
        let trust = TrustStore::load(
            &path.join("gateway-trust.bin"),
            &sealing_seed,
            u64::from_be_bytes(trust_floor_bytes),
            8,
        )
        .unwrap();
        let coordinator = GatewayCoordinator::load_persistent(
            root,
            60,
            64,
            &replay_path,
            &replay_floor_path,
            &sealing_seed,
        )
        .unwrap();
        let mut reopened = Gateway::new_persistent(
            identity,
            129,
            trust,
            coordinator,
            GatewayPersistence::new(
                FileStorage::new(&path).unwrap(),
                false,
                path.clone(),
                floor_root.clone(),
                sealing_seed,
            ),
        )
        .unwrap();
        assert!(reopened.rpl_stack.rpl_node().router().is_root());
        assert_eq!(
            reopened
                .handle_gcp_request(
                    CoapMethod::Post,
                    "handoff",
                    &[0xff],
                    true,
                    Some(&remote_pubkey),
                    2,
                )
                .code,
            0x80,
            "trust and GCP replay owners survive a production restart"
        );
        drop(reopened);
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[tokio::test]
    async fn icmpv6_echo_request_round_trips() {
        let src = ll(1);
        let dst = ll(2);
        let mut packet = [0u8; 52];
        let n = icmpv6::echo_request(&src, &dst, 0x1234, 5, b"ping", &mut packet);
        let packet = &packet[..n];

        let mut gw = test_gateway();
        let wire = gw.upstream_to_mesh(packet).await.unwrap();
        let schc = l2_from_wire(&wire);
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2");

        let recovered = Gateway::decompress_l2_payload(schc).unwrap();

        // IPv6 header fields
        assert_eq!(recovered[6], 58, "NH should be ICMPv6");
        assert_eq!(&recovered[8..24], &src.0, "src mismatch");
        assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
        // ICMPv6 fields
        assert_eq!(recovered[40], icmpv6::ECHO_REQUEST, "type should be 128");
        assert_eq!(recovered[41], 0, "code should be 0");
        assert_eq!(&recovered[44..46], &[0x12, 0x34], "id mismatch");
        assert_eq!(&recovered[46..48], &[0x00, 0x05], "seq mismatch");
        assert_eq!(&recovered[48..], b"ping", "payload mismatch");
    }

    #[tokio::test]
    async fn icmpv6_echo_reply_round_trips() {
        let src = ll(2);
        let dst = ll(1);
        let mut packet = [0u8; 48];
        let n = icmpv6::echo_reply(&src, &dst, 0x1234, 5, &[], &mut packet);
        let packet = &packet[..n];

        let mut gw = test_gateway();
        let wire = gw.upstream_to_mesh(packet).await.unwrap();
        let schc = l2_from_wire(&wire);
        assert_eq!(schc[0], L2_DISPATCH_SCHC);
        assert_eq!(schc[1], 2, "expected rule 2");

        let recovered = Gateway::decompress_l2_payload(schc).unwrap();
        assert_eq!(recovered[40], icmpv6::ECHO_REPLY, "type should be 129");
        assert_eq!(&recovered[8..24], &src.0, "src mismatch");
        assert_eq!(&recovered[24..40], &dst.0, "dst mismatch");
    }

    #[tokio::test]
    async fn non_ipv6_upstream_is_dropped() {
        let mut gw = test_gateway();
        assert!(gw.upstream_to_mesh(&[0u8; 40]).await.is_none());
    }

    #[test]
    fn unknown_schc_rule_is_dropped() {
        assert!(Gateway::decompress_l2_payload(&[L2_DISPATCH_SCHC, 0xAAu8, 0x00,]).is_none());
    }

    #[test]
    fn non_schc_l2_payload_is_dropped() {
        assert!(Gateway::decompress_l2_payload(&[0x15, 0x01]).is_none());
    }

    #[test]
    fn yggdrasil_cross_mesh_routing() {
        let gw = test_gateway();
        let local = ll(1);
        let ygg_cross = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let nat64 = [
            0x00u8, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1,
        ];
        assert!(gw.is_local_mesh(&local.0));
        assert!(!gw.is_local_mesh(&ygg_cross));
        assert!(!gw.is_local_mesh(&nat64));
    }

    #[test]
    fn canonical_superframe_id_uses_absolute_unix_time() {
        assert_eq!(Gateway::superframe_id_at(1_720_008_000, 60), 28_666_800);
        assert_eq!(Gateway::superframe_id_at(u64::MAX, 0), 0);
    }

    #[tokio::test]
    async fn unknown_route_is_dropped_in_mesh_to_mesh() {
        let mut gw = test_gateway();
        let dst = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        assert!(!gw.is_local_mesh(&dst));
        let packet = [
            0x60, 0, 0, 0, 40, 0, 58, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        ];
        let result = gw.mesh_to_mesh(&packet).await;
        assert!(result.is_none());
    }

    #[test]
    fn dao_route_makes_ygg_address_local() {
        let mut gw = test_gateway();
        let node_addr = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];

        // Gateway is a root; no route yet — not local
        assert!(gw.rpl_stack.rpl_node().router().is_root());
        assert!(!gw.is_local_mesh(&node_addr));

        // Inject a DAO route
        let root_addr = gw.rpl_stack.rpl_node().node().node_id.link_local_addr().0;
        let path = [root_addr, node_addr];
        gw.rpl_stack
            .rpl_node_mut()
            .router_mut()
            .inject_route(node_addr, &path);

        // Now the 02xx address is local mesh
        assert!(gw.is_local_mesh(&node_addr));
    }

    #[tokio::test]
    async fn root_originated_downward_srh() {
        let mut gw = test_gateway();
        let root_addr = gw.rpl_stack.rpl_node().node().node_id.link_local_addr().0;
        let node_addr = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];

        // Inject DAO route: root → node_addr (single hop)
        let path = [root_addr, node_addr];
        gw.rpl_stack
            .rpl_node_mut()
            .router_mut()
            .inject_route(node_addr, &path);

        // Build IPv6 packet FROM root TO node_addr
        let payload = b"hello";
        let udp_len = 8 + payload.len();
        let payload_len = udp_len as u16;
        let mut packet = vec![0u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 17; // UDP NH
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&root_addr);
        packet[24..40].copy_from_slice(&node_addr);
        UdpHeader::new(5683, 5683)
            .write_packet_to(
                &Addr(root_addr),
                &Addr(node_addr),
                payload,
                &mut packet[40..],
            )
            .unwrap();

        let result = gw.mesh_to_mesh(&packet).await;
        assert!(result.is_some(), "expected SRH-compressed payload");
        let wire = result.unwrap();
        let compressed = l2_from_wire(&wire);
        assert_eq!(compressed[0], L2_DISPATCH_SCHC);

        // Decompress and verify SRH was inserted
        let mut decompressed = [0u8; lichen_core::constants::SCHC_MAX_DECOMPRESSED];
        let n = lichen_schc::codec::decompress(&compressed[1..], &mut decompressed)
            .expect("decompress should succeed");
        assert!(n >= 40, "decompressed IPv6 packet");
        assert_eq!(decompressed[6], 43, "NH should be Routing (SRH)");
        assert_eq!(decompressed[24..40], path[0], "dst = first hop (root→node)");
        assert_eq!(decompressed[40], 17, "inner NH should be UDP");
        assert_eq!(
            decompressed[42], 3,
            "SRH routing type = 3 (RPL source route)"
        );
        // Last address in SRH should be the original destination
        let addr_count = (decompressed[41] as usize + 1) * 8;
        let srh_end = 40 + addr_count;
        let last_addr_start = srh_end - 16;
        assert_eq!(
            &decompressed[last_addr_start..srh_end],
            &node_addr,
            "last SRH address = original dst"
        );
    }
}

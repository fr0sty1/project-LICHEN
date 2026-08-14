//! DAO crypto verification.
//!
//! Signature verification for signed DAO messages.

#[cfg(feature = "std")]
use crate::message::{Dao, DaoEnvelopeError, SignedDaoEnvelope};
#[cfg(feature = "std")]
use lichen_link::{identity::iid_from_pubkey, keys::PublicKey, schnorr};
#[cfg(feature = "std")]
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "std")]
pub const DAO_ORIGIN_DOMAIN: &[u8] = b"LICHEN-DAO-ORIGIN-v1";

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoMalformed {
    MissingSignature,
    DuplicateSignature,
    NonTerminalSignature,
    InvalidOptionLength,
    UnknownOption(u8),
    InvalidDao,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoVerifyError {
    Malformed(DaoMalformed),
    UnknownKey,
    WrongInstance,
    WrongDodag,
    IidMismatch,
    BadSignature,
}

#[cfg(feature = "std")]
#[derive(Debug)]
/// Low-level signature-verified DAO capability.
///
/// This proves cryptography only. Callers must supply a previously authorized
/// key from an external authenticated pin store and separately enforce routing
/// semantics. Application code should use its node-level root handler.
pub struct SignatureVerifiedDao<'a> {
    pub(crate) envelope: SignedDaoEnvelope<'a>,
    pub(crate) origin: [u8; 16],
    pub(crate) public_key: [u8; 32],
    pub(crate) signed_dao_sha256: [u8; 32],
}

#[cfg(feature = "std")]
impl<'a> SignatureVerifiedDao<'a> {
    /// Verify using a key supplied by an external authenticated pin store.
    /// Packet input must never choose `pinned_key` directly.
    pub fn verify_signature(
        wire: &'a [u8],
        origin: [u8; 16],
        rpl_instance_id: u8,
        active_dodag_id: [u8; 16],
        pinned_key: Option<PublicKey>,
    ) -> Result<Self, DaoVerifyError> {
        let dao = Dao::from_bytes(wire)
            .map_err(|_| DaoVerifyError::Malformed(DaoMalformed::InvalidDao))?;
        if dao.flags != 0 || wire[2] != 0 {
            return Err(DaoVerifyError::Malformed(DaoMalformed::InvalidDao));
        }
        if dao.rpl_instance_id != rpl_instance_id {
            return Err(DaoVerifyError::WrongInstance);
        }
        // D=0 uses Some([0; 16]) sentinel meaning "use receiver's DODAG".
        if dao
            .dodag_id
            .is_some_and(|dodag| dodag != [0u8; 16] && dodag != active_dodag_id)
        {
            return Err(DaoVerifyError::WrongDodag);
        }
        let envelope = SignedDaoEnvelope::from_bytes(wire).map_err(map_envelope_error)?;
        let pinned_key = pinned_key.ok_or(DaoVerifyError::UnknownKey)?;
        if origin[8..] != iid_from_pubkey(&pinned_key) {
            return Err(DaoVerifyError::IidMismatch);
        }
        // D=0 uses Some([0; 16]) sentinel - use active_dodag_id for digest.
        let effective_dodag_id = envelope
            .dao
            .dodag_id
            .filter(|id| *id != [0u8; 16])
            .unwrap_or(active_dodag_id);
        let digest = dao_origin_digest(
            origin,
            effective_dodag_id,
            envelope.origin.origin_sequence,
            envelope.unsigned_bytes,
        );
        if !schnorr::verify(&pinned_key, &digest, envelope.origin.signature) {
            return Err(DaoVerifyError::BadSignature);
        }
        Ok(Self {
            envelope,
            origin,
            public_key: *pinned_key.as_bytes(),
            signed_dao_sha256: Sha256::digest(wire).into(),
        })
    }

    pub fn wire(&self) -> &'a [u8] {
        self.envelope.signed_bytes
    }

    pub fn origin_iid(&self) -> [u8; 8] {
        self.origin[8..].try_into().unwrap()
    }
}

#[cfg(feature = "std")]
pub(crate) fn map_envelope_error(error: DaoEnvelopeError) -> DaoVerifyError {
    let malformed = match error {
        DaoEnvelopeError::MissingSignature => DaoMalformed::MissingSignature,
        DaoEnvelopeError::DuplicateSignature => DaoMalformed::DuplicateSignature,
        DaoEnvelopeError::NonTerminalSignature => DaoMalformed::NonTerminalSignature,
        DaoEnvelopeError::InvalidOptionLength => DaoMalformed::InvalidOptionLength,
        DaoEnvelopeError::UnknownOption(option) => DaoMalformed::UnknownOption(option),
        DaoEnvelopeError::Rpl(_) => DaoMalformed::InvalidDao,
    };
    DaoVerifyError::Malformed(malformed)
}

#[cfg(feature = "std")]
pub fn dao_origin_digest(
    origin: [u8; 16],
    dodag_id: [u8; 16],
    origin_sequence: u64,
    unsigned_dao: &[u8],
) -> [u8; 64] {
    Sha512::new()
        .chain_update(DAO_ORIGIN_DOMAIN)
        .chain_update(origin)
        .chain_update(dodag_id)
        .chain_update(origin_sequence.to_be_bytes())
        .chain_update(unsigned_dao)
        .finalize()
        .into()
}

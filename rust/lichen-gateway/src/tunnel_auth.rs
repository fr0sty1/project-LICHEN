//! Fail-closed tunnel authorization for root-to-egress forwarding.
//!
//! The codec and authorization table use fixed-capacity storage and `core`
//! primitives.  The gateway's CoAP/OSCORE transport supplies the authenticated
//! root identity; this module never treats a signature alone as authorization.

use schnorr48::{sign, verify, PrivateKey, PublicKey};
use sha2::{Digest, Sha256};

pub const TUNNEL_AUTH_PATH: &str = "/.well-known/tunnel-auth";
pub const COSE_SCHNORR48_ED25519: i64 = -65_537;
pub const MAX_AUTHORIZATION_WIRE_LEN: usize = 256;
pub const DEFAULT_AUTHORIZATION_CAPACITY: usize = 256;
pub const MAX_ROUTE_HOPS: usize = 8;
pub const COAP_FORBIDDEN_CODE: u8 = 0x83;

const PROTECTED: &[u8; 7] = b"\xa1\x01\x3a\x00\x01\x00\x00";

/// Exact reason an authorization or data-plane decision was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelAuthError {
    BufferTooSmall,
    MalformedCbor,
    NonCanonicalCbor,
    UnsupportedAlgorithm,
    MissingOscoreAuthentication,
    WrongRoot,
    RootIdentityMismatch,
    WrongEgress,
    InvalidPrefix,
    InvalidRoute,
    WrongDirection,
    SourceOutsideMesh,
    DestinationInMesh,
    Expired,
    ClockRollback,
    Replay,
    Revoked,
    InvalidSignature,
    TableDisabled,
    UnauthorizedTunnel,
}

impl TunnelAuthError {
    /// Fail closed without revealing which authorization check failed.
    pub const fn coap_response_code(self) -> u8 {
        COAP_FORBIDDEN_CODE
    }
}

/// Prefix and route authorization signed by the current DODAG root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelAuthorization {
    pub prefix: [u8; 16],
    pub prefix_len: u8,
    pub route_hash: [u8; 16],
    pub path_seq: u64,
    pub expiry: u64,
    pub egress_iid: [u8; 8],
}

impl TunnelAuthorization {
    pub fn new(
        prefix: [u8; 16],
        prefix_len: u8,
        route_hash: [u8; 16],
        path_seq: u64,
        expiry: u64,
        egress_iid: [u8; 8],
    ) -> Result<Self, TunnelAuthError> {
        if prefix_len > 128 || !prefix_is_canonical(&prefix, prefix_len) {
            return Err(TunnelAuthError::InvalidPrefix);
        }
        if route_hash == [0; 16] {
            return Err(TunnelAuthError::InvalidRoute);
        }
        Ok(Self {
            prefix,
            prefix_len,
            route_hash,
            path_seq,
            expiry,
            egress_iid,
        })
    }

    fn matches_source(&self, source: &[u8; 16]) -> bool {
        let whole = usize::from(self.prefix_len / 8);
        let rem = self.prefix_len % 8;
        if self.prefix[..whole] != source[..whole] {
            return false;
        }
        rem == 0 || ((self.prefix[whole] ^ source[whole]) & (u8::MAX << (8 - rem))) == 0
    }
}

/// Fixed-size encoded COSE_Sign1 suitable for a CoAP POST body.
#[derive(Clone, Copy)]
pub struct SignedTunnelAuthorization {
    bytes: [u8; MAX_AUTHORIZATION_WIRE_LEN],
    len: usize,
}

impl SignedTunnelAuthorization {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Authenticated transport identity supplied by the OSCORE resource layer.
pub struct AuthenticatedRoot<'a> {
    pub iid: [u8; 8],
    pub public_key: &'a PublicKey,
    pub oscore_authenticated: bool,
}

/// Root-side result ready to send via OSCORE-protected CoAP POST.
pub struct TunnelAuthPost {
    pub path: &'static str,
    pub content_format: &'static str,
    pub oscore_required: bool,
    pub body: SignedTunnelAuthorization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelDirection {
    MeshToExternal,
    ExternalToMesh,
}

/// Routing facts required for a least-privilege egress decision.
pub struct DecapsulationRequest<'a> {
    pub direction: TunnelDirection,
    pub inner_source: [u8; 16],
    pub source_is_mesh: bool,
    pub destination_is_mesh: bool,
    pub route: &'a [[u8; 8]],
}

/// Build the root's least-privilege authorization POST.
pub fn build_root_post(
    claim: TunnelAuthorization,
    route: &[[u8; 8]],
    root_iid: [u8; 8],
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<TunnelAuthPost, TunnelAuthError> {
    if lichen_core::addr::iid_from_pubkey_bytes(public_key.as_bytes()) != root_iid {
        return Err(TunnelAuthError::RootIdentityMismatch);
    }
    if route.last() != Some(&claim.egress_iid) || route_hash(route)? != claim.route_hash {
        return Err(TunnelAuthError::InvalidRoute);
    }
    Ok(TunnelAuthPost {
        path: TUNNEL_AUTH_PATH,
        content_format: "application/cose; cose-type=\"cose-sign1\"",
        oscore_required: true,
        body: encode_sign1(claim, root_iid, private_key, public_key)?,
    })
}

#[derive(Clone, Copy)]
struct Entry {
    claim: TunnelAuthorization,
    used: u64,
}

#[derive(Clone, Copy)]
struct ReplayFloor {
    prefix: [u8; 16],
    prefix_len: u8,
    route_hash: [u8; 16],
    path_seq: u64,
    revoked: bool,
    used: u64,
}

/// Bounded egress authorization cache.  Validation is completed before any
/// table mutation; replacement is deterministic least-recently-used eviction.
pub struct TunnelAuthorizationTable<const N: usize = DEFAULT_AUTHORIZATION_CAPACITY> {
    entries: [Option<Entry>; N],
    replay_floors: [Option<ReplayFloor>; N],
    root_iid: Option<[u8; 8]>,
    clock: u64,
    last_now: Option<u64>,
}

impl<const N: usize> Default for TunnelAuthorizationTable<N> {
    fn default() -> Self {
        Self {
            entries: [None; N],
            replay_floors: [None; N],
            root_iid: None,
            clock: 0,
            last_now: None,
        }
    }
}

impl<const N: usize> TunnelAuthorizationTable<N> {
    /// Change the trusted DODAG root.  A root change atomically revokes every
    /// authorization; there is no old-root grace interval.
    pub fn set_root(&mut self, root_iid: [u8; 8]) {
        if self.root_iid != Some(root_iid) {
            self.entries.fill(None);
            self.replay_floors.fill(None);
            self.root_iid = Some(root_iid);
            self.clock = 0;
            self.last_now = None;
        }
    }

    pub fn clear(&mut self) {
        self.entries.fill(None);
        self.replay_floors.fill(None);
        self.clock = 0;
        self.last_now = None;
    }

    pub fn revoke(
        &mut self,
        prefix: [u8; 16],
        prefix_len: u8,
        route_hash: [u8; 16],
        path_seq: u64,
    ) -> Result<(), TunnelAuthError> {
        if N == 0 {
            return Err(TunnelAuthError::TableDisabled);
        }
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| {
                entry.claim.prefix == prefix
                    && entry.claim.prefix_len == prefix_len
                    && entry.claim.route_hash == route_hash
            }) {
                *slot = None;
            }
        }
        self.clock = self.clock.saturating_add(1);
        let existing = self.replay_floors.iter().position(|slot| {
            slot.is_some_and(|floor| {
                floor.prefix == prefix
                    && floor.prefix_len == prefix_len
                    && floor.route_hash == route_hash
            })
        });
        let index = existing
            .or_else(|| self.replay_floors.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                self.replay_floors
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, slot)| slot.unwrap().used)
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        let retained = existing
            .and_then(|slot| self.replay_floors[slot])
            .map_or(path_seq, |floor| floor.path_seq.max(path_seq));
        self.replay_floors[index] = Some(ReplayFloor {
            prefix,
            prefix_len,
            route_hash,
            path_seq: retained,
            revoked: true,
            used: self.clock,
        });
        Ok(())
    }

    /// Validate an OSCORE-authenticated POST and atomically cache its claim.
    pub fn accept_post(
        &mut self,
        wire: &[u8],
        authenticated: AuthenticatedRoot<'_>,
        own_iid: [u8; 8],
        now: u64,
    ) -> Result<TunnelAuthorization, TunnelAuthError> {
        if !authenticated.oscore_authenticated {
            return Err(TunnelAuthError::MissingOscoreAuthentication);
        }
        if self.root_iid != Some(authenticated.iid) {
            return Err(TunnelAuthError::WrongRoot);
        }
        if N == 0 {
            return Err(TunnelAuthError::TableDisabled);
        }
        if lichen_core::addr::iid_from_pubkey_bytes(authenticated.public_key.as_bytes())
            != authenticated.iid
        {
            return Err(TunnelAuthError::RootIdentityMismatch);
        }
        let (kid, claim, signature, digest) = decode_and_hash_sign1(wire)?;
        if kid != authenticated.iid {
            return Err(TunnelAuthError::WrongRoot);
        }
        if claim.egress_iid != own_iid {
            return Err(TunnelAuthError::WrongEgress);
        }
        if !verify(authenticated.public_key, &digest, &signature) {
            return Err(TunnelAuthError::InvalidSignature);
        }

        self.check_time(now)?;
        if claim.expiry <= now {
            return Err(TunnelAuthError::Expired);
        }

        let floor = self
            .replay_floors
            .iter()
            .position(|slot| slot.is_some_and(|entry| same_floor_key(&entry, &claim)));
        if let Some(index) = floor {
            let retained = self.replay_floors[index].unwrap();
            if retained.path_seq >= claim.path_seq {
                return Err(if retained.revoked {
                    TunnelAuthError::Revoked
                } else {
                    TunnelAuthError::Replay
                });
            }
        }

        let existing = self
            .entries
            .iter()
            .position(|slot| slot.is_some_and(|entry| same_key(&entry.claim, &claim)));
        let index = existing
            .or_else(|| self.entries.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .min_by(|(_, left), (_, right)| left.unwrap().used.cmp(&right.unwrap().used))
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        self.clock = self.clock.saturating_add(1);
        let floor_index = floor
            .or_else(|| self.replay_floors.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                self.replay_floors
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, slot)| slot.unwrap().used)
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        self.replay_floors[floor_index] = Some(ReplayFloor {
            prefix: claim.prefix,
            prefix_len: claim.prefix_len,
            route_hash: claim.route_hash,
            path_seq: claim.path_seq,
            revoked: false,
            used: self.clock,
        });
        self.entries[index] = Some(Entry {
            claim,
            used: self.clock,
        });
        self.last_now = Some(now);
        Ok(claim)
    }

    /// Authorize only egress decapsulation of an inner source matching the
    /// signed prefix and the exact source-route hash.
    pub fn authorize_decapsulation(
        &mut self,
        request: DecapsulationRequest<'_>,
        now: u64,
    ) -> Result<(), TunnelAuthError> {
        if request.direction != TunnelDirection::MeshToExternal {
            return Err(TunnelAuthError::WrongDirection);
        }
        if !request.source_is_mesh {
            return Err(TunnelAuthError::SourceOutsideMesh);
        }
        if request.destination_is_mesh {
            return Err(TunnelAuthError::DestinationInMesh);
        }
        validate_route(request.route)?;
        let request_route_hash = route_hash(request.route)?;
        self.check_time(now)?;
        let mut found = None;
        for (index, slot) in self.entries.iter_mut().enumerate() {
            let matches = slot.is_some_and(|entry| {
                entry.claim.route_hash == request_route_hash
                    && request.route.last() == Some(&entry.claim.egress_iid)
                    && entry.claim.matches_source(&request.inner_source)
            });
            if matches && slot.unwrap().claim.expiry <= now {
                *slot = None;
                return Err(TunnelAuthError::Expired);
            }
            if slot.is_some_and(|entry| entry.claim.expiry <= now) {
                *slot = None;
            } else if matches {
                found = Some(index);
                break;
            }
        }
        let index = found.ok_or(TunnelAuthError::UnauthorizedTunnel)?;
        self.clock = self.clock.saturating_add(1);
        if let Some(entry) = &mut self.entries[index] {
            entry.used = self.clock;
        }
        let accepted_claim = self.entries[index].unwrap().claim;
        if let Some(floor) = self.replay_floors.iter_mut().flatten().find(|floor| {
            floor.route_hash == request_route_hash
                && floor.prefix == accepted_claim.prefix
                && floor.prefix_len == accepted_claim.prefix_len
        }) {
            floor.used = self.clock;
        }
        self.last_now = Some(now);
        Ok(())
    }

    fn check_time(&mut self, now: u64) -> Result<(), TunnelAuthError> {
        if self.last_now.is_some_and(|last| now < last) {
            self.clear();
            return Err(TunnelAuthError::ClockRollback);
        }
        Ok(())
    }
}

fn same_key(left: &TunnelAuthorization, right: &TunnelAuthorization) -> bool {
    left.prefix == right.prefix
        && left.prefix_len == right.prefix_len
        && left.route_hash == right.route_hash
}

fn same_floor_key(left: &ReplayFloor, right: &TunnelAuthorization) -> bool {
    left.prefix == right.prefix
        && left.prefix_len == right.prefix_len
        && left.route_hash == right.route_hash
}

fn validate_route(hops: &[[u8; 8]]) -> Result<(), TunnelAuthError> {
    if hops.is_empty() || hops.len() > MAX_ROUTE_HOPS {
        return Err(TunnelAuthError::InvalidRoute);
    }
    for (index, hop) in hops.iter().enumerate() {
        if hops[..index].contains(hop) {
            return Err(TunnelAuthError::InvalidRoute);
        }
    }
    Ok(())
}

pub fn route_hash(hops: &[[u8; 8]]) -> Result<[u8; 16], TunnelAuthError> {
    validate_route(hops)?;
    let mut hash = Sha256::new();
    for hop in hops {
        hash.update(hop);
    }
    let digest = hash.finalize();
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}

fn encode_sign1(
    claim: TunnelAuthorization,
    root_iid: [u8; 8],
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<SignedTunnelAuthorization, TunnelAuthError> {
    let mut payload = [0; 96];
    let payload_len = encode_payload(claim, &mut payload)?;
    let digest = signature_digest(&payload[..payload_len])?;
    let signature = sign(private_key, public_key, &digest);
    if !verify(public_key, &digest, &signature) {
        return Err(TunnelAuthError::InvalidSignature);
    }
    let mut output = SignedTunnelAuthorization {
        bytes: [0; MAX_AUTHORIZATION_WIRE_LEN],
        len: 0,
    };
    let mut writer = Writer::new(&mut output.bytes);
    writer.byte(0x84)?;
    writer.bstr(PROTECTED)?;
    writer.byte(0xa1)?;
    writer.byte(0x04)?;
    writer.bstr(&root_iid)?;
    writer.bstr(&payload[..payload_len])?;
    writer.bstr(&signature)?;
    output.len = writer.position();
    Ok(output)
}

fn signature_digest(payload: &[u8]) -> Result<[u8; 32], TunnelAuthError> {
    let mut input = [0; 192];
    let length = {
        let mut writer = Writer::new(&mut input);
        writer.byte(0x84)?;
        writer.tstr(b"Signature1")?;
        writer.bstr(PROTECTED)?;
        writer.bstr(&[])?;
        writer.bstr(payload)?;
        writer.position()
    };
    let digest = Sha256::digest(&input[..length]);
    Ok(digest.into())
}

fn encode_payload(claim: TunnelAuthorization, output: &mut [u8]) -> Result<usize, TunnelAuthError> {
    if claim.prefix_len > 128 || !prefix_is_canonical(&claim.prefix, claim.prefix_len) {
        return Err(TunnelAuthError::InvalidPrefix);
    }
    if claim.route_hash == [0; 16] {
        return Err(TunnelAuthError::InvalidRoute);
    }
    let prefix_octets = usize::from(claim.prefix_len.div_ceil(8));
    let mut writer = Writer::new(output);
    writer.byte(0xa6)?;
    writer.uint(1)?;
    writer.bstr(&claim.prefix[..prefix_octets])?;
    writer.uint(2)?;
    writer.uint(u64::from(claim.prefix_len))?;
    writer.uint(3)?;
    writer.bstr(&claim.route_hash)?;
    writer.uint(4)?;
    writer.uint(claim.path_seq)?;
    writer.uint(5)?;
    writer.uint(claim.expiry)?;
    writer.uint(6)?;
    writer.bstr(&claim.egress_iid)?;
    Ok(writer.position())
}

type DecodedSign1 = ([u8; 8], TunnelAuthorization, [u8; 48], [u8; 32]);

fn decode_and_hash_sign1(wire: &[u8]) -> Result<DecodedSign1, TunnelAuthError> {
    if wire.len() > MAX_AUTHORIZATION_WIRE_LEN {
        return Err(TunnelAuthError::BufferTooSmall);
    }
    let mut reader = Reader::new(wire);
    reader.exact(0x84)?;
    let protected = reader.bstr()?;
    if protected != PROTECTED {
        return Err(if protected.starts_with(&[0xa1, 0x01]) {
            TunnelAuthError::UnsupportedAlgorithm
        } else {
            TunnelAuthError::MalformedCbor
        });
    }
    reader.exact(0xa1)?;
    reader.exact(0x04)?;
    let kid = <[u8; 8]>::try_from(reader.bstr()?).map_err(|_| TunnelAuthError::MalformedCbor)?;
    let payload = reader.bstr()?;
    let signature =
        <[u8; 48]>::try_from(reader.bstr()?).map_err(|_| TunnelAuthError::MalformedCbor)?;
    if !reader.finished() {
        return Err(TunnelAuthError::MalformedCbor);
    }
    let claim = decode_payload(payload)?;
    let digest = signature_digest(payload)?;
    Ok((kid, claim, signature, digest))
}

fn decode_payload(payload: &[u8]) -> Result<TunnelAuthorization, TunnelAuthError> {
    let mut reader = Reader::new(payload);
    reader.exact(0xa6)?;
    reader.uint_exact(1)?;
    let prefix_bytes = reader.bstr()?;
    reader.uint_exact(2)?;
    let prefix_len = u8::try_from(reader.uint()?).map_err(|_| TunnelAuthError::InvalidPrefix)?;
    if prefix_len > 128 || prefix_bytes.len() != usize::from(prefix_len.div_ceil(8)) {
        return Err(TunnelAuthError::InvalidPrefix);
    }
    let mut prefix = [0; 16];
    prefix[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
    reader.uint_exact(3)?;
    let route_hash =
        <[u8; 16]>::try_from(reader.bstr()?).map_err(|_| TunnelAuthError::InvalidRoute)?;
    reader.uint_exact(4)?;
    let path_seq = reader.uint()?;
    reader.uint_exact(5)?;
    let expiry = reader.uint()?;
    reader.uint_exact(6)?;
    let egress_iid =
        <[u8; 8]>::try_from(reader.bstr()?).map_err(|_| TunnelAuthError::WrongEgress)?;
    if !reader.finished() {
        return Err(TunnelAuthError::MalformedCbor);
    }
    TunnelAuthorization::new(prefix, prefix_len, route_hash, path_seq, expiry, egress_iid)
}

fn prefix_is_canonical(prefix: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let whole = usize::from(prefix_len / 8);
    let rem = prefix_len % 8;
    if rem != 0 && prefix[whole] & (u8::MAX >> rem) != 0 {
        return false;
    }
    let first_unused = whole + usize::from(rem != 0);
    prefix[first_unused..].iter().all(|byte| *byte == 0)
}

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn byte(&mut self, value: u8) -> Result<(), TunnelAuthError> {
        let slot = self
            .output
            .get_mut(self.position)
            .ok_or(TunnelAuthError::BufferTooSmall)?;
        *slot = value;
        self.position += 1;
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), TunnelAuthError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(TunnelAuthError::BufferTooSmall)?;
        self.output
            .get_mut(self.position..end)
            .ok_or(TunnelAuthError::BufferTooSmall)?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn head(&mut self, major: u8, value: u64) -> Result<(), TunnelAuthError> {
        match value {
            0..=23 => self.byte((major << 5) | value as u8),
            24..=0xff => {
                self.byte((major << 5) | 24)?;
                self.byte(value as u8)
            }
            0x100..=0xffff => {
                self.byte((major << 5) | 25)?;
                self.bytes(&(value as u16).to_be_bytes())
            }
            0x1_0000..=0xffff_ffff => {
                self.byte((major << 5) | 26)?;
                self.bytes(&(value as u32).to_be_bytes())
            }
            _ => {
                self.byte((major << 5) | 27)?;
                self.bytes(&value.to_be_bytes())
            }
        }
    }

    fn uint(&mut self, value: u64) -> Result<(), TunnelAuthError> {
        self.head(0, value)
    }

    fn bstr(&mut self, value: &[u8]) -> Result<(), TunnelAuthError> {
        self.head(2, value.len() as u64)?;
        self.bytes(value)
    }

    fn tstr(&mut self, value: &[u8]) -> Result<(), TunnelAuthError> {
        self.head(3, value.len() as u64)?;
        self.bytes(value)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn finished(&self) -> bool {
        self.position == self.input.len()
    }

    fn byte(&mut self) -> Result<u8, TunnelAuthError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(TunnelAuthError::MalformedCbor)?;
        self.position += 1;
        Ok(value)
    }

    fn exact(&mut self, expected: u8) -> Result<(), TunnelAuthError> {
        if self.byte()? == expected {
            Ok(())
        } else {
            Err(TunnelAuthError::MalformedCbor)
        }
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, TunnelAuthError> {
        let first = self.byte()?;
        if first >> 5 != expected_major {
            return Err(TunnelAuthError::MalformedCbor);
        }
        let additional = first & 0x1f;
        let (value, minimum) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (u64::from(self.byte()?), 24),
            25 => {
                let bytes = self.take(2)?;
                (u64::from(u16::from_be_bytes([bytes[0], bytes[1]])), 0x100)
            }
            26 => {
                let bytes = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes(bytes.try_into().unwrap())),
                    0x1_0000,
                )
            }
            27 => {
                let bytes = self.take(8)?;
                (u64::from_be_bytes(bytes.try_into().unwrap()), 0x1_0000_0000)
            }
            _ => return Err(TunnelAuthError::MalformedCbor),
        };
        if value < minimum {
            return Err(TunnelAuthError::NonCanonicalCbor);
        }
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TunnelAuthError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(TunnelAuthError::MalformedCbor)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(TunnelAuthError::MalformedCbor)?;
        self.position = end;
        Ok(value)
    }

    fn uint(&mut self) -> Result<u64, TunnelAuthError> {
        self.head(0)
    }

    fn uint_exact(&mut self, expected: u64) -> Result<(), TunnelAuthError> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(TunnelAuthError::MalformedCbor)
        }
    }

    fn bstr(&mut self) -> Result<&'a [u8], TunnelAuthError> {
        let length = usize::try_from(self.head(2)?).map_err(|_| TunnelAuthError::MalformedCbor)?;
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schnorr48::{derive_keypair, Seed};

    type Fixture = (
        TunnelAuthorization,
        [[u8; 8]; 3],
        [u8; 8],
        [u8; 8],
        PrivateKey,
        PublicKey,
    );

    fn fixture() -> Fixture {
        let route = [[1; 8], [2; 8], [3; 8]];
        let route_digest = route_hash(&route).unwrap();
        let claim = TunnelAuthorization::new(
            [
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            64,
            route_digest,
            7,
            10_000,
            [3; 8],
        )
        .unwrap();
        let (private, public) = derive_keypair(&Seed::new([0x42; 32]));
        let root = lichen_core::addr::iid_from_pubkey_bytes(public.as_bytes());
        (claim, route, root, [3; 8], private, public)
    }

    fn authenticated<'a>(root: [u8; 8], public: &'a PublicKey) -> AuthenticatedRoot<'a> {
        AuthenticatedRoot {
            iid: root,
            public_key: public,
            oscore_authenticated: true,
        }
    }

    fn egress_request<'a>(source: [u8; 16], route: &'a [[u8; 8]]) -> DecapsulationRequest<'a> {
        DecapsulationRequest {
            direction: TunnelDirection::MeshToExternal,
            inner_source: source,
            source_is_mesh: true,
            destination_is_mesh: false,
            route,
        }
    }

    #[test]
    fn root_post_accepts_and_authorizes_exact_route_and_prefix() {
        let (claim, route, root, own, private, public) = fixture();
        let post = build_root_post(claim, &route, root, &private, &public).unwrap();
        assert_eq!(post.path, TUNNEL_AUTH_PATH);
        assert!(post.oscore_required);
        assert_eq!(
            &post.body.as_bytes()[..9],
            b"\x84\x47\xa1\x01\x3a\x00\x01\x00\x00"
        );
        let mut table = TunnelAuthorizationTable::<4>::default();
        table.set_root(root);
        assert_eq!(
            table.accept_post(post.body.as_bytes(), authenticated(root, &public), own, 50),
            Ok(claim)
        );
        let mut source = claim.prefix;
        source[15] = 1;
        assert_eq!(
            table.authorize_decapsulation(egress_request(source, &route), 51),
            Ok(())
        );
        assert_eq!(
            table.authorize_decapsulation(egress_request(source, &[[7; 8]]), 51),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );
        source[0] ^= 1;
        assert_eq!(
            table.authorize_decapsulation(egress_request(source, &route), 51),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );
    }

    #[test]
    fn rejects_wrong_authentication_signature_egress_expiry_and_replay_atomically() {
        let (claim, route, root, own, private, public) = fixture();
        let post = build_root_post(claim, &route, root, &private, &public).unwrap();
        let mut table = TunnelAuthorizationTable::<2>::default();
        table.set_root(root);
        assert_eq!(
            table.accept_post(
                post.body.as_bytes(),
                AuthenticatedRoot {
                    iid: root,
                    public_key: &public,
                    oscore_authenticated: false,
                },
                own,
                1,
            ),
            Err(TunnelAuthError::MissingOscoreAuthentication)
        );
        assert_eq!(
            table.accept_post(post.body.as_bytes(), authenticated([8; 8], &public), own, 1),
            Err(TunnelAuthError::WrongRoot)
        );
        let mut mismatched = TunnelAuthorizationTable::<2>::default();
        mismatched.set_root([8; 8]);
        assert_eq!(
            mismatched.accept_post(post.body.as_bytes(), authenticated([8; 8], &public), own, 1,),
            Err(TunnelAuthError::RootIdentityMismatch)
        );
        assert_eq!(
            table.accept_post(
                post.body.as_bytes(),
                authenticated(root, &public),
                [4; 8],
                1
            ),
            Err(TunnelAuthError::WrongEgress)
        );
        let mut corrupted = post.body;
        corrupted.bytes[corrupted.len - 1] ^= 1;
        assert_eq!(
            table.accept_post(corrupted.as_bytes(), authenticated(root, &public), own, 1),
            Err(TunnelAuthError::InvalidSignature)
        );
        assert_eq!(
            table.accept_post(
                post.body.as_bytes(),
                authenticated(root, &public),
                own,
                10_000
            ),
            Err(TunnelAuthError::Expired)
        );
        table
            .accept_post(post.body.as_bytes(), authenticated(root, &public), own, 1)
            .unwrap();
        assert_eq!(
            table.accept_post(post.body.as_bytes(), authenticated(root, &public), own, 1),
            Err(TunnelAuthError::Replay)
        );
    }

    #[test]
    fn revocation_root_change_expiry_and_lru_fail_closed() {
        let (base, route, root, own, private, public) = fixture();
        let mut table = TunnelAuthorizationTable::<1>::default();
        table.set_root(root);
        let first = build_root_post(base, &route, root, &private, &public).unwrap();
        table
            .accept_post(first.body.as_bytes(), authenticated(root, &public), own, 1)
            .unwrap();
        let mut second_claim = base;
        second_claim.prefix[7] = 0x79;
        let second_route = [[4; 8], [5; 8], [3; 8]];
        second_claim.route_hash = route_hash(&second_route).unwrap();
        let second = build_root_post(second_claim, &second_route, root, &private, &public).unwrap();
        table
            .accept_post(second.body.as_bytes(), authenticated(root, &public), own, 1)
            .unwrap();
        assert_eq!(
            table.authorize_decapsulation(egress_request(base.prefix, &route), 2),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );
        table
            .revoke(
                second_claim.prefix,
                second_claim.prefix_len,
                second_claim.route_hash,
                second_claim.path_seq,
            )
            .unwrap();
        assert_eq!(
            table.authorize_decapsulation(egress_request(second_claim.prefix, &second_route), 2),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );
        assert_eq!(
            table.accept_post(second.body.as_bytes(), authenticated(root, &public), own, 3),
            Err(TunnelAuthError::Replay)
        );
        let mut fresher_claim = second_claim;
        fresher_claim.path_seq += 1;
        let fresher =
            build_root_post(fresher_claim, &second_route, root, &private, &public).unwrap();
        table
            .accept_post(
                fresher.body.as_bytes(),
                authenticated(root, &public),
                own,
                3,
            )
            .unwrap();
        table.set_root([0xaa; 8]);
        assert_eq!(
            table.authorize_decapsulation(egress_request(second_claim.prefix, &second_route), 2),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );
    }

    #[test]
    fn direction_scope_clock_and_capacity_fail_closed() {
        let (claim, route, root, own, private, public) = fixture();
        let post = build_root_post(claim, &route, root, &private, &public).unwrap();
        let mut table = TunnelAuthorizationTable::<2>::default();
        table.set_root(root);
        table
            .accept_post(post.body.as_bytes(), authenticated(root, &public), own, 50)
            .unwrap();

        let mut wrong_direction = egress_request(claim.prefix, &route);
        wrong_direction.direction = TunnelDirection::ExternalToMesh;
        assert_eq!(
            table.authorize_decapsulation(wrong_direction, 51),
            Err(TunnelAuthError::WrongDirection)
        );
        let mut non_mesh_source = egress_request(claim.prefix, &route);
        non_mesh_source.source_is_mesh = false;
        assert_eq!(
            table.authorize_decapsulation(non_mesh_source, 51),
            Err(TunnelAuthError::SourceOutsideMesh)
        );
        let mut mesh_destination = egress_request(claim.prefix, &route);
        mesh_destination.destination_is_mesh = true;
        assert_eq!(
            table.authorize_decapsulation(mesh_destination, 51),
            Err(TunnelAuthError::DestinationInMesh)
        );
        assert_eq!(
            table.authorize_decapsulation(egress_request(claim.prefix, &route), 49),
            Err(TunnelAuthError::ClockRollback)
        );
        assert_eq!(
            table.authorize_decapsulation(egress_request(claim.prefix, &route), 52),
            Err(TunnelAuthError::UnauthorizedTunnel)
        );

        let mut disabled = TunnelAuthorizationTable::<0>::default();
        disabled.set_root(root);
        assert_eq!(
            disabled.accept_post(post.body.as_bytes(), authenticated(root, &public), own, 1),
            Err(TunnelAuthError::TableDisabled)
        );
        assert_eq!(
            disabled.revoke(
                claim.prefix,
                claim.prefix_len,
                claim.route_hash,
                claim.path_seq
            ),
            Err(TunnelAuthError::TableDisabled)
        );
        assert_eq!(
            TunnelAuthError::InvalidSignature.coap_response_code(),
            COAP_FORBIDDEN_CODE
        );
    }

    #[test]
    fn canonical_bounds_and_malformed_inputs_are_rejected() {
        let (claim, route, root, own, private, public) = fixture();
        assert_eq!(route_hash(&[]), Err(TunnelAuthError::InvalidRoute));
        assert_eq!(
            route_hash(&[[1; 8], [1; 8]]),
            Err(TunnelAuthError::InvalidRoute)
        );
        assert_eq!(
            route_hash(&[[1; 8]; MAX_ROUTE_HOPS + 1]),
            Err(TunnelAuthError::InvalidRoute)
        );
        let mut noncanonical = claim.prefix;
        noncanonical[8] = 1;
        assert_eq!(
            TunnelAuthorization::new(noncanonical, 64, claim.route_hash, 1, 2, own),
            Err(TunnelAuthError::InvalidPrefix)
        );
        assert_eq!(
            build_root_post(claim, &route[..2], root, &private, &public).map(|_| ()),
            Err(TunnelAuthError::InvalidRoute)
        );
        assert_eq!(
            build_root_post(claim, &route, [9; 8], &private, &public).map(|_| ()),
            Err(TunnelAuthError::RootIdentityMismatch)
        );
        let post = build_root_post(claim, &route, root, &private, &public).unwrap();
        let mut table = TunnelAuthorizationTable::<2>::default();
        table.set_root(root);
        for cut in 0..post.body.as_bytes().len() {
            assert!(table
                .accept_post(
                    &post.body.as_bytes()[..cut],
                    authenticated(root, &public),
                    own,
                    1,
                )
                .is_err());
        }
        let mut wrong_alg = post.body;
        wrong_alg.bytes[7] ^= 1;
        assert_eq!(
            table.accept_post(wrong_alg.as_bytes(), authenticated(root, &public), own, 1),
            Err(TunnelAuthError::UnsupportedAlgorithm)
        );
    }
}

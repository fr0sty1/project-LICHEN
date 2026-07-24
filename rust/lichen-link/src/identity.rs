//! Node identity: Ed25519 keypair + IID derivation.

extern crate alloc;

use crate::keys::{PrivateKey, PublicKey, Seed};
use crate::schnorr::{clamp, derive_keypair};
use curve25519_dalek::MontgomeryPoint;
use lichen_core::{
    addr::{iid_from_pubkey_bytes, ygg_addr_from_pubkey},
    lichen_hash_32,
};
use sha2::{Digest, Sha512};

pub fn iid_from_pubkey(pubkey: &PublicKey) -> [u8; 8] {
    iid_from_pubkey_bytes(pubkey.as_bytes())
}

/// Human-readable Crockford Base32 node address from pubkey (spec 03-addressing).

pub fn human_address_from_pubkey(pubkey: &PublicKey) -> [u8; 15] {
    let iid = iid_from_pubkey(pubkey);
    human_address_from_iid(&iid)
}

fn human_address_from_iid(iid: &[u8; 8]) -> [u8; 15] {
    let mut n = u64::from_be_bytes(*iid);
    let alphabet = *b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut buf = [0u8; 13];
    for i in 0..13 {
        let r = (n % 32) as usize;
        buf[12 - i] = alphabet[r];
        n /= 32;
    }
    let mut out = [0u8; 15];
    out[0..4].copy_from_slice(&buf[0..4]);
    out[4] = b'-';
    out[5..9].copy_from_slice(&buf[4..8]);
    out[9] = b'-';
    out[10..15].copy_from_slice(&buf[8..13]);
    out
}

/// Local node identity (seed + derived keypair + IID + Yggdrasil address).
///
/// Unified Ed25519 identity for LICHEN (signatures, OSCORE, IID) and Yggdrasil
/// (global routing). Address derivation ensures deterministic mapping.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub seed: Seed,
    pub privkey: PrivateKey,
    pub pubkey: PublicKey,
    pub iid: [u8; 8],
    pub ygg_addr: [u8; 16],
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("seed", &"[REDACTED]")
            .field("privkey", &"[REDACTED]")
            .field("pubkey", &self.pubkey)
            .field("iid", &self.iid)
            .field("ygg_addr", &self.ygg_addr)
            .finish()
    }
}

impl Identity {
    pub fn from_seed(seed: Seed) -> Self {
        let (privkey, pubkey) = derive_keypair(&seed);
        let iid = iid_from_pubkey(&pubkey);
        let ygg_addr = ygg_addr_from_pubkey(pubkey.as_bytes());
        Identity {
            seed,
            privkey,
            pubkey,
            iid,
            ygg_addr,
        }
    }

    /// Derive X25519 private key from the Ed25519 seed per spec 8.8.
    ///
    /// `x25519_private = clamp(SHA-512(seed)[0:32])` per RFC 7748 §5.
    /// This is byte-identical to the Ed25519 private scalar (same
    /// derivation), but interpreted on the Montgomery curve for ECDH.
    pub fn x25519_private(&self) -> [u8; 32] {
        let hash = Sha512::digest(self.seed.as_bytes());
        clamp(hash[..32].try_into().unwrap())
    }

    /// Derive X25519 public key from the Ed25519 seed per spec 8.8.
    ///
    /// `x25519_public = X25519(x25519_private, basepoint)`
    pub fn x25519_public(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(self.x25519_private()).to_bytes()
    }
}

/// A remote peer known by pubkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pubkey: PublicKey,
    pub iid: [u8; 8],
}

impl PeerIdentity {
    pub fn from_pubkey(pubkey: PublicKey) -> Self {
        let iid = iid_from_pubkey(&pubkey);
        PeerIdentity { pubkey, iid }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::from_hex;

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().unwrap()
    }

    #[test]
    fn hash_32_fnv1a32() {
        assert_eq!(lichen_hash_32(b""), 0x811c9dc5);
        assert_eq!(lichen_hash_32(b"test"), 0xafd071e5);
        assert_eq!(lichen_hash_32(&[0u8; 32]), 0x0b2ae445);
    }

    #[test]
    fn iid_u_l_bit_cleared() {
        let pubkey = PublicKey::new([0u8; 32]);
        let iid = iid_from_pubkey(&pubkey);
        let expected = [0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86];
        assert_eq!(iid, expected);
        assert_eq!(iid[0] & 0x02, 0, "U/L bit must be cleared");
    }

    #[test]
    fn iid_deterministic() {
        let pk = PublicKey::new([0xabu8; 32]);
        assert_eq!(iid_from_pubkey(&pk), iid_from_pubkey(&pk));
    }

    #[test]
    fn identity_from_seed_consistent() {
        let seed = Seed::new([0x01u8; 32]);
        let id1 = Identity::from_seed(seed.clone());
        let id2 = Identity::from_seed(seed);
        assert_eq!(id1.privkey, id2.privkey);
        assert_eq!(id1.pubkey, id2.pubkey);
        assert_eq!(id1.iid, id2.iid);
        assert_eq!(id1.iid, iid_from_pubkey(&id1.pubkey));
    }

    #[test]
    fn peer_identity_from_pubkey_matches_iid() {
        let seed = Seed::new(arr32(&from_hex(
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
        )));
        let id = Identity::from_seed(seed);
        let peer = PeerIdentity::from_pubkey(id.pubkey);
        assert_eq!(peer.pubkey, id.pubkey);
        assert_eq!(peer.iid, id.iid);
    }

    #[test]
    fn different_seeds_different_iids() {
        let id_a = Identity::from_seed(Seed::new([0x01u8; 32]));
        let id_b = Identity::from_seed(Seed::new([0x02u8; 32]));
        assert_ne!(id_a.iid, id_b.iid);
    }

    #[test]
    fn yggdrasil_addr_unified_with_iid() {
        let seed = Seed::new([0x01u8; 32]);
        let id = Identity::from_seed(seed);
        let direct = ygg_addr_from_pubkey(id.pubkey.as_bytes());
        assert_eq!(direct[0], 0x02, "must start with Yggdrasil prefix");
        assert_eq!(
            &direct[8..],
            &id.iid[..],
            "lower 64 bits must match LICHEN IID"
        );
        // deterministic
        assert_eq!(direct, ygg_addr_from_pubkey(id.pubkey.as_bytes()));
    }

    #[test]
    fn x25519_private_matches_python_zero_seed() {
        let seed = Seed::new([0u8; 32]);
        let id = Identity::from_seed(seed);
        let expected = arr32(&from_hex(
            "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156",
        ));
        assert_eq!(id.x25519_private(), expected);
    }

    #[test]
    fn x25519_private_equals_ed25519_privkey() {
        // Both derive via clamp(SHA-512(seed)[0:32])
        let seed = Seed::new([0xabu8; 32]);
        let id = Identity::from_seed(seed);
        assert_eq!(id.x25519_private(), *id.privkey.as_bytes());
    }

    #[test]
    fn x25519_public_matches_python_zero_seed() {
        let seed = Seed::new([0u8; 32]);
        let id = Identity::from_seed(seed);
        let expected = arr32(&from_hex(
            "5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d",
        ));
        assert_eq!(id.x25519_public(), expected);
    }

    #[test]
    fn x25519_public_is_deterministic() {
        let seed = Seed::new([0x42u8; 32]);
        let id = Identity::from_seed(seed);
        assert_eq!(id.x25519_public(), id.x25519_public());
    }

    #[test]
    fn x25519_public_differs_from_ed25519_pubkey() {
        // Same seed → same private scalar, but different curve interpretation
        // produces different public keys.
        let seed = Seed::new([0x01u8; 32]);
        let id = Identity::from_seed(seed);
        assert_ne!(id.x25519_public(), *id.pubkey.as_bytes());
    }

    #[test]
    fn human_address_from_pubkey_matches_test_vectors() {
        let pk0 = PublicKey::new([0u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk0), *b"50HN-DR7D-TGE46");
        let pk1 = PublicKey::new([1u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk1), *b"5ST3-EZDT-ZMKHC");
        let pk4 = PublicKey::new([4u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk4), *b"4JFH-W2HE-QWT0A");
    }
}

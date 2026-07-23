//! Node identity: Ed25519 keypair + IID derivation.

extern crate alloc;

use crate::keys::{PrivateKey, PublicKey, Seed};
use crate::schnorr::derive_keypair;
use sha2::{Digest, Sha256, Sha512};

/// Derive a link-local IID from an Ed25519 public key.
///
/// Uses lichen_hash_32 (FNV-1a32) twice for 64 bits (pubkey, pubkey+0x01).
/// U/L bit cleared per RFC 4291. Ensures consistency with TDMA/CCP hash_32
/// (project-LICHEN-eirg).
pub fn iid_from_pubkey(pubkey: &PublicKey) -> [u8; 8] {
    iid_from_pubkey_bytes(pubkey.as_bytes())
}

pub fn hash_32(data: &[u8]) -> u32 {
    let mut h = 0x811c9dc5u32;
    for &b in data {
        h = (h ^ (b as u32)).wrapping_mul(0x01000193) & 0xffff_ffff;
    }
    h
}

/// Derive a link-local IID from raw public key bytes using lichen_hash_32 (FNV-1a32).
fn iid_from_pubkey_bytes(pubkey: &[u8; 32]) -> [u8; 8] {
    let h1 = hash_32(pubkey);
    let mut buf2 = [0u8; 33];
    buf2[0..32].copy_from_slice(pubkey);
    buf2[32] = 1;
    let h2 = hash_32(&buf2);
    let mut iid = [0u8; 8];
    iid[0..4].copy_from_slice(&h1.to_be_bytes());
    iid[4..8].copy_from_slice(&h2.to_be_bytes());
    iid[0] &= 0b1111_1101; // clear U/L bit (bit 1)
    iid
}

/// Derive Yggdrasil address bytes (16 bytes) from Ed25519 public key for unified identity.
///
/// Uses SHA-512(pubkey) for upper 56 bits (with 0x02 prefix for 0200::/7), and LICHEN
/// IID for lower 64 bits. This ensures one Ed25519 keypair yields both LICHEN IID
/// and a deterministic Yggdrasil global address (per project-LICHEN-zt3c.1).
pub fn yggdrasil_addr_from_pubkey(pubkey: &PublicKey) -> [u8; 16] {
    let hash = Sha512::digest(pubkey.as_bytes());
    let iid = iid_from_pubkey(pubkey);
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1..8].copy_from_slice(&hash[0..7]);
    addr[8..16].copy_from_slice(&iid);
    addr
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
        let ygg_addr = yggdrasil_addr_from_pubkey(&pubkey);
        Identity {
            seed,
            privkey,
            pubkey,
            iid,
            ygg_addr,
        }
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
        // Exact match to Python _hash_32, Rust lichen-core::lichen_hash_32.
        // FNV-1a32 (basis 0x811c9dc5, prime 0x01000193). Matches all vectors.
        assert_eq!(hash_32(b""), 0x811c9dc5);
        assert_eq!(hash_32(b"test"), 0xafd071e5);
        assert_eq!(hash_32(&[0u8; 32]), 0x0b2ae445);
    }

    #[test]
    fn iid_u_l_bit_cleared() {
        let pubkey = PublicKey::new([0u8; 32]);
        let iid = iid_from_pubkey(&pubkey);
        // Matches updated hash_32.json iid_derivation_zero and FNV primitive.
        let expected = [0x09, 0x2a, 0xe4, 0x45, 0xd8, 0x85, 0x57, 0x0c];
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
        let direct = yggdrasil_addr_from_pubkey(&id.pubkey);
        assert_eq!(direct[0], 0x02, "must start with Yggdrasil prefix");
        assert_eq!(
            &direct[8..],
            &id.iid[..],
            "lower 64 bits must match LICHEN IID"
        );
        // deterministic
        assert_eq!(direct, yggdrasil_addr_from_pubkey(&id.pubkey));
    }
}

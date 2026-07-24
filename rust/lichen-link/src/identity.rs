//! Node identity: Ed25519 keypair + IID derivation.

extern crate alloc;

use crate::keys::{PrivateKey, PublicKey, Seed};
use crate::schnorr::derive_keypair;
use lichen_core::addr::ygg_addr_from_pubkey;
#[cfg(test)]
use lichen_core::lichen_hash_32;
use sha2::{Digest, Sha256};

/// Derive a link-local IID from an Ed25519 public key.
///
/// Canonical SHA-256(pubkey)[0..8] with U/L bit cleared (IID[0] &= 0b11111101)
/// per RFC 4291 §2.5.1 and spec/04-network.md §6.2. Matches Python/C exactly
/// for cross-impl consistency (project-LICHEN-iqxx).
pub fn iid_from_pubkey(pubkey: &PublicKey) -> [u8; 8] {
    iid_from_pubkey_bytes(pubkey.as_bytes())
}

/// Derive a link-local IID from raw public key bytes (SHA-256 truncation).
fn iid_from_pubkey_bytes(pubkey: &[u8; 32]) -> [u8; 8] {
    let digest = Sha256::digest(pubkey);
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&digest[0..8]);
    iid[0] &= 0b1111_1101; // clear U/L bit (bit 1)
    iid
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
        // Matches node-addresses.json all-zero-pubkey IID (SHA256[:8] + U/L cleared).
        let expected = [0x64, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77];
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
    fn human_address_from_pubkey_matches_test_vectors() {
        let pk0 = PublicKey::new([0u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk0), *b"68T3-TNQW-65FBQ");
        let pk1 = PublicKey::new([1u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk1), *b"71KB-EGGH-C81ZV");
        let pk4 = PublicKey::new([4u8; 32]);
        assert_eq!(human_address_from_pubkey(&pk4), *b"9TKX-PHWZ-1VB42");
    }
}

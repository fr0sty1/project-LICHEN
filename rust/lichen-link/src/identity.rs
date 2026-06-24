//! Node identity: Ed25519 keypair + IID derivation.

use crate::schnorr::derive_keypair;
use sha2::{Digest, Sha256};

/// Derive a link-local IID from an Ed25519 public key.
///
/// IID = SHA-256(pubkey)[0:8] with the U/L bit (bit 1 of byte 0) cleared.
/// RFC 4291 §2.5.1 — locally-administered identifier.
pub fn iid_from_pubkey(pubkey: &[u8; 32]) -> [u8; 8] {
    let hash = Sha256::digest(pubkey);
    let mut iid: [u8; 8] = hash[..8].try_into().unwrap();
    iid[0] &= 0b1111_1101; // clear U/L bit
    iid
}

/// Local node identity (seed + derived keypair + IID).
pub struct Identity {
    pub seed: [u8; 32],
    pub privkey: [u8; 32],
    pub pubkey: [u8; 32],
    pub iid: [u8; 8],
}

impl Identity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (privkey, pubkey) = derive_keypair(&seed);
        let iid = iid_from_pubkey(&pubkey);
        Identity { seed, privkey, pubkey, iid }
    }
}

/// A remote peer known by pubkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pubkey: [u8; 32],
    pub iid: [u8; 8],
}

impl PeerIdentity {
    pub fn from_pubkey(pubkey: [u8; 32]) -> Self {
        let iid = iid_from_pubkey(&pubkey);
        PeerIdentity { pubkey, iid }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().unwrap()
    }

    #[test]
    fn iid_u_l_bit_cleared() {
        let pubkey = [0u8; 32];
        let iid = iid_from_pubkey(&pubkey);
        // SHA-256(0x00*32) = e3b0c44298fc1c149afb... — first byte 0xe3 & ~0x02 = 0xe1
        let expected_hash = Sha256::digest(&[0u8; 32]);
        let mut expected: [u8; 8] = expected_hash[..8].try_into().unwrap();
        expected[0] &= 0b1111_1101;
        assert_eq!(iid, expected);
        assert_eq!(iid[0] & 0x02, 0, "U/L bit must be cleared");
    }

    #[test]
    fn iid_deterministic() {
        let pk = [0xabu8; 32];
        assert_eq!(iid_from_pubkey(&pk), iid_from_pubkey(&pk));
    }

    #[test]
    fn identity_from_seed_consistent() {
        let seed = [0x01u8; 32];
        let id1 = Identity::from_seed(seed);
        let id2 = Identity::from_seed(seed);
        assert_eq!(id1.privkey, id2.privkey);
        assert_eq!(id1.pubkey, id2.pubkey);
        assert_eq!(id1.iid, id2.iid);
        assert_eq!(id1.iid, iid_from_pubkey(&id1.pubkey));
    }

    #[test]
    fn peer_identity_from_pubkey_matches_iid() {
        let seed = arr32(&from_hex(
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
        ));
        let id = Identity::from_seed(seed);
        let peer = PeerIdentity::from_pubkey(id.pubkey);
        assert_eq!(peer.pubkey, id.pubkey);
        assert_eq!(peer.iid, id.iid);
    }

    #[test]
    fn different_seeds_different_iids() {
        let id_a = Identity::from_seed([0x01u8; 32]);
        let id_b = Identity::from_seed([0x02u8; 32]);
        assert_ne!(id_a.iid, id_b.iid);
    }
}

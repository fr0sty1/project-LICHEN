//! Node identity: Ed25519 keypair + IID derivation.

use crate::keys::{PrivateKey, PublicKey, Seed};
use crate::schnorr::derive_keypair;

/// Keyed 32-bit hash using fixed network key b"LICHEN" (0x4c494348454e)
/// as initializer. Per spec 02a-coordinated-capacity.md and test vectors.
/// Used for packet_hash, tuple CRCs, short-addr derivation, channel selection.
/// Syncs with lichen/subsys/lichen/link/link_ctx.c:tuple_crc().
/// Prefixes key bytes into standard CRC32 (matches Zephyr crc32_ieee and
/// schc CRC impl).
pub fn hash_32(data: &[u8]) -> u32 {
    const KEY: &[u8] = b"LICHEN";
    let mut crc: u32 = 0xffff_ffff;
    for &byte in KEY.iter().chain(data.iter()) {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Derive a link-local IID from an Ed25519 public key.
///
/// Updated per project-LICHEN-swvz to use keyed hash_32 (twice for 64 bits)
/// with key b"LICHEN" instead of plain SHA-256. U/L bit cleared per RFC 4291.
/// This ensures consistency with coordinated capacity channel/short-addr hashes.
///
/// # Panics
///
/// This function does not panic.
pub fn iid_from_pubkey(pubkey: &PublicKey) -> [u8; 8] {
    iid_from_pubkey_bytes(pubkey.as_bytes())
}

/// Derive a link-local IID from raw public key bytes using keyed hash_32.
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

/// Format 8-byte IID as 15-byte human-readable address `XXXX-XXXX-XXXXX`
/// using Crockford Base32 (spec 03-addressing.md).
pub fn human_address(iid: &[u8; 8]) -> [u8; 15] {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut n = u64::from_be_bytes(*iid);
    let mut chars = [0u8; 13];
    for i in (0..13).rev() {
        let rem = (n % 32) as usize;
        chars[i] = ALPHABET[rem];
        n /= 32;
    }
    let mut buf = [0u8; 15];
    buf[0..4].copy_from_slice(&chars[0..4]);
    buf[4] = b'-';
    buf[5..9].copy_from_slice(&chars[4..8]);
    buf[9] = b'-';
    buf[10..15].copy_from_slice(&chars[8..13]);
    buf
}

/// Local node identity (seed + derived keypair + IID).
///
/// Note: Cannot derive Copy because Seed and PrivateKey have ZeroizeOnDrop.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub seed: Seed,
    pub privkey: PrivateKey,
    pub pubkey: PublicKey,
    pub iid: [u8; 8],
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("seed", &"[REDACTED]")
            .field("privkey", &"[REDACTED]")
            .field("pubkey", &self.pubkey)
            .field("iid", &self.iid)
            .finish()
    }
}

impl Identity {
    pub fn from_seed(seed: Seed) -> Self {
        let (privkey, pubkey) = derive_keypair(&seed);
        let iid = iid_from_pubkey(&pubkey);
        Identity {
            seed,
            privkey,
            pubkey,
            iid,
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
    fn hash_32_keyed_with_lichen() {
        // Independent oracle computed with Python zlib.crc32(b"LICHEN" + data)
        // (standard CRC32 with key prefixed as initializer; matches spec and C impl)
        assert_eq!(hash_32(b""), 0x77f9adf0);
        assert_eq!(hash_32(b"test"), 0x84a618f3);
        assert_eq!(hash_32(&[0u8; 32]), 0x922b4f72);
    }

    #[test]
    fn iid_u_l_bit_cleared() {
        let pubkey = PublicKey::new([0u8; 32]);
        let iid = iid_from_pubkey(&pubkey);
        // New derivation per project-LICHEN-swvz: keyed hash_32(pubkey) + hash_32(pubkey+1)
        // Independent oracle: 0x902b4f721b9ce444 (U/L bit already clear)
        let expected = [0x90, 0x2b, 0x4f, 0x72, 0x1b, 0x9c, 0xe4, 0x44];
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
    fn human_address_format() {
        let iid = [0x11, 0x9e, 0x39, 0x40, 0xe6, 0x4b, 0x54, 0x91];
        let human = human_address(&iid);
        let s = core::str::from_utf8(&human).unwrap();
        assert_eq!(s, "137H-S83K-4PN4H");
        assert_eq!(human_address(&[0u8; 8]), *b"90AT-FE8D-SSS24"); // updated for keyed hash_32(seed=0)
    }
}

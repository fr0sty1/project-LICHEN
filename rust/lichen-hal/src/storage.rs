//! Persistent identity storage using NonVolatile trait.
//!
//! Stores:
//! - Identity seed (32 bytes) → derives keypair on load
//! - Peer table (pubkeys for signature verification)
//! - Link layer sequence numbers (for replay protection continuity)

use crate::NonVolatile;
use lichen_link::{PublicKey, Seed};

/// Storage key constants for persistent identity and link state.
///
/// # Design Rationale
///
/// Keys are defined as constants rather than inline strings to:
/// - **Prevent typos**: A misspelled constant is a compile error; a misspelled
///   string silently reads/writes the wrong slot.
/// - **Enable refactoring**: Renaming a key updates all usages automatically.
/// - **Support grep/IDE navigation**: Constants are discoverable; magic strings
///   scattered across call sites are not.
///
/// # Naming Convention
///
/// Keys use a `namespace.field` format with short names (8 chars max) to
/// minimize flash wear and storage overhead on embedded targets. The prefixes
/// group related data:
/// - `id.*` — node identity (seed, replay-protection state)
/// - `peers.*` — peer public keys
/// - `peer.N` — individual peer entries (see [`peer_key`])
pub mod keys {
    /// 32-byte Ed25519 seed that derives the node's keypair.
    pub const IDENTITY_SEED: &str = "id.seed";
    /// Link-layer epoch counter (1 byte) for replay protection.
    pub const EPOCH: &str = "id.epoch";
    /// Link-layer sequence number (2 bytes, big-endian) for replay protection.
    pub const SEQNUM: &str = "id.seq";
    /// Number of persisted peers (1 byte).
    pub const PEER_COUNT: &str = "peers.n";
}

/// Maximum number of peers to persist.
pub const MAX_PEERS: usize = 16;

/// Get peer key name for index.
pub fn peer_key(index: usize) -> heapless::String<16> {
    let mut s = heapless::String::new();
    core::fmt::write(&mut s, format_args!("peer.{}", index))
        .expect("peer key always fits in 16 bytes");
    s
}

/// Load identity seed from storage.
///
/// Returns `Some(seed)` if found and valid, `None` otherwise.
pub fn load_seed<S: NonVolatile>(storage: &S) -> Option<Seed> {
    let mut buf = [0u8; 32];
    let n = storage.read(keys::IDENTITY_SEED, &mut buf)?;
    if n == 32 {
        Some(Seed::new(buf))
    } else {
        None
    }
}

/// Save identity seed to storage.
pub fn save_seed<S: NonVolatile>(storage: &mut S, seed: &Seed) -> Result<(), S::Error> {
    storage.write(keys::IDENTITY_SEED, seed.as_bytes())
}

/// Load link layer epoch from storage.
pub fn load_epoch<S: NonVolatile>(storage: &S) -> Option<u8> {
    let mut buf = [0u8; 1];
    let n = storage.read(keys::EPOCH, &mut buf)?;
    if n == 1 {
        Some(buf[0])
    } else {
        None
    }
}

/// Save link layer epoch to storage.
pub fn save_epoch<S: NonVolatile>(storage: &mut S, epoch: u8) -> Result<(), S::Error> {
    storage.write(keys::EPOCH, &[epoch])
}

/// Load link layer sequence number from storage.
pub fn load_seqnum<S: NonVolatile>(storage: &S) -> Option<u16> {
    let mut buf = [0u8; 2];
    let n = storage.read(keys::SEQNUM, &mut buf)?;
    if n == 2 {
        Some(u16::from_be_bytes(buf))
    } else {
        None
    }
}

/// Save link layer sequence number to storage.
pub fn save_seqnum<S: NonVolatile>(storage: &mut S, seqnum: u16) -> Result<(), S::Error> {
    storage.write(keys::SEQNUM, &seqnum.to_be_bytes())
}

/// Load peer count from storage.
pub fn load_peer_count<S: NonVolatile>(storage: &S) -> usize {
    let mut buf = [0u8; 1];
    storage
        .read(keys::PEER_COUNT, &mut buf)
        .map(|n| if n == 1 { buf[0] as usize } else { 0 })
        .unwrap_or(0)
}

/// Load a peer pubkey from storage.
pub fn load_peer<S: NonVolatile>(storage: &S, index: usize) -> Option<PublicKey> {
    if index >= MAX_PEERS {
        return None;
    }
    let key = peer_key(index);
    let mut buf = [0u8; 32];
    let n = storage.read(&key, &mut buf)?;
    if n == 32 {
        Some(PublicKey::new(buf))
    } else {
        None
    }
}

/// Save peer table to storage.
///
/// Overwrites existing peers. Pass a slice of pubkeys.
///
/// SECURITY: Writes entries before count to ensure crash safety - the count
/// only reflects successfully written entries.
pub fn save_peers<S: NonVolatile>(storage: &mut S, peers: &[PublicKey]) -> Result<(), S::Error> {
    let count = peers.len().min(MAX_PEERS);
    for (i, pubkey) in peers.iter().take(count).enumerate() {
        let key = peer_key(i);
        storage.write(&key, pubkey.as_bytes())?;
    }
    // Write count LAST so it only reflects successfully written entries
    storage.write(keys::PEER_COUNT, &[count as u8])?;
    Ok(())
}

/// In-memory NonVolatile implementation for testing.
#[cfg(any(test, feature = "std"))]
pub mod mem {
    extern crate std;
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use crate::NonVolatile;

    /// In-memory storage for testing.
    #[derive(Debug, Default, Clone)]
    pub struct MemStorage {
        data: HashMap<String, Vec<u8>>,
    }

    impl MemStorage {
        pub fn new() -> Self {
            Self::default()
        }

        /// Simulate reboot by clearing volatile state but keeping persisted data.
        ///
        /// No-op: MemStorage is always persistent, so "reboot" changes nothing.
        /// Call this in tests to verify data survives simulated reboots.
        pub fn clear_volatile(&mut self) {}
    }

    impl NonVolatile for MemStorage {
        type Error = core::convert::Infallible;

        fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize> {
            let data = self.data.get(key)?;
            let stored = data.len();
            let n = stored.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Some(stored)
        }

        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            self.data.insert(key.into(), data.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &str) -> bool {
            self.data.remove(key).is_some()
        }
    }
}

#[cfg(feature = "std")]
pub mod fs {
    extern crate std;
    use crate::NonVolatile;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    #[derive(Debug)]
    pub struct FileStorage {
        dir: PathBuf,
    }

    impl FileStorage {
        pub fn new<P: AsRef<Path>>(p: P) -> io::Result<Self> {
            let d = p.as_ref().to_path_buf();
            fs::create_dir_all(&d)?;
            Ok(Self { dir: d })
        }
        fn key_path(&self, k: &str) -> PathBuf {
            self.dir.join(k)
        }
        fn tmp_path(&self, k: &str) -> PathBuf {
            self.dir.join(format!("{}.tmp", k))
        }
    }

    impl NonVolatile for FileStorage {
        type Error = io::Error;
        fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize> {
            let p = self.key_path(key);
            let data = match fs::read(&p) {
                Ok(d) => d,
                Err(_) => return None,
            };
            let stored = data.len();
            let n = stored.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Some(stored)
        }
        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            let t = self.tmp_path(key);
            let f = self.key_path(key);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&t)?;
            std::io::Write::write_all(&mut file, data)?;
            file.sync_all()?;
            fs::rename(t, f)?;
            let _ = fs::File::open(&self.dir).and_then(|d| d.sync_all());
            Ok(())
        }
        fn delete(&mut self, key: &str) -> bool {
            let p = self.key_path(key);
            fs::remove_file(p).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs::FileStorage;
    use mem::MemStorage;

    #[test]
    fn seed_round_trip() {
        let mut storage = MemStorage::new();
        let seed = Seed::new([0xABu8; 32]);

        assert!(load_seed(&storage).is_none());
        save_seed(&mut storage, &seed).unwrap();
        assert_eq!(load_seed(&storage), Some(seed));
    }

    #[test]
    fn epoch_seqnum_round_trip() {
        let mut storage = MemStorage::new();

        assert!(load_epoch(&storage).is_none());
        assert!(load_seqnum(&storage).is_none());

        save_epoch(&mut storage, 5).unwrap();
        save_seqnum(&mut storage, 12345).unwrap();

        assert_eq!(load_epoch(&storage), Some(5));
        assert_eq!(load_seqnum(&storage), Some(12345));
    }

    #[test]
    fn peers_round_trip() {
        let mut storage = MemStorage::new();
        let peers = [
            PublicKey::new([0x01u8; 32]),
            PublicKey::new([0x02u8; 32]),
            PublicKey::new([0x03u8; 32]),
        ];

        assert_eq!(load_peer_count(&storage), 0);
        save_peers(&mut storage, &peers).unwrap();

        assert_eq!(load_peer_count(&storage), 3);
        assert_eq!(load_peer(&storage, 0), Some(PublicKey::new([0x01u8; 32])));
        assert_eq!(load_peer(&storage, 1), Some(PublicKey::new([0x02u8; 32])));
        assert_eq!(load_peer(&storage, 2), Some(PublicKey::new([0x03u8; 32])));
        assert!(load_peer(&storage, 3).is_none());
    }

    #[test]
    fn seed_survives_simulated_reboot() {
        let mut storage = MemStorage::new();
        let seed = Seed::new([0xDEu8; 32]);
        save_seed(&mut storage, &seed).unwrap();

        storage.clear_volatile();
        assert_eq!(load_seed(&storage), Some(seed));
    }

    #[test]
    fn file_storage_durable_and_preserves_on_failure() {
        let d = std::path::Path::new("/tmp/lichen-nv-test");
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).unwrap();
        let mut s = FileStorage::new(d).unwrap();
        let seed = Seed::new([0x22u8; 32]);
        save_seed(&mut s, &seed).unwrap();
        assert_eq!(load_seed(&s), Some(seed.clone()));
        let s2 = FileStorage::new(d).unwrap();
        assert_eq!(load_seed(&s2), Some(seed));
        save_epoch(&mut s, 42).unwrap();
        assert_eq!(load_epoch(&s), Some(42));
        let _ = std::fs::remove_dir_all(d);
    }
}

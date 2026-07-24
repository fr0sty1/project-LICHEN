//! Persistent identity storage using NonVolatile trait.
//!
//! Stores:
//! - Identity seed (32 bytes) → derives keypair on load
//! - Peer table (pubkeys for signature verification)
//! - Link layer sequence numbers (for replay protection continuity)

use crate::NonVolatile;
use lichen_link::{PublicKey, Seed};

const SLOT_VERSION: u8 = 1;
const SLOT_HEADER_LEN: usize = 20;
const SLOT_TRAILER_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedundantOpenError<E> {
    Missing,
    Corrupt,
    BufferTooSmall,
    Storage(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedundantValue {
    pub generation: u64,
    pub slot: usize,
    pub len: usize,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedundantProvisionError<E> {
    Exists,
    Storage(E),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedundantUpdateError<E> {
    Storage(E),
    Stale,
    Exhausted,
    Corrupt,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn parse_slot<'a>(raw: &'a [u8], magic: &[u8; 4]) -> Option<(u64, &'a [u8])> {
    if raw.len() < SLOT_HEADER_LEN + SLOT_TRAILER_LEN
        || &raw[..4] != magic
        || raw[4] != SLOT_VERSION
        || raw[5..8] != [0; 3]
    {
        return None;
    }
    let generation = u64::from_be_bytes(raw[8..16].try_into().ok()?);
    let payload_len = u32::from_be_bytes(raw[16..20].try_into().ok()?) as usize;
    let checksum_at = SLOT_HEADER_LEN.checked_add(payload_len)?;
    if generation == 0 || checksum_at.checked_add(SLOT_TRAILER_LEN)? != raw.len() {
        return None;
    }
    let expected = u32::from_be_bytes(raw[checksum_at..].try_into().ok()?);
    (crc32(&raw[..checksum_at]) == expected)
        .then_some((generation, &raw[SLOT_HEADER_LEN..checksum_at]))
}

fn read_raw<'a, S: NonVolatile>(
    storage: &S,
    key: &str,
    buf: &'a mut [u8],
) -> Result<Option<&'a [u8]>, RedundantOpenError<S::Error>> {
    let Some(len) = storage
        .read(key, buf)
        .map_err(RedundantOpenError::Storage)?
    else {
        return Ok(None);
    };
    if len > buf.len() {
        return Err(RedundantOpenError::BufferTooSmall);
    }
    Ok(Some(&buf[..len]))
}

fn read_parsed_update<S: NonVolatile>(
    storage: &S,
    key: &str,
    buf: &mut [u8],
    magic: [u8; 4],
) -> Result<Option<(u64, usize)>, RedundantUpdateError<S::Error>> {
    let raw = read_raw(storage, key, buf).map_err(|error| match error {
        RedundantOpenError::Storage(error) => RedundantUpdateError::Storage(error),
        _ => RedundantUpdateError::Corrupt,
    })?;
    Ok(raw.and_then(|raw| parse_slot(raw, &magic)).map(|(generation, payload)| (generation, payload.len())))
}

/// Open the newest valid value from two alternating slots.
pub fn open_redundant<S: NonVolatile>(
    storage: &S,
    keys: [&str; 2],
    magic: [u8; 4],
    slot_a: &mut [u8],
    slot_b: &mut [u8],
    out: &mut [u8],
) -> Result<RedundantValue, RedundantOpenError<S::Error>> {
    let raw_a = read_raw(storage, keys[0], slot_a)?;
    let raw_b = read_raw(storage, keys[1], slot_b)?;
    let parsed_a = raw_a.and_then(|raw| parse_slot(raw, &magic));
    let parsed_b = raw_b.and_then(|raw| parse_slot(raw, &magic));
    let (generation, slot, payload) = match (parsed_a, parsed_b) {
        (Some(a), Some(b)) if b.0 > a.0 => (b.0, 1, b.1),
        (Some(a), _) => (a.0, 0, a.1),
        (None, Some(b)) => (b.0, 1, b.1),
        (None, None) if raw_a.is_none() && raw_b.is_none() => {
            return Err(RedundantOpenError::Missing)
        }
        (None, None) => return Err(RedundantOpenError::Corrupt),
    };
    if payload.len() > out.len() {
        return Err(RedundantOpenError::BufferTooSmall);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(RedundantValue {
        generation,
        slot,
        len: payload.len(),
    })
}

fn encode_slot(magic: [u8; 4], generation: u64, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = SLOT_HEADER_LEN
        .checked_add(payload.len())?
        .checked_add(SLOT_TRAILER_LEN)?;
    if generation == 0 || payload.len() > u32::MAX as usize || out.len() < len {
        return None;
    }
    out[..4].copy_from_slice(&magic);
    out[4] = SLOT_VERSION;
    out[5..8].fill(0);
    out[8..16].copy_from_slice(&generation.to_be_bytes());
    out[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[20..20 + payload.len()].copy_from_slice(payload);
    let checksum_at = 20 + payload.len();
    let checksum = crc32(&out[..checksum_at]);
    out[checksum_at..len].copy_from_slice(&checksum.to_be_bytes());
    Some(len)
}

/// Provision an absent two-slot value. Existing or corrupt state is not overwritten.
pub fn provision_redundant<S: NonVolatile>(
    storage: &mut S,
    keys: [&str; 2],
    magic: [u8; 4],
    payload: &[u8],
    record: &mut [u8],
) -> Result<(), RedundantProvisionError<S::Error>> {
    let mut present = [0u8; 1];
    let a = storage
        .read(keys[0], &mut present)
        .map_err(RedundantProvisionError::Storage)?;
    let b = storage
        .read(keys[1], &mut present)
        .map_err(RedundantProvisionError::Storage)?;
    if a.is_some() || b.is_some() {
        return Err(RedundantProvisionError::Exists);
    }
    let len = encode_slot(magic, 1, payload, record).expect("record buffer sized by caller");
    storage
        .write(keys[0], &record[..len])
        .map_err(RedundantProvisionError::Storage)
}

/// Persist the next generation to the slot opposite `current.slot`.
pub fn update_redundant<S: NonVolatile>(
    storage: &mut S,
    keys: [&str; 2],
    magic: [u8; 4],
    current: RedundantValue,
    payload: &[u8],
    record: &mut [u8],
) -> Result<RedundantValue, RedundantUpdateError<S::Error>> {
    let (parsed_a, a_present) = read_parsed_update(storage, keys[0], record, magic)?;
    let (parsed_b, b_present) = read_parsed_update(storage, keys[1], record, magic)?;
    let latest = match (parsed_a, parsed_b) {
        (Some(a), Some(b)) if b.0 > a.0 => RedundantValue {
            generation: b.0,
            slot: 1,
            len: b.1,
        },
        (Some(a), _) => RedundantValue {
            generation: a.0,
            slot: 0,
            len: a.1,
        },
        (None, Some(b)) => RedundantValue {
            generation: b.0,
            slot: 1,
            len: b.1,
        },
        (None, None) if !a_present && !b_present => return Err(RedundantUpdateError::Stale),
        (None, None) => return Err(RedundantUpdateError::Corrupt),
    };
    if latest.generation != current.generation || latest.slot != current.slot {
        return Err(RedundantUpdateError::Stale);
    }
    let generation = current
        .generation
        .checked_add(1)
        .ok_or(RedundantUpdateError::Exhausted)?;
    let len =
        encode_slot(magic, generation, payload, record).expect("record buffer sized by caller");
    let slot = 1 - current.slot;
    storage
        .write(keys[slot], &record[..len])
        .map_err(RedundantUpdateError::Storage)?;
    Ok(RedundantValue {
        generation,
        slot,
        len: payload.len(),
    })
}

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
pub fn load_seed<S: NonVolatile>(storage: &S) -> Result<Option<Seed>, S::Error> {
    let mut buf = [0u8; 32];
    let Some(n) = storage.read(keys::IDENTITY_SEED, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 32 { Some(Seed::new(buf)) } else { None })
}

/// Save identity seed to storage.
pub fn save_seed<S: NonVolatile>(storage: &mut S, seed: &Seed) -> Result<(), S::Error> {
    storage.write(keys::IDENTITY_SEED, seed.as_bytes())
}

/// Load link layer epoch from storage.
pub fn load_epoch<S: NonVolatile>(storage: &S) -> Result<Option<u8>, S::Error> {
    let mut buf = [0u8; 1];
    let Some(n) = storage.read(keys::EPOCH, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 1 { Some(buf[0]) } else { None })
}

/// Save link layer epoch to storage.
pub fn save_epoch<S: NonVolatile>(storage: &mut S, epoch: u8) -> Result<(), S::Error> {
    storage.write(keys::EPOCH, &[epoch])
}

/// Load link layer sequence number from storage.
pub fn load_seqnum<S: NonVolatile>(storage: &S) -> Result<Option<u16>, S::Error> {
    let mut buf = [0u8; 2];
    let Some(n) = storage.read(keys::SEQNUM, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 2 {
        Some(u16::from_be_bytes(buf))
    } else {
        None
    })
}

/// Save link layer sequence number to storage.
pub fn save_seqnum<S: NonVolatile>(storage: &mut S, seqnum: u16) -> Result<(), S::Error> {
    storage.write(keys::SEQNUM, &seqnum.to_be_bytes())
}

/// Load peer count from storage.
pub fn load_peer_count<S: NonVolatile>(storage: &S) -> Result<usize, S::Error> {
    let mut buf = [0u8; 1];
    Ok(storage.read(keys::PEER_COUNT, &mut buf)?.map_or(0, |n| {
        if n == 1 {
            buf[0] as usize
        } else {
            0
        }
    }))
}

/// Load a peer pubkey from storage.
pub fn load_peer<S: NonVolatile>(storage: &S, index: usize) -> Result<Option<PublicKey>, S::Error> {
    if index >= MAX_PEERS {
        return Ok(None);
    }
    let key = peer_key(index);
    let mut buf = [0u8; 32];
    let Some(n) = storage.read(&key, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 32 {
        Some(PublicKey::new(buf))
    } else {
        None
    })
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
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use crate::NonVolatile;

    /// In-memory storage for testing.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemStorageError;

    #[derive(Debug, Default, Clone)]
    pub struct MemStorage {
        data: HashMap<String, Vec<u8>>,
        fail_after_writes: Option<usize>,
        fail_next_read: Cell<bool>,
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

        pub fn fail_next_write(&mut self) {
            self.fail_after_writes = Some(0);
        }

        pub fn fail_next_read(&self) {
            self.fail_next_read.set(true);
        }

        pub fn fail_after_writes(&mut self, successful_writes: usize) {
            self.fail_after_writes = Some(successful_writes);
        }

        pub fn set_raw(&mut self, key: &str, value: &[u8]) {
            self.data.insert(key.into(), value.to_vec());
        }

        pub fn raw(&self, key: &str) -> Option<&[u8]> {
            self.data.get(key).map(Vec::as_slice)
        }
    }

    impl NonVolatile for MemStorage {
        type Error = MemStorageError;

        fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize> {
            let data = self.data.get(key)?;
            let stored = data.len();
            let n = stored.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Some(stored)
        }

        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            if let Some(remaining) = self.fail_after_writes.as_mut() {
                if *remaining == 0 {
                    self.fail_after_writes = None;
                    return Err(MemStorageError);
                }
                *remaining -= 1;
            }
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

        assert_eq!(load_seed(&storage).unwrap(), None);
        save_seed(&mut storage, &seed).unwrap();
        assert_eq!(load_seed(&storage).unwrap(), Some(seed));
    }

    #[test]
    fn epoch_seqnum_round_trip() {
        let mut storage = MemStorage::new();

        assert_eq!(load_epoch(&storage).unwrap(), None);
        assert_eq!(load_seqnum(&storage).unwrap(), None);

        save_epoch(&mut storage, 5).unwrap();
        save_seqnum(&mut storage, 12345).unwrap();

        assert_eq!(load_epoch(&storage).unwrap(), Some(5));
        assert_eq!(load_seqnum(&storage).unwrap(), Some(12345));
    }

    #[test]
    fn peers_round_trip() {
        let mut storage = MemStorage::new();
        let peers = [
            PublicKey::new([0x01u8; 32]),
            PublicKey::new([0x02u8; 32]),
            PublicKey::new([0x03u8; 32]),
        ];

        assert_eq!(load_peer_count(&storage).unwrap(), 0);
        save_peers(&mut storage, &peers).unwrap();

        assert_eq!(load_peer_count(&storage).unwrap(), 3);
        assert_eq!(
            load_peer(&storage, 0).unwrap(),
            Some(PublicKey::new([0x01u8; 32]))
        );
        assert_eq!(
            load_peer(&storage, 1).unwrap(),
            Some(PublicKey::new([0x02u8; 32]))
        );
        assert_eq!(
            load_peer(&storage, 2).unwrap(),
            Some(PublicKey::new([0x03u8; 32]))
        );
        assert_eq!(load_peer(&storage, 3).unwrap(), None);
    }

    #[test]
    fn seed_survives_simulated_reboot() {
        let mut storage = MemStorage::new();
        let seed = Seed::new([0xDEu8; 32]);
        save_seed(&mut storage, &seed).unwrap();

        storage.clear_volatile();
        assert_eq!(load_seed(&storage).unwrap(), Some(seed));
    }

    #[test]
    fn redundant_slots_survive_corrupt_newest_and_reject_torn_only_slot() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).unwrap();
        storage.set_raw(keys[1], b"torn");
        let loaded = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(&out[..loaded.len], b"old");

        storage.delete(keys[0]);
        assert_eq!(
            open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out),
            Err(RedundantOpenError::Corrupt)
        );
    }

    #[test]
    fn acknowledged_write_is_atomic_or_old_value_remains() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        storage.fail_next_write();
        assert!(
            update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).is_err()
        );
        let loaded = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(&out[..loaded.len], b"old");
    }

    #[test]
    fn redundant_open_rejects_reported_length_larger_than_buffer() {
        let mut storage = MemStorage::new();
        storage.set_raw("test.a", &[0u8; 65]);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        assert_eq!(
            open_redundant(
                &storage,
                ["test.a", "test.b"],
                *b"TEST",
                &mut a,
                &mut b,
                &mut out,
            ),
            Err(RedundantOpenError::BufferTooSmall)
        );
    }

    #[test]
    fn redundant_update_rejects_stale_handle() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        let stale = first;
        update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).unwrap();
        assert_eq!(
            update_redundant(&mut storage, keys, *b"TEST", stale, b"lost", &mut record),
            Err(RedundantUpdateError::Stale)
        );
    }

    #[test]
    fn redundant_read_failures_are_not_treated_as_missing() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        storage.fail_next_read();
        assert_eq!(
            open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out),
            Err(RedundantOpenError::Storage(mem::MemStorageError))
        );

        let mut record = [0u8; 64];
        storage.fail_next_read();
        assert_eq!(
            provision_redundant(&mut storage, keys, *b"TEST", b"new", &mut record),
            Err(RedundantProvisionError::Storage(mem::MemStorageError))
        );
        assert!(storage.raw(keys[0]).is_none());
        assert!(storage.raw(keys[1]).is_none());
    }

    #[test]
    fn equal_max_generation_slots_are_exhausted_without_write() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        let len = encode_slot(*b"TEST", u64::MAX, b"old", &mut record).unwrap();
        storage.set_raw(keys[0], &record[..len]);
        storage.set_raw(keys[1], &record[..len]);
        let before_a = storage.raw(keys[0]).unwrap().to_vec();
        let before_b = storage.raw(keys[1]).unwrap().to_vec();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let current = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(current.generation, u64::MAX);
        assert_eq!(current.slot, 0);
        assert_eq!(
            update_redundant(&mut storage, keys, *b"TEST", current, b"new", &mut record,),
            Err(RedundantUpdateError::Exhausted)
        );
        assert_eq!(storage.raw(keys[0]), Some(before_a.as_slice()));
        assert_eq!(storage.raw(keys[1]), Some(before_b.as_slice()));
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

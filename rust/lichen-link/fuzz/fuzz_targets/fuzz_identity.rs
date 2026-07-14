#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_link::identity::{iid_from_pubkey, Identity};
use lichen_link::keys::{PublicKey, Seed};

fuzz_target!(|data: &[u8]| {
    // Fuzz identity derivation
    // Should never panic

    // Need exactly 32 bytes for a seed
    if data.len() >= 32 {
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&data[..32]);

        // Create identity from seed - should never panic
        let seed = Seed::from(seed_bytes);
        let identity = Identity::from_seed(seed);

        // IID derivation should be deterministic
        let iid1 = iid_from_pubkey(&identity.pubkey);
        let iid2 = iid_from_pubkey(&identity.pubkey);
        assert_eq!(iid1, iid2);

        // U/L bit should always be clear
        assert_eq!(iid1[0] & 0x02, 0);
    }

    // Try parsing as public key
    if data.len() >= 32 {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&data[..32]);

        // Some keys will be invalid curve points - that's OK
        if let Ok(pk) = PublicKey::from_bytes(&pk_bytes) {
            let _ = iid_from_pubkey(&pk);
        }
    }
});

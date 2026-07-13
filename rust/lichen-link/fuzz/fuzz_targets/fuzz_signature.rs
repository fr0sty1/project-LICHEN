#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured signature verification input
#[derive(Arbitrary, Debug)]
struct SigInput {
    message: Vec<u8>,
    signature: [u8; 48],  // Schnorr-48 signature size
    pubkey: [u8; 32],     // Ed25519-style pubkey
}

fuzz_target!(|input: SigInput| {
    // Fuzz signature verification
    // The verifier should never panic, only return true/false

    if input.message.len() > 1500 {
        return;
    }

    // Try to verify with arbitrary data
    // This tests that malformed signatures don't cause panics
    #[cfg(feature = "schnorr")]
    {
        use lichen_link::schnorr::{verify_signature, PublicKey, Signature};

        // Try to parse signature
        if let Ok(sig) = Signature::from_bytes(&input.signature) {
            if let Ok(pk) = PublicKey::from_bytes(&input.pubkey) {
                // Verification should never panic
                let _ = verify_signature(&pk, &input.message, &sig);
            }
        }
    }
});

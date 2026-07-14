#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lichen_coap::{BlockOption, BlockReceiver, BlockSender};

/// Structured block option input
#[derive(Arbitrary, Debug)]
struct BlockInput {
    num: u32,
    more: bool,
    szx: u8,  // Size exponent (0-6)
}

fuzz_target!(|inputs: Vec<BlockInput>| {
    // Fuzz blockwise transfer
    // Tests block option encoding/decoding and receiver state machine

    if inputs.is_empty() || inputs.len() > 100 {
        return;
    }

    // Test BlockOption encoding/decoding
    for input in &inputs {
        let szx = input.szx % 7;  // Valid range is 0-6

        // Create a block option
        let block = BlockOption::new(input.num, input.more, szx);

        // Encode to bytes
        let bytes = block.to_bytes();

        // Decode back
        if let Ok(decoded) = BlockOption::from_bytes(&bytes) {
            // Round-trip should preserve values (with szx clamped)
            assert_eq!(decoded.num(), block.num());
            assert_eq!(decoded.more(), block.more());
            assert_eq!(decoded.szx(), block.szx());
        }
    }

    // Test BlockReceiver state machine
    let mut receiver = BlockReceiver::new();

    for (i, input) in inputs.iter().enumerate().take(50) {
        let szx = input.szx % 7;
        let block_size = 16 << szx;

        // Generate fake block payload
        let payload: Vec<u8> = (0..block_size.min(1024)).map(|j| (i + j) as u8).collect();

        let block = BlockOption::new(input.num, input.more, szx);

        // Feed to receiver - should never panic
        let _ = receiver.receive_block(block, &payload);
    }

    // Check if complete
    if receiver.is_complete() {
        let _ = receiver.assemble();
    }
});

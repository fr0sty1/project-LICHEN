#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{FragmentHeader, FragmentReassembler, FragmentSender};

/// Structured fragment input
#[derive(Arbitrary, Debug)]
struct FragmentInput {
    rule_id: u8,
    window: u8,
    fcn: u8,
    payload: Vec<u8>,
}

fuzz_target!(|inputs: Vec<FragmentInput>| {
    // Fuzz fragment reassembly with multiple fragments
    // Tests the reassembler's handling of out-of-order, duplicate, and invalid fragments

    if inputs.is_empty() || inputs.len() > 100 {
        return;
    }

    // Create a reassembler and feed it fragments
    let mut reassembler = FragmentReassembler::new(inputs[0].rule_id);

    for input in &inputs {
        if input.payload.len() > 200 {
            continue;
        }

        // Build a fragment header
        let header_byte = ((input.window & 0x01) << 6) | (input.fcn & 0x3F);

        // Build fragment bytes
        let mut fragment = vec![input.rule_id, header_byte];
        fragment.extend_from_slice(&input.payload);

        // Try to parse the fragment header
        if let Ok(header) = FragmentHeader::parse(&fragment) {
            // Feed to reassembler - should never panic
            let _ = reassembler.receive(&fragment);
        }
    }

    // Try to get the reassembled result
    let _ = reassembler.is_complete();
    if reassembler.is_complete() {
        let mut output = [0u8; 2000];
        let _ = reassembler.assemble(&mut output);
    }
});

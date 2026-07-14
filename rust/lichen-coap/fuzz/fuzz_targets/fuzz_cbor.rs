#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lichen_coap::{CoapOption, CoapPacket};

/// Structured option input for more targeted fuzzing
#[derive(Arbitrary, Debug)]
struct OptionInput {
    delta: u16,
    value: Vec<u8>,
}

fuzz_target!(|inputs: Vec<OptionInput>| {
    // Fuzz CoAP option encoding/decoding
    // Tests the delta-encoded option format

    if inputs.len() > 20 {
        return;
    }

    // Build a packet with these options
    let mut bytes = vec![
        0x40,  // Ver=1, Type=CON, TKL=0
        0x01,  // Code = GET
        0x00, 0x01,  // Message ID
    ];

    let mut current_delta = 0u16;
    for input in &inputs {
        if input.value.len() > 300 {
            continue;
        }

        // Calculate relative delta
        let delta = input.delta.saturating_sub(current_delta);
        if delta > 0xFFFF - 269 {
            continue;  // Would overflow
        }

        // Encode option
        let (delta_nibble, delta_ext) = if delta < 13 {
            (delta as u8, vec![])
        } else if delta < 269 {
            (13, vec![(delta - 13) as u8])
        } else {
            (14, (delta - 269).to_be_bytes().to_vec())
        };

        let len = input.value.len();
        let (len_nibble, len_ext) = if len < 13 {
            (len as u8, vec![])
        } else if len < 269 {
            (13, vec![(len - 13) as u8])
        } else if len < 65536 {
            (14, ((len - 269) as u16).to_be_bytes().to_vec())
        } else {
            continue;  // Too long
        };

        bytes.push((delta_nibble << 4) | len_nibble);
        bytes.extend_from_slice(&delta_ext);
        bytes.extend_from_slice(&len_ext);
        bytes.extend_from_slice(&input.value);

        current_delta = input.delta;
    }

    // Try to parse the constructed packet
    if let Ok(packet) = CoapPacket::parse(&bytes) {
        // Access all options
        let mut count = 0;
        for option in packet.options() {
            let _ = option.number();
            let _ = option.value();
            count += 1;
            if count > 100 {
                break;  // Safety limit
            }
        }
    }
});

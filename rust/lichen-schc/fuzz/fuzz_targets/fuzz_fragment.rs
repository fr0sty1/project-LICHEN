#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{
    Ack, Fragment, FragmentReceiver, RULE_ID_A_TO_B, RULE_ID_B_TO_A, TILE_SIZE,
};

const FUZZ_RECEIVER_LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Extract rule_id from fuzzer input to test check_rule boundaries.
    // Valid rule_ids: RULE_ID_A_TO_B (0x78=120), RULE_ID_B_TO_A (0x79=121)
    // Boundary values to test: 119, 120, 121, 122, 127, 128
    let fuzz_rule_id = data[0];
    let rest = if data.len() > 1 {
        &data[1..]
    } else {
        &[] as &[u8]
    };

    let mut buf = [0u8; TILE_SIZE + 4];
    let _ = Fragment::from_bytes(data, &mut buf);
    let _ = Ack::from_bytes(data);

    // Test with the fuzz-derived rule_id substituted into the message
    if rest.len() >= 2 {
        let mut modified = rest.to_vec();
        modified[0] = fuzz_rule_id;
        let _ = Fragment::from_bytes(&modified, &mut buf);
        let _ = Ack::from_bytes(&modified);
    }

    // Test explicit boundary values around valid rule_id range (120-121)
    let boundary_rule_ids: [u8; 8] = [
        0,              // minimum
        119,            // just below valid
        RULE_ID_A_TO_B, // 120: valid
        RULE_ID_B_TO_A, // 121: valid
        122,            // just above valid
        127,            // edge of 7-bit range
        128,            // 8-bit boundary
        255,            // maximum
    ];

    if rest.len() >= 2 {
        for &rule_id in &boundary_rule_ids {
            let mut test_msg = rest.to_vec();
            test_msg[0] = rule_id;
            let _ = Fragment::from_bytes(&test_msg, &mut buf);
            let _ = Ack::from_bytes(&test_msg);
        }
    }

    let mut storage = [0u8; FUZZ_RECEIVER_LIMIT];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    for message in data.split_inclusive(|byte| *byte == 0).take(TILE_SIZE) {
        let _ = receiver.receive_bytes(message);
        if receiver.is_done() {
            break;
        }
    }

    // Test receiver with fuzz-derived rule_id and boundary values
    if rest.len() >= 2 {
        let mut storage2 = [0u8; FUZZ_RECEIVER_LIMIT];
        let mut receiver2 = FragmentReceiver::new(&mut storage2).unwrap();
        let mut modified = rest.to_vec();
        modified[0] = fuzz_rule_id;
        let _ = receiver2.receive_bytes(&modified);

        // Test boundary rule_ids through receiver
        for &rule_id in &boundary_rule_ids {
            let mut storage3 = [0u8; FUZZ_RECEIVER_LIMIT];
            let mut receiver3 = FragmentReceiver::new(&mut storage3).unwrap();
            let mut test_msg = rest.to_vec();
            test_msg[0] = rule_id;
            let _ = receiver3.receive_bytes(&test_msg);
        }
    }
});

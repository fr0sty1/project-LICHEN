#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{Ack, Fragment, FragmentReceiver, DEFAULT_RECEIVER_LIMIT};

fuzz_target!(|data: &[u8]| {
    let _ = Fragment::from_bytes(data);
    let _ = Ack::from_bytes(data);
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    for message in data.split_inclusive(|byte| *byte == 0).take(DEFAULT_RECEIVER_LIMIT) {
        let _ = receiver.receive_bytes(message);
        if receiver.is_done() {
            break;
        }
    }
});

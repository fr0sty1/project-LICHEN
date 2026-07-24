#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{Ack, Fragment, FragmentReceiver, TILE_SIZE, MAX_PACKET_SIZE};

fuzz_target!(|data: &[u8]| {
    let _ = Fragment::from_bytes(data);
    let _ = Ack::from_bytes(data);
    let mut storage = [0u8; MAX_PACKET_SIZE];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    for message in data.split_inclusive(|byte| *byte == 0).take(TILE_SIZE) {
        let _ = receiver.receive_bytes(message);
        if receiver.is_done() {
            break;
        }
    }
});

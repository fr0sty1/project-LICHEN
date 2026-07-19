#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{Ack, Fragment, FragmentReceiver, DEFAULT_RECEIVER_LIMIT, TILE_SIZE};

fuzz_target!(|data: &[u8]| {
    let mut tile = [0u8; TILE_SIZE];
    let _ = Fragment::from_bytes(data, &mut tile);
    let _ = Ack::from_bytes(data);
    let mut storage = [0u8; DEFAULT_RECEIVER_LIMIT];
    let mut receiver = FragmentReceiver::new(&mut storage).unwrap();
    for message in data.split_inclusive(|byte| *byte == 0).take(TILE_SIZE) {
        let _ = receiver.receive_bytes(message);
        if receiver.is_done() {
            break;
        }
    }
});

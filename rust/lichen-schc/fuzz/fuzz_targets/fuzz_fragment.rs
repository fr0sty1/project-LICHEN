#![no_main]

use libfuzzer_sys::fuzz_target;
use lichen_schc::fragment::{Ack, Fragment, FragmentReceiver, TILE_SIZE, DEFAULT_RECEIVER_LIMIT};

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; TILE_SIZE + 4];
    let _ = Fragment::from_bytes(data, &mut buf);
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

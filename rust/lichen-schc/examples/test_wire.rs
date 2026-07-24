fn main() {
    use lichen_schc::fragment::{Fragment, TILE_SIZE, MIC_LENGTH};
    let payload = [0x22u8; TILE_SIZE];
    let fragment = Fragment {
        rule_id: 0x78,
        window: 0,
        fcn: 61,
        payload: &payload,
        mic: [0; MIC_LENGTH],
    };
    let mut wire = [0xffu8; TILE_SIZE + 6];
    let len = fragment.write_to(&mut wire).unwrap();
    println!("First 6 bytes: {:02x?}", &wire[..6.min(len)]);
    println!("Byte[2] = 0x{:02x}, expect 0x{:02x}", wire[2], 0x22u8 << 1);
}

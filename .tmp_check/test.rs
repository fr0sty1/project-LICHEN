fn transcript_4(a: &[u8], b: &[u8]) -> u8 { 0 }

fn main() {
    let a = [0u8; 32];
    let b = [1u8; 32];
    let c = [2u8; 32];
    let _x = transcript_4(&a, &b, &c);
}

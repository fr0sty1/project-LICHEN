//! SLIP framing (RFC 1055).
//!
//! SLIP is a trivial byte-stuffing framing protocol.  Each packet is bounded
//! by END (0xC0) bytes; END and ESC bytes in the payload are replaced by
//! two-byte escape sequences.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const END: u8 = 0xC0;
const ESC: u8 = 0xDB;
const ESC_END: u8 = 0xDC; // sent in place of END inside a packet
const ESC_ESC: u8 = 0xDD; // sent in place of ESC inside a packet

/// Send `packet` as a single SLIP frame on `writer`.
///
/// Surrounds the packet with END bytes and escapes any END/ESC bytes in the
/// payload per RFC 1055 §2.
pub async fn send_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &[u8],
) -> io::Result<()> {
    // Leading END flushes any garbage from a previous interrupted packet.
    writer.write_all(&[END]).await?;

    let mut buf = Vec::with_capacity(packet.len() + 2);
    for &byte in packet {
        match byte {
            END => {
                buf.push(ESC);
                buf.push(ESC_END);
            }
            ESC => {
                buf.push(ESC);
                buf.push(ESC_ESC);
            }
            b => buf.push(b),
        }
    }
    buf.push(END);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Read one SLIP packet from `reader` into `buf`.
///
/// Blocks until a complete packet is received (terminated by END).
/// Returns the number of bytes written into `buf`, or an error if `buf`
/// is too small.
pub async fn recv_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut out = 0usize;
    let mut in_escape = false;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        let byte = byte[0];

        match byte {
            END => {
                if out > 0 {
                    // Non-empty packet complete.
                    return Ok(out);
                }
                // Empty END: inter-packet separator, keep reading.
            }
            ESC => {
                in_escape = true;
            }
            ESC_END if in_escape => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SLIP packet too large"));
                }
                buf[out] = END;
                out += 1;
            }
            ESC_ESC if in_escape => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SLIP packet too large"));
                }
                buf[out] = ESC;
                out += 1;
            }
            b => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SLIP packet too large"));
                }
                buf[out] = b;
                out += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(packet: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        send_packet(&mut wire, packet).await.unwrap();

        let mut decoded = vec![0u8; packet.len() + 4];
        let n = recv_packet(&mut wire.as_slice(), &mut decoded).await.unwrap();
        decoded.truncate(n);
        decoded
    }

    #[tokio::test]
    async fn plain_packet() {
        let data = b"hello SLIP";
        assert_eq!(roundtrip(data).await, data);
    }

    #[tokio::test]
    async fn packet_with_end_byte() {
        let data = [0x01, END, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_esc_byte() {
        let data = [0x01, ESC, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_both_special_bytes() {
        let data = [END, ESC, END, 0x42, ESC];
        assert_eq!(roundtrip(&data).await, &data);
    }
}

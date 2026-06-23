//! TCP client stub connecting to the LICHEN simulator server.
//!
//! The simulator server speaks a simple length-prefixed framing protocol over
//! TCP. Each message is a 2-byte big-endian length followed by the frame bytes.
//! This mirrors the Python SimRadio in `python/src/lichen/radio/sim_client.py`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};

/// Default simulator server address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:4444";

/// TCP client for the LICHEN simulator.
pub struct SimClient {
    stream: TcpStream,
}

impl SimClient {
    /// Connect to the simulator server at `addr`.
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream })
    }

    /// Send a raw frame to the simulator.
    pub fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let len = (frame.len() as u16).to_be_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(frame)?;
        Ok(())
    }

    /// Receive one frame from the simulator into `buf`.
    ///
    /// Returns the number of bytes written into `buf`, or an error if the
    /// frame is larger than `buf`.
    pub fn recv_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len_bytes = [0u8; 2];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u16::from_be_bytes(len_bytes) as usize;
        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        self.stream.read_exact(&mut buf[..len])?;
        Ok(len)
    }
}

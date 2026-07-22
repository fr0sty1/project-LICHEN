//! Mock HAL implementations for host-side testing.
//!
//! These implement the lichen-hal traits using std, allowing protocol logic
//! to be tested without real hardware.

use lichen_hal::{ChannelConfig, Clock, NonVolatile, RadioConfig, RadioError, Rng, RxPacket};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

/// Mock radio that stores transmitted packets and can be fed received packets.
#[derive(Debug)]
pub struct MockRadio {
    config: RadioConfig,
    tx_queue: Mutex<Vec<Vec<u8>>>,
    rx_queue: Mutex<VecDeque<(Vec<u8>, RxPacket)>>,
}

impl MockRadio {
    pub fn new() -> Self {
        Self {
            config: RadioConfig::default(),
            tx_queue: Mutex::new(Vec::new()),
            rx_queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Get packets that were transmitted.
    pub fn take_transmitted(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.tx_queue.lock().unwrap())
    }

    /// Feed a packet to be received.
    pub fn feed_rx(&self, data: &[u8], rssi: i16, snr: i8) {
        self.rx_queue.lock().unwrap().push_back((
            data.to_vec(),
            RxPacket {
                len: data.len(),
                rssi: Some(rssi),
                snr: Some(snr),
            },
        ));
    }
}

impl Default for MockRadio {
    fn default() -> Self {
        Self::new()
    }
}

impl lichen_hal::Radio for MockRadio {
    type Error = RadioError<core::convert::Infallible>;

    async fn transmit(&mut self, _channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        self.tx_queue.lock().unwrap().push(payload.to_vec());
        Ok(())
    }

    async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn receive(
        &mut self,
        _channel: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        debug_assert!(
            buf.len() >= 255,
            "Radio::receive buffer too small: {} < 255",
            buf.len()
        );

        let mut queue = self.rx_queue.lock().unwrap();
        if let Some((data, meta)) = queue.pop_front() {
            if data.len() > buf.len() {
                return Err(RadioError::Protocol);
            }
            buf[..data.len()].copy_from_slice(&data);
            return Ok(Some(RxPacket {
                len: data.len(),
                rssi: meta.rssi,
                snr: meta.snr,
            }));
        }
        drop(queue);

        std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
        Ok(None)
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
    }

    async fn configure_channels(
        &mut self,
        _channels: &[ChannelConfig],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Mock clock using std::time::Instant.
#[derive(Debug)]
pub struct MockClock {
    start: Instant,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

/// Mock RNG for testing only - uses deterministic xorshift PRNG.
///
/// # Security Warning
///
/// **DO NOT USE FOR CRYPTOGRAPHIC OPERATIONS.**
///
/// This implementation:
/// - Uses a hardcoded seed (`0xDEADBEEF`) - output is fully predictable
/// - Uses xorshift which is NOT cryptographically secure
/// - Produces identical sequences across all instances and runs
///
/// This is intentionally simple and deterministic for reproducible tests.
/// For production, use a hardware RNG or OS-provided CSPRNG.
///
/// # Accidental Production Use
///
/// The `mock` feature should never be enabled in release builds. If you see
/// compile warnings about the mock feature in release mode, that's a bug.
#[cfg_attr(
    all(feature = "mock", not(debug_assertions)),
    deprecated(note = "MockRng enabled in release build - this is a security risk!")
)]
#[derive(Debug)]
pub struct MockRng;

impl Rng for MockRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        // SECURITY: Deterministic xorshift - NOT cryptographically secure.
        // ponytail: simple xorshift instead of pulling in rand crate
        static SEED: Mutex<u64> = Mutex::new(0xDEADBEEF);
        let mut seed = SEED.lock().unwrap();
        for byte in buf.iter_mut() {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *byte = *seed as u8;
        }
    }
}

/// Mock non-volatile storage using a HashMap.
#[derive(Debug)]
pub struct MockNonVolatile {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockNonVolatile {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockNonVolatile {
    fn default() -> Self {
        Self::new()
    }
}

impl NonVolatile for MockNonVolatile {
    type Error = core::convert::Infallible;

    fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize> {
        let data = self.data.lock().unwrap();
        data.get(key).map(|v| {
            let len = v.len().min(buf.len());
            buf[..len].copy_from_slice(&v[..len]);
            len
        })
    }

    fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), data.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &str) -> bool {
        self.data.lock().unwrap().remove(key).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_advances() {
        let clock = MockClock::new();
        let t1 = clock.now_us();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clock.now_us();
        assert!(t2 > t1);
    }

    #[test]
    fn mock_rng_produces_bytes() {
        let mut rng = MockRng;
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn mock_nv_roundtrip() {
        let mut nv = MockNonVolatile::new();
        nv.write("test_key", b"hello").unwrap();

        let mut buf = [0u8; 32];
        let len = nv.read("test_key", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");

        assert!(nv.delete("test_key"));
        assert!(nv.read("test_key", &mut buf).is_none());
    }

    #[tokio::test]
    async fn mock_radio_tx() {
        use lichen_hal::Radio;

        let mut radio = MockRadio::new();
        radio.transmit(0, b"hello mesh").await.unwrap();

        let tx = radio.take_transmitted();
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0], b"hello mesh");
    }

    #[tokio::test]
    async fn mock_radio_rx() {
        use lichen_hal::Radio;

        let mut radio = MockRadio::new();
        radio.feed_rx(b"incoming", -80, 10);

        let mut buf = [0u8; 255];
        let pkt = radio.receive(0, &mut buf, 1000).await.unwrap().unwrap();
        assert_eq!(pkt.len, 8);
        assert_eq!(&buf[..8], b"incoming");
        assert_eq!(pkt.rssi, Some(-80));
    }
}

//! Announce scheduler for periodic transmission (spec section 9.4).
//!
//! Manages the announce loop: waits interval + jitter, builds signed announces,
//! transmits via link layer, increments sequence number.
//!
//! Why separate from Stack: Single responsibility. The scheduler owns timing and
//! sequence number management. Stack owns lifecycle and layer integration.
//!
//! Why sequence number persistence matters: If seq_num resets on reboot, peers
//! may reject our new announces as "stale" (lower than what they've seen).
//! For the prototype, we don't persist to flash. Production implementations
//! MUST persist seq_num to non-volatile storage.

extern crate std;

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::vec;
use std::vec::Vec;

use lichen_core::announce::AnnounceBuilder;
use lichen_link::identity::Identity;
use lichen_link::schnorr::sign;

#[cfg(feature = "defmt")]
use defmt::{info, warn};
#[cfg(all(feature = "log", not(feature = "defmt")))]
use log::{info, warn};

/// Default announce interval in milliseconds (spec 9.4: 5 minutes).
pub const DEFAULT_INTERVAL_MS: u64 = 300_000;

/// Default maximum jitter in milliseconds (spec 9.4: 0-30 seconds).
pub const DEFAULT_JITTER_MS: u64 = 30_000;

/// Default RX channel announced for rendezvous (CCP-9).
pub const DEFAULT_CHANNEL: u8 = 0;

/// Announce scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub interval_ms: u64,
    pub jitter_ms: u64,
    pub initial_delay_ms: u64,
    pub rx_channel: u8,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            jitter_ms: DEFAULT_JITTER_MS,
            initial_delay_ms: 0,
            rx_channel: 0,
        }
    }
}

/// Error returned by scheduler operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    /// Scheduler is not running.
    NotRunning,
    /// Scheduler is already running.
    AlreadyRunning,
    /// Buffer too small for announce message.
    BufferTooSmall,
    InvalidChannel,
    /// Transmission failed.
    TransmitFailed,
}

impl core::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRunning => write!(f, "scheduler not running"),
            Self::AlreadyRunning => write!(f, "scheduler already running"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidChannel => write!(f, "invalid rx_channel"),
            Self::TransmitFailed => write!(f, "transmit failed"),
        }
    }
}

impl core::error::Error for SchedulerError {}

/// Trait for transmitting announces.
///
/// Why a trait: Decouples scheduler from link layer. Allows testing
/// with mocks and different transmission strategies.
pub trait AnnounceTransmitter: Send + Sync {
    /// Transmit announce data. Returns Ok(true) on success.
    fn transmit_announce<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Callback type for sequence number changes (for persistence).
pub type SeqChangeCallback = Box<dyn Fn(u16) + Send + Sync>;

/// Shared state for the scheduler, allowing external control.
struct SchedulerState {
    /// Current sequence number (atomic for safe concurrent access).
    seq_num: AtomicU16,
    /// Whether the scheduler is running.
    running: AtomicBool,
}

/// Periodic announce transmission scheduler (spec 9.4).
///
/// Why this struct: Encapsulates the announce loop, sequence number
/// management, and timing. Can be started/stopped independently.
pub struct AnnounceScheduler<T: AnnounceTransmitter> {
    /// This node's cryptographic identity.
    identity: Identity,
    /// How to send announces (link layer or mock).
    transmitter: Arc<T>,
    /// Scheduler configuration.
    config: SchedulerConfig,
    /// Optional application data to include in announces.
    app_data: Vec<u8>,
    /// Shared state (seq_num, running flag).
    state: Arc<SchedulerState>,
    /// Callback for sequence number changes (optional).
    on_seq_change: Option<SeqChangeCallback>,
}

impl<T: AnnounceTransmitter + 'static> AnnounceScheduler<T> {
    /// Create a new scheduler with the given identity and transmitter.
    pub fn new(identity: Identity, transmitter: T) -> Self {
        Self {
            identity,
            transmitter: Arc::new(transmitter),
            config: SchedulerConfig::default(),
            app_data: Vec::new(),
            state: Arc::new(SchedulerState {
                seq_num: AtomicU16::new(0),
                running: AtomicBool::new(false),
            }),
            on_seq_change: None,
        }
    }

    /// Create a new scheduler with custom configuration.
    pub fn with_config(identity: Identity, transmitter: T, config: SchedulerConfig) -> Self {
        Self {
            identity,
            transmitter: Arc::new(transmitter),
            config,
            app_data: Vec::new(),
            state: Arc::new(SchedulerState {
                seq_num: AtomicU16::new(0),
                running: AtomicBool::new(false),
            }),
            on_seq_change: None,
        }
    }

    /// Set the sequence number (for persistence restore).
    ///
    /// Why exposed: On startup, caller loads persisted seq_num and
    /// sets it here before starting the scheduler.
    pub fn set_seq_num(&self, seq_num: u16) {
        self.state.seq_num.store(seq_num, Ordering::SeqCst);
        #[cfg(any(feature = "defmt", feature = "log"))]
        info!("sequence number set to {}", seq_num);
    }

    /// Get the current sequence number (for persistence save).
    pub fn get_seq_num(&self) -> u16 {
        self.state.seq_num.load(Ordering::SeqCst)
    }

    /// Set callback for sequence number changes (for persistence).
    ///
    /// Why callback: Caller owns persistence. We notify when seq_num
    /// changes so they can save it.
    pub fn set_on_seq_change(&mut self, callback: SeqChangeCallback) {
        self.on_seq_change = Some(callback);
    }

    /// Set optional application data to include in announces.
    pub fn set_app_data(&mut self, data: Vec<u8>) {
        self.app_data = data;
    }

    /// Get the current RX channel announced for rendezvous (CCP-9).
    ///
    /// Why exposed: LCI and processor query this to know what channel
    /// we're advertising as our preferred RX for announce-driven
    /// rendezvous pinning.
    pub fn current_channel(&self) -> u8 {
        self.config.rx_channel
    }

    /// Whether the scheduler is currently running.
    pub fn is_running(&self) -> bool {
        self.state.running.load(Ordering::SeqCst)
    }

    /// Increment and return the new sequence number.
    ///
    /// Why wrap at 0xFFFF: seq_num is 16-bit per spec.
    fn increment_seq(&self) -> u16 {
        let new_seq = self
            .state
            .seq_num
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(x.wrapping_add(1))
            })
            .unwrap()
            .wrapping_add(1);

        // Why notify: Allows caller to persist the new value.
        if let Some(ref callback) = self.on_seq_change {
            callback(new_seq);
        }

        new_seq
    }

    /// Build a signed announce message.
    ///
    /// Why separate method: Allows testing without running the loop.
    /// Also useful for manual announce triggers.
    ///
    /// Returns the number of bytes written to the output buffer.
    pub fn build_announce(&self, out: &mut [u8]) -> Result<usize, SchedulerError> {
        if self.config.rx_channel >= 8 {
            return Err(SchedulerError::InvalidChannel);
        }
        let seq = self.increment_seq();

        let signed_data_len = 8 + 32 + 2 + 1 + self.app_data.len();
        let mut signed_data = vec![0u8; signed_data_len];
        signed_data[..8].copy_from_slice(&self.identity.iid);
        signed_data[8..40].copy_from_slice(self.identity.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&seq.to_be_bytes());
        signed_data[42] = self.config.rx_channel;
        signed_data[43..].copy_from_slice(&self.app_data);

        let signature = sign(&self.identity.privkey, &self.identity.pubkey, &signed_data);

        let builder = AnnounceBuilder {
            originator_iid: &self.identity.iid,
            pubkey: self.identity.pubkey.as_bytes(),
            seq_num: seq,
            hop_count: 0,
            rx_channel: self.config.rx_channel,
            signature: &signature,
            app_data: &self.app_data,
        };

        builder
            .write_to(out)
            .map_err(|_| SchedulerError::BufferTooSmall)
    }

    /// Start the announce scheduler.
    ///
    /// Returns a future that runs the scheduler loop until stopped.
    /// The caller should spawn this as a background task.
    ///
    /// # Errors
    ///
    /// Returns `SchedulerError::AlreadyRunning` if already running.
    pub async fn start(&self) -> Result<(), SchedulerError> {
        if self
            .state
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SchedulerError::AlreadyRunning);
        }

        #[cfg(any(feature = "defmt", feature = "log"))]
        info!("announce scheduler started");

        self.run_loop().await;

        Ok(())
    }

    /// Stop the announce scheduler.
    ///
    /// Safe to call even if not running.
    pub fn stop(&self) {
        self.state.running.store(false, Ordering::SeqCst);
        #[cfg(any(feature = "defmt", feature = "log"))]
        info!("announce scheduler stopped");
    }

    /// The main announce loop.
    ///
    /// Why infinite loop: Runs until stop() is called.
    ///
    /// Flow:
    /// 1. Wait initial delay (let node discover peers first)
    /// 2. Loop forever:
    ///    a. Build and send announce
    ///    b. Wait interval + random jitter
    async fn run_loop(&self) {
        // Why initial delay: Let node receive announces from others first.
        // This builds gradients before we advertise ourselves.
        // Why randomize: Prevents thundering herd if many nodes power on together.
        let initial_delay = if self.config.initial_delay_ms == 0 {
            // Random 1-30 seconds (at least 1s to receive some announces)
            let upper = self.config.jitter_ms.max(1000);
            random_range(1000, upper)
        } else {
            self.config.initial_delay_ms
        };

        tokio::time::sleep(Duration::from_millis(initial_delay)).await;

        while self.state.running.load(Ordering::SeqCst) {
            // Send announce
            self.send_announce().await;

            // Wait with jitter
            // Why jitter: Prevents all nodes announcing at the same time.
            let jitter = random_range(0, self.config.jitter_ms);
            let delay = self.config.interval_ms + jitter;
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    /// Build and transmit an announce.
    async fn send_announce(&self) {
        let mut buf = [0u8; 256];
        match self.build_announce(&mut buf) {
            Ok(len) => {
                let success = self.transmitter.transmit_announce(&buf[..len]).await;
                #[cfg(any(feature = "defmt", feature = "log"))]
                {
                    let seq = self.get_seq_num();
                    if success {
                        info!("sent announce seq={}", seq);
                    } else {
                        warn!("failed to send announce seq={}", seq);
                    }
                }
                #[cfg(not(any(feature = "defmt", feature = "log")))]
                let _ = success;
            }
            Err(_e) => {
                #[cfg(any(feature = "defmt", feature = "log"))]
                warn!("failed to build announce");
            }
        }
    }

    /// Manually trigger an immediate announce.
    ///
    /// Why exposed: Useful for testing and for triggering announces
    /// after significant events (e.g., topology change).
    ///
    /// Returns Ok(true) if announce was sent successfully.
    pub async fn send_now(&self) -> Result<bool, SchedulerError> {
        if !self.state.running.load(Ordering::SeqCst) {
            #[cfg(any(feature = "defmt", feature = "log"))]
            warn!("cannot send announce: scheduler not running");
            return Err(SchedulerError::NotRunning);
        }

        let mut buf = [0u8; 256];
        let len = self.build_announce(&mut buf)?;
        let success = self.transmitter.transmit_announce(&buf[..len]).await;
        Ok(success)
    }
}

/// Generate a random u64 in the range [min, max] using LCG for jitter.
fn random_range(min: u64, max: u64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    if min >= max {
        return min;
    }

    // Static state for LCG, persists between calls
    static STATE: AtomicU64 = AtomicU64::new(0);

    // LCG parameters (Numerical Recipes)
    let a: u64 = 1664525;
    let c: u64 = 1013904223;
    let m: u64 = 1 << 32;

    loop {
        let current = STATE.load(Ordering::Relaxed);
        let state = if current == 0 {
            // First call: seed from time + process ID for per-node uniqueness
            let time_seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_nanos() as u64;
            let pid = std::process::id() as u64;
            time_seed.wrapping_add(pid.wrapping_mul(0x9E3779B97F4A7C15))
        } else {
            current
        };

        // Advance the LCG
        let next_state = (state.wrapping_mul(a).wrapping_add(c)) % m;

        // Atomically update state (handles concurrent calls)
        if STATE
            .compare_exchange(current, next_state, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return min + (next_state % (max - min + 1));
        }
        // Another thread updated state, retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_link::Seed;
    use std::sync::atomic::AtomicUsize;
    use std::vec::Vec;

    /// Mock transmitter for testing.
    struct MockTransmitter {
        tx_count: AtomicUsize,
        last_data: std::sync::Mutex<Vec<u8>>,
    }

    impl MockTransmitter {
        fn new() -> Self {
            Self {
                tx_count: AtomicUsize::new(0),
                last_data: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn tx_count(&self) -> usize {
            self.tx_count.load(Ordering::SeqCst)
        }
    }

    impl AnnounceTransmitter for MockTransmitter {
        fn transmit_announce<'a>(
            &'a self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move {
                self.tx_count.fetch_add(1, Ordering::SeqCst);
                *self.last_data.lock().unwrap() = data.to_vec();
                true
            })
        }
    }

    #[test]
    fn seq_num_management() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let scheduler = AnnounceScheduler::new(identity, tx);

        assert_eq!(scheduler.get_seq_num(), 0);

        scheduler.set_seq_num(100);
        assert_eq!(scheduler.get_seq_num(), 100);

        // Increment wraps at 0xFFFF
        scheduler.set_seq_num(0xFFFF);
        let mut buf = [0u8; 128];
        scheduler.build_announce(&mut buf).unwrap();
        assert_eq!(scheduler.get_seq_num(), 0); // Wrapped
    }

    #[test]
    fn build_announce_valid() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let scheduler = AnnounceScheduler::new(identity.clone(), tx);

        let mut buf = [0u8; 128];
        let len = scheduler.build_announce(&mut buf).unwrap();

        // Minimum announce size: 93 bytes (1+1+1+2+8+32+48)
        assert!(len >= 93);

        // Parse the announce
        let announce = lichen_core::announce::Announce::from_bytes(&buf[..len]).unwrap();
        assert_eq!(announce.originator_iid, &identity.iid);
        assert_eq!(announce.pubkey, identity.pubkey.as_bytes());
        assert_eq!(announce.seq_num, 1); // First increment
        assert_eq!(announce.hop_count, 0); // We're the originator
    }

    #[test]
    fn build_announce_with_app_data() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let mut scheduler = AnnounceScheduler::new(identity, tx);

        scheduler.set_app_data(vec![0x01, 0x02, 0x03, 0x04]);

        let mut buf = [0u8; 128];
        let len = scheduler.build_announce(&mut buf).unwrap();

        let announce = lichen_core::announce::Announce::from_bytes(&buf[..len]).unwrap();
        assert_eq!(announce.app_data, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn seq_change_callback() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let mut scheduler = AnnounceScheduler::new(identity, tx);

        let callback_seq = Arc::new(AtomicU16::new(0));
        let callback_seq_clone = callback_seq.clone();

        scheduler.set_on_seq_change(Box::new(move |seq| {
            callback_seq_clone.store(seq, Ordering::SeqCst);
        }));

        let mut buf = [0u8; 128];
        scheduler.build_announce(&mut buf).unwrap();

        assert_eq!(callback_seq.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn scheduler_lifecycle() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let scheduler = AnnounceScheduler::with_config(
            identity,
            tx,
            SchedulerConfig {
                interval_ms: 50,
                jitter_ms: 0,
                initial_delay_ms: 1,
                rx_channel: 0,
            },
        );

        assert!(!scheduler.is_running());

        // Start in background
        let scheduler = Arc::new(scheduler);
        let scheduler_clone = scheduler.clone();
        let handle = tokio::spawn(async move { scheduler_clone.start().await });

        // Wait a bit for it to start and send some announces
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert!(scheduler.is_running());
        assert!(scheduler.transmitter.tx_count() >= 1);
        assert!(!scheduler.transmitter.last_data().is_empty());

        // Stop
        scheduler.stop();

        // Wait for task to finish
        let _ = handle.await;

        assert!(!scheduler.is_running());
    }

    #[tokio::test]
    async fn send_now_requires_running() {
        let identity = Identity::from_seed(Seed::new([0x01; 32]));
        let tx = MockTransmitter::new();
        let scheduler = AnnounceScheduler::new(identity, tx);

        let result = scheduler.send_now().await;
        assert_eq!(result, Err(SchedulerError::NotRunning));
    }

    #[test]
    fn random_range_produces_varied_output() {
        // Consecutive calls must produce different values (within a large range).
        // This catches the original bug where same-millisecond calls were identical.
        let mut values = Vec::new();
        for _ in 0..100 {
            values.push(super::random_range(0, 1_000_000));
        }

        // Count unique values - should be high (near 100) for a working PRNG
        let mut unique = values.clone();
        unique.sort();
        unique.dedup();

        // With range 0..1M and 100 samples, collision is unlikely.
        // Allow a few collisions but not many.
        assert!(
            unique.len() >= 90,
            "PRNG produced too many duplicates: {} unique out of 100",
            unique.len()
        );
    }
}

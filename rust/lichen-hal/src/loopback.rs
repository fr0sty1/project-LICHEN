// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Loopback radio for testing.
//!
//! Provides a pair of connected radios for host-side integration tests.
//! TX on one side appears as RX on the other.

use crate::{ChannelConfig, Radio, RadioConfig, RadioError, RxPacket};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Shared channel between loopback radio pair.
///
/// This is a thin wrapper around VecDeque that provides radio-semantic method
/// names (send/recv). Intentionally minimal: the wrapper costs nothing at
/// runtime and keeps the Radio impl readable. If the underlying queue type
/// changes (e.g., to a bounded channel), the change is localized here.
struct Channel {
    queue: VecDeque<Vec<u8>>,
}

impl Channel {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    fn send(&mut self, data: &[u8]) {
        self.queue.push_back(data.to_vec());
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
}

/// Loopback radio endpoint.
///
/// Part of a connected pair. TX goes to the other endpoint's RX.
pub struct LoopbackRadio {
    /// Channel for packets we transmit (other side receives).
    tx_chan: Arc<Mutex<Channel>>,
    /// Channel for packets we receive (other side transmitted).
    rx_chan: Arc<Mutex<Channel>>,
    /// Current configuration.
    config: RadioConfig,
}

impl LoopbackRadio {
    /// Create a connected pair of loopback radios.
    ///
    /// Returns (radio_a, radio_b). TX on A appears as RX on B and vice versa.
    pub fn pair() -> (Self, Self) {
        let chan_a_to_b = Arc::new(Mutex::new(Channel::new()));
        let chan_b_to_a = Arc::new(Mutex::new(Channel::new()));

        let radio_a = Self {
            tx_chan: Arc::clone(&chan_a_to_b),
            rx_chan: Arc::clone(&chan_b_to_a),
            config: RadioConfig::default(),
        };

        let radio_b = Self {
            tx_chan: chan_b_to_a,
            rx_chan: chan_a_to_b,
            config: RadioConfig::default(),
        };

        (radio_a, radio_b)
    }

    /// Check if there are pending packets to receive.
    pub fn has_pending(&self) -> bool {
        let guard = self.rx_chan.lock().unwrap_or_else(|e| e.into_inner());
        !guard.queue.is_empty()
    }
}

impl Radio for LoopbackRadio {
    type Error = RadioError<std::convert::Infallible>;

    async fn transmit(&mut self, _channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        let mut guard = self.tx_chan.lock().unwrap_or_else(|e| e.into_inner());
        guard.send(payload);
        Ok(())
    }

    async fn receive(
        &mut self,
        _channel: u8,
        buf: &mut [u8],
        _timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        let data = {
            let mut guard = self.rx_chan.lock().unwrap_or_else(|e| e.into_inner());
            guard.recv()
        };

        debug_assert!(
            buf.len() >= 255,
            "Radio::receive buffer too small: {} < 255",
            buf.len()
        );

        match data {
            Some(pkt) => {
                if pkt.len() > buf.len() {
                    return Err(RadioError::Protocol);
                }
                buf[..pkt.len()].copy_from_slice(&pkt);
                Ok(Some(RxPacket {
                    len: pkt.len(),
                    rssi: Some(-50),
                    snr: Some(10),
                }))
            }
            None => Ok(None),
        }
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
    }

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn cca(&mut self, _channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_loopback_pair() {
        let (mut radio_a, mut radio_b) = LoopbackRadio::pair();

        // A sends, B receives
        radio_a.transmit(0, b"hello from A").await.unwrap();

        let mut buf = [0u8; 256];
        let rx = radio_b.receive(0, &mut buf, 1000).await.unwrap();
        assert!(rx.is_some());
        let rx = rx.unwrap();
        assert_eq!(&buf[..rx.len], b"hello from A");

        // B sends, A receives
        radio_b.transmit(0, b"hello from B").await.unwrap();

        let rx = radio_a.receive(0, &mut buf, 1000).await.unwrap();
        assert!(rx.is_some());
        let rx = rx.unwrap();
        assert_eq!(&buf[..rx.len], b"hello from B");
    }

    #[tokio::test]
    async fn test_loopback_empty() {
        let (mut radio_a, _radio_b) = LoopbackRadio::pair();

        let mut buf = [0u8; 256];
        let rx = radio_a.receive(0, &mut buf, 100).await.unwrap();
        assert!(rx.is_none());
    }
}

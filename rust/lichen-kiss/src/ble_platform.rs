//! Platform bindings for the KISS BLE GATT transport.
//!
//! The lifecycle wrapper stays `no_std`; host Bluetooth support is isolated
//! behind `kiss-ble-btleplug` so embedded/core builds do not acquire an OS BLE
//! stack. Embedded firmware can implement [`BleGattBackend`] with its selected
//! controller/host stack (Embassy itself is only an executor/HAL).

use core::fmt;

/// Largest bounded KISS GATT write or notification accepted by this binding.
pub const MAX_BLE_FRAME: usize = 512;

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleLinkState {
    /// No usable GATT connection.
    Disconnected,
    /// Service discovery and notification subscription completed.
    Connected,
}

/// Platform-independent asynchronous GATT operations.
#[allow(async_fn_in_trait)]
pub trait BleGattBackend {
    /// Platform error.
    type Error;

    /// Connect, discover the KISS service, and subscribe to RX notifications.
    async fn connect(&mut self) -> Result<(), Self::Error>;

    /// Write one bounded KISS fragment to the TX characteristic.
    async fn write_tx(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Await one RX notification and copy it into `out`.
    async fn next_rx(&mut self, out: &mut [u8]) -> Result<usize, Self::Error>;

    /// Disconnect and release platform resources.
    async fn disconnect(&mut self) -> Result<(), Self::Error>;
}

/// Lifecycle or platform error from [`BleTncLink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleLinkError<E> {
    /// Operation requires a different connection state.
    InvalidState,
    /// Empty writes are not valid KISS fragments.
    EmptyFrame,
    /// Frame exceeds the fixed transport bound.
    FrameTooLarge,
    /// Backend reported more bytes than the supplied output buffer.
    InvalidLength,
    /// Platform backend failure.
    Backend(E),
}

impl<E: fmt::Display> fmt::Display for BleLinkError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState => f.write_str("invalid BLE link state"),
            Self::EmptyFrame => f.write_str("empty BLE frame"),
            Self::FrameTooLarge => f.write_str("BLE frame exceeds fixed bound"),
            Self::InvalidLength => f.write_str("BLE backend returned an invalid length"),
            Self::Backend(err) => write!(f, "BLE backend: {err}"),
        }
    }
}

/// Bounded connection lifecycle around a platform GATT backend.
pub struct BleTncLink<B> {
    backend: B,
    state: BleLinkState,
}

impl<B: BleGattBackend> BleTncLink<B> {
    /// Create a disconnected link.
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            state: BleLinkState::Disconnected,
        }
    }

    /// Current lifecycle state.
    pub const fn state(&self) -> BleLinkState {
        self.state
    }

    /// Borrow the backend, primarily for platform diagnostics.
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Connect and complete service discovery/subscription atomically.
    pub async fn connect(&mut self) -> Result<(), BleLinkError<B::Error>> {
        if self.state != BleLinkState::Disconnected {
            return Err(BleLinkError::InvalidState);
        }
        self.backend
            .connect()
            .await
            .map_err(BleLinkError::Backend)?;
        self.state = BleLinkState::Connected;
        Ok(())
    }

    /// Write a KISS fragment to the device.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), BleLinkError<B::Error>> {
        if self.state != BleLinkState::Connected {
            return Err(BleLinkError::InvalidState);
        }
        if data.is_empty() {
            return Err(BleLinkError::EmptyFrame);
        }
        if data.len() > MAX_BLE_FRAME {
            return Err(BleLinkError::FrameTooLarge);
        }
        self.backend
            .write_tx(data)
            .await
            .map_err(BleLinkError::Backend)
    }

    /// Await and copy one bounded device notification.
    pub async fn receive(&mut self, out: &mut [u8]) -> Result<usize, BleLinkError<B::Error>> {
        if self.state != BleLinkState::Connected {
            return Err(BleLinkError::InvalidState);
        }
        let bound = core::cmp::min(out.len(), MAX_BLE_FRAME);
        let len = self
            .backend
            .next_rx(&mut out[..bound])
            .await
            .map_err(BleLinkError::Backend)?;
        if len > bound {
            return Err(BleLinkError::InvalidLength);
        }
        Ok(len)
    }

    /// Disconnect. State is cleared even if platform cleanup reports an error.
    pub async fn disconnect(&mut self) -> Result<(), BleLinkError<B::Error>> {
        if self.state != BleLinkState::Connected {
            return Err(BleLinkError::InvalidState);
        }
        let result = self.backend.disconnect().await;
        self.state = BleLinkState::Disconnected;
        result.map_err(BleLinkError::Backend)
    }

    /// Consume the wrapper and return the backend.
    pub fn into_backend(self) -> B {
        self.backend
    }
}

#[cfg(feature = "kiss-ble-btleplug")]
pub mod btleplug_backend {
    //! Desktop BLE Central binding using `btleplug`.

    use super::{BleGattBackend, MAX_BLE_FRAME};
    use crate::ble::{RX_CHAR_UUID, SERVICE_UUID, TX_CHAR_UUID};
    use btleplug::api::{
        Central, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType,
    };
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures_util::StreamExt;
    use std::string::String;
    use std::time::Duration;
    use std::vec;
    use tokio::time::{sleep, timeout, Instant};
    use uuid::Uuid;

    /// Host binding failures.
    #[derive(Debug)]
    pub enum BtleplugError {
        /// OS/platform Bluetooth operation failed.
        Platform(btleplug::Error),
        /// No Bluetooth adapter is available.
        NoAdapter,
        /// Scan timed out without a matching service/name.
        NotFound,
        /// Required KISS characteristic or property is absent.
        MissingCharacteristic,
        /// Notification exceeded the fixed transport bound.
        NotificationTooLarge,
        /// Notification stream ended or timed out.
        NotificationClosed,
    }

    impl core::fmt::Display for BtleplugError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Platform(err) => write!(f, "{err}"),
                Self::NoAdapter => f.write_str("no Bluetooth adapter"),
                Self::NotFound => f.write_str("KISS BLE peripheral not found"),
                Self::MissingCharacteristic => f.write_str("KISS GATT characteristic missing"),
                Self::NotificationTooLarge => f.write_str("BLE notification exceeds bound"),
                Self::NotificationClosed => f.write_str("BLE notification stream closed"),
            }
        }
    }

    impl From<btleplug::Error> for BtleplugError {
        fn from(value: btleplug::Error) -> Self {
            Self::Platform(value)
        }
    }

    /// Host discovery and notification timing.
    #[derive(Debug, Clone)]
    pub struct BtleplugConfig {
        /// Optional exact advertised local name.
        pub local_name: Option<String>,
        /// Overall discovery timeout.
        pub scan_timeout: Duration,
        /// Poll interval while scanning.
        pub scan_interval: Duration,
        /// Maximum wait for the next notification.
        pub notification_timeout: Duration,
    }

    impl Default for BtleplugConfig {
        fn default() -> Self {
            Self {
                local_name: None,
                scan_timeout: Duration::from_secs(10),
                scan_interval: Duration::from_millis(100),
                notification_timeout: Duration::from_secs(30),
            }
        }
    }

    /// `btleplug` central backend for the KISS BLE service.
    pub struct BtleplugBackend {
        adapter: Adapter,
        config: BtleplugConfig,
        peripheral: Option<Peripheral>,
        tx: Option<btleplug::api::Characteristic>,
        rx: Option<btleplug::api::Characteristic>,
    }

    impl BtleplugBackend {
        /// Create a backend from the first OS Bluetooth adapter.
        pub async fn new(config: BtleplugConfig) -> Result<Self, BtleplugError> {
            let manager = Manager::new().await?;
            let adapter = manager
                .adapters()
                .await?
                .into_iter()
                .next()
                .ok_or(BtleplugError::NoAdapter)?;
            Ok(Self {
                adapter,
                config,
                peripheral: None,
                tx: None,
                rx: None,
            })
        }

        async fn find_peripheral(&self) -> Result<Peripheral, BtleplugError> {
            let service = Uuid::parse_str(SERVICE_UUID).expect("constant UUID");
            self.adapter
                .start_scan(ScanFilter {
                    services: vec![service],
                })
                .await?;
            let deadline = Instant::now() + self.config.scan_timeout;
            while Instant::now() < deadline {
                for peripheral in self.adapter.peripherals().await? {
                    let properties = peripheral.properties().await?;
                    let Some(properties) = properties else {
                        continue;
                    };
                    let name_matches = self
                        .config
                        .local_name
                        .as_ref()
                        .map_or(true, |name| properties.local_name.as_ref() == Some(name));
                    if name_matches && properties.services.contains(&service) {
                        self.adapter.stop_scan().await?;
                        return Ok(peripheral);
                    }
                }
                sleep(self.config.scan_interval).await;
            }
            self.adapter.stop_scan().await?;
            Err(BtleplugError::NotFound)
        }
    }

    impl BleGattBackend for BtleplugBackend {
        type Error = BtleplugError;

        async fn connect(&mut self) -> Result<(), Self::Error> {
            if self.peripheral.is_some() {
                return Ok(());
            }
            let peripheral = self.find_peripheral().await?;
            if !peripheral.is_connected().await? {
                peripheral.connect().await?;
            }
            if let Err(err) = peripheral.discover_services().await {
                let _ = peripheral.disconnect().await;
                return Err(err.into());
            }
            let tx_uuid = Uuid::parse_str(TX_CHAR_UUID).expect("constant UUID");
            let rx_uuid = Uuid::parse_str(RX_CHAR_UUID).expect("constant UUID");
            let tx = peripheral.characteristics().into_iter().find(|ch| {
                ch.uuid == tx_uuid
                    && ch
                        .properties
                        .intersects(CharPropFlags::WRITE | CharPropFlags::WRITE_WITHOUT_RESPONSE)
            });
            let rx = peripheral
                .characteristics()
                .into_iter()
                .find(|ch| ch.uuid == rx_uuid && ch.properties.contains(CharPropFlags::NOTIFY));
            let (Some(tx), Some(rx)) = (tx, rx) else {
                let _ = peripheral.disconnect().await;
                return Err(BtleplugError::MissingCharacteristic);
            };
            if let Err(err) = peripheral.subscribe(&rx).await {
                let _ = peripheral.disconnect().await;
                return Err(err.into());
            }
            self.tx = Some(tx);
            self.rx = Some(rx);
            self.peripheral = Some(peripheral);
            Ok(())
        }

        async fn write_tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            if data.len() > MAX_BLE_FRAME {
                return Err(BtleplugError::NotificationTooLarge);
            }
            let peripheral = self.peripheral.as_ref().ok_or(BtleplugError::NotFound)?;
            let tx = self
                .tx
                .as_ref()
                .ok_or(BtleplugError::MissingCharacteristic)?;
            peripheral
                .write(tx, data, WriteType::WithoutResponse)
                .await?;
            Ok(())
        }

        async fn next_rx(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
            let peripheral = self.peripheral.as_ref().ok_or(BtleplugError::NotFound)?;
            let rx = self
                .rx
                .as_ref()
                .ok_or(BtleplugError::MissingCharacteristic)?;
            let mut notifications = peripheral.notifications().await?;
            loop {
                let notification = timeout(self.config.notification_timeout, notifications.next())
                    .await
                    .map_err(|_| BtleplugError::NotificationClosed)?
                    .ok_or(BtleplugError::NotificationClosed)?;
                if notification.uuid != rx.uuid {
                    continue;
                }
                if notification.value.len() > out.len() || notification.value.len() > MAX_BLE_FRAME
                {
                    return Err(BtleplugError::NotificationTooLarge);
                }
                out[..notification.value.len()].copy_from_slice(&notification.value);
                return Ok(notification.value.len());
            }
        }

        async fn disconnect(&mut self) -> Result<(), Self::Error> {
            self.tx = None;
            self.rx = None;
            if let Some(peripheral) = self.peripheral.take() {
                if peripheral.is_connected().await? {
                    peripheral.disconnect().await?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockError {
        Connect,
        Disconnect,
    }

    #[derive(Default)]
    struct MockBackend {
        connected: bool,
        fail_connect: bool,
        fail_disconnect: bool,
        writes: Vec<Vec<u8>>,
        notification: Vec<u8>,
    }

    impl BleGattBackend for MockBackend {
        type Error = MockError;

        async fn connect(&mut self) -> Result<(), Self::Error> {
            if self.fail_connect {
                return Err(MockError::Connect);
            }
            self.connected = true;
            Ok(())
        }

        async fn write_tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.writes.push(data.to_vec());
            Ok(())
        }

        async fn next_rx(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
            let len = self.notification.len();
            let copied = core::cmp::min(len, out.len());
            out[..copied].copy_from_slice(&self.notification[..copied]);
            Ok(len)
        }

        async fn disconnect(&mut self) -> Result<(), Self::Error> {
            self.connected = false;
            if self.fail_disconnect {
                return Err(MockError::Disconnect);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn lifecycle_write_receive_disconnect() {
        let backend = MockBackend {
            notification: vec![0xc0, 0x00, b'o', b'k', 0xc0],
            ..MockBackend::default()
        };
        let mut link = BleTncLink::new(backend);
        assert_eq!(link.state(), BleLinkState::Disconnected);
        link.connect().await.unwrap();
        assert_eq!(link.state(), BleLinkState::Connected);
        link.write(&[0xc0, 0x00, 0xc0]).await.unwrap();
        let mut out = [0u8; 16];
        let len = link.receive(&mut out).await.unwrap();
        assert_eq!(&out[..len], &[0xc0, 0x00, b'o', b'k', 0xc0]);
        link.disconnect().await.unwrap();
        assert_eq!(link.state(), BleLinkState::Disconnected);
    }

    #[tokio::test]
    async fn rejects_invalid_state_and_bounds_without_backend_io() {
        let mut link = BleTncLink::new(MockBackend::default());
        assert_eq!(link.write(&[1]).await, Err(BleLinkError::InvalidState));
        link.connect().await.unwrap();
        assert_eq!(link.connect().await, Err(BleLinkError::InvalidState));
        assert_eq!(link.write(&[]).await, Err(BleLinkError::EmptyFrame));
        assert_eq!(
            link.write(&[0u8; MAX_BLE_FRAME + 1]).await,
            Err(BleLinkError::FrameTooLarge)
        );
        assert!(link.backend().writes.is_empty());
    }

    #[tokio::test]
    async fn failure_is_atomic_and_disconnect_clears_state() {
        let mut connect_failure = BleTncLink::new(MockBackend {
            fail_connect: true,
            ..MockBackend::default()
        });
        assert_eq!(
            connect_failure.connect().await,
            Err(BleLinkError::Backend(MockError::Connect))
        );
        assert_eq!(connect_failure.state(), BleLinkState::Disconnected);

        let mut disconnect_failure = BleTncLink::new(MockBackend {
            fail_disconnect: true,
            ..MockBackend::default()
        });
        disconnect_failure.connect().await.unwrap();
        assert_eq!(
            disconnect_failure.disconnect().await,
            Err(BleLinkError::Backend(MockError::Disconnect))
        );
        assert_eq!(disconnect_failure.state(), BleLinkState::Disconnected);
    }

    #[tokio::test]
    async fn rejects_backend_length_overrun() {
        let mut link = BleTncLink::new(MockBackend {
            notification: vec![0u8; 32],
            ..MockBackend::default()
        });
        link.connect().await.unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            link.receive(&mut out).await,
            Err(BleLinkError::InvalidLength)
        );
    }
}

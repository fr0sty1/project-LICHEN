//! Interface variant for STM32WL SubGHz radio.
//!
//! Provides the lora-phy InterfaceVariant implementation for the STM32WL's
//! integrated SX1262-compatible SubGHz radio.

use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::interrupt;
use embassy_stm32::interrupt::typelevel::Binding;
use embassy_stm32::interrupt::InterruptExt;
use embassy_stm32::Peri;
use embassy_sync::signal::Signal;
use embedded_hal_async::delay::DelayNs;
use embedded_hal_async::spi::{Operation, SpiDevice};
use lora_phy::mod_params::RadioError;
use lora_phy::mod_traits::InterfaceVariant;

/// Static signal for IRQ completion.
static IRQ_SIGNAL: Signal<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, ()> =
    Signal::new();

/// Interrupt handler for SUBGHZ_RADIO.
///
/// Disables the interrupt and signals completion.
pub struct InterruptHandler;

impl interrupt::typelevel::Handler<interrupt::typelevel::SUBGHZ_RADIO> for InterruptHandler {
    unsafe fn on_interrupt() {
        interrupt::SUBGHZ_RADIO.disable();
        IRQ_SIGNAL.signal(());
    }
}

/// RF switch mode for STM32WL boards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfSwitchMode {
    /// High-power PA (PA_BOOST, typically +22dBm max).
    HighPower,
    /// Low-power PA (typically +14dBm max).
    LowPower,
}

/// Interface variant for STM32WL SubGHz radio.
///
/// Handles RF switch control, busy polling, and interrupt handling.
/// Uses raw GPIO control for RF switch to avoid complex pin type wrangling.
pub struct Stm32wlInterfaceVariant<'d, RX: embassy_stm32::gpio::Pin, TX: embassy_stm32::gpio::Pin> {
    rf_switch_rx: Option<Output<'d>>,
    rf_switch_tx: Option<Output<'d>>,
    #[allow(dead_code)]
    rf_switch_mode: RfSwitchMode,
    _rx: core::marker::PhantomData<RX>,
    _tx: core::marker::PhantomData<TX>,
}

impl<'d, RX: embassy_stm32::gpio::Pin, TX: embassy_stm32::gpio::Pin>
    Stm32wlInterfaceVariant<'d, RX, TX>
{
    /// Create a new interface variant.
    ///
    /// The binding parameter ensures interrupt handler is properly registered.
    /// RF switch pins control the antenna switch for TX/RX.
    ///
    /// For Nucleo-WL55JC1:
    /// - RF switch RX: PC3
    /// - RF switch TX: PC4
    pub fn new(
        _irq: impl Binding<interrupt::typelevel::SUBGHZ_RADIO, InterruptHandler>,
        rf_switch_rx: Option<Peri<'d, RX>>,
        rf_switch_tx: Option<Peri<'d, TX>>,
        rf_switch_mode: RfSwitchMode,
    ) -> Self {
        // Clear any pending interrupt
        interrupt::SUBGHZ_RADIO.disable();

        Self {
            rf_switch_rx: rf_switch_rx.map(|p| Output::new(p, Level::Low, Speed::Low)),
            rf_switch_tx: rf_switch_tx.map(|p| Output::new(p, Level::Low, Speed::Low)),
            rf_switch_mode,
            _rx: core::marker::PhantomData,
            _tx: core::marker::PhantomData,
        }
    }
}

impl<RX: embassy_stm32::gpio::Pin, TX: embassy_stm32::gpio::Pin> InterfaceVariant
    for Stm32wlInterfaceVariant<'_, RX, TX>
{
    async fn reset(&mut self, _delay: &mut impl DelayNs) -> Result<(), RadioError> {
        // STM32WL reset is done via RCC, not a GPIO pin.
        // We need to access the RCC CSR register to toggle RF reset.
        // Since PAC is private in embassy-stm32 0.6, we use raw register access.

        // RCC CSR register address (from STM32WL reference manual)
        const RCC_CSR: *mut u32 = 0x5800_0094 as *mut u32;
        const RFRST_BIT: u32 = 1 << 15; // RFRST is bit 15

        unsafe {
            // Set RFRST bit
            let val = core::ptr::read_volatile(RCC_CSR);
            core::ptr::write_volatile(RCC_CSR, val | RFRST_BIT);

            // Clear RFRST bit
            let val = core::ptr::read_volatile(RCC_CSR);
            core::ptr::write_volatile(RCC_CSR, val & !RFRST_BIT);
        }

        Ok(())
    }

    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        // Poll the radio busy status in the PWR peripheral.
        // PWR SR2 register, RFBUSYS bit (bit 1)
        const PWR_SR2: *const u32 = 0x5800_0414 as *const u32;
        const RFBUSYS_BIT: u32 = 1 << 1;

        // Wait until RFBUSYS is cleared, yielding to async executor
        while unsafe { core::ptr::read_volatile(PWR_SR2) } & RFBUSYS_BIT != 0 {
            embassy_time::Timer::after_micros(10).await;
        }

        Ok(())
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        // Clear any pending IRQ signal
        IRQ_SIGNAL.reset();

        // Enable the SUBGHZ_RADIO interrupt
        unsafe {
            interrupt::SUBGHZ_RADIO.enable();
        }

        // Wait for the interrupt handler to signal completion
        IRQ_SIGNAL.wait().await;

        Ok(())
    }

    async fn enable_rf_switch_rx(&mut self) -> Result<(), RadioError> {
        // Disable TX path first
        if let Some(ref mut tx) = self.rf_switch_tx {
            tx.set_low();
        }
        // Enable RX path
        if let Some(ref mut rx) = self.rf_switch_rx {
            rx.set_high();
        }
        Ok(())
    }

    async fn enable_rf_switch_tx(&mut self) -> Result<(), RadioError> {
        // Disable RX path first
        if let Some(ref mut rx) = self.rf_switch_rx {
            rx.set_low();
        }
        // Enable TX path
        if let Some(ref mut tx) = self.rf_switch_tx {
            tx.set_high();
        }
        Ok(())
    }

    async fn disable_rf_switch(&mut self) -> Result<(), RadioError> {
        if let Some(ref mut rx) = self.rf_switch_rx {
            rx.set_low();
        }
        if let Some(ref mut tx) = self.rf_switch_tx {
            tx.set_low();
        }
        Ok(())
    }
}

/// SPI device wrapper for STM32WL SubGHz.
///
/// Manages NSS via the PWR.SUBGHZSPICR register rather than a GPIO pin.
/// Implements the async SpiDevice trait required by lora-phy.
///
/// This wrapper works with any Spi type that implements the SpiBus trait.
pub struct SubghzSpiDevice<SPI> {
    spi: SPI,
}

impl<SPI> SubghzSpiDevice<SPI> {
    /// Create a new SubGHz SPI device.
    ///
    /// The SPI must be created with `Spi::new_subghz()`.
    pub fn new(spi: SPI) -> Self {
        Self { spi }
    }

    /// Assert NSS (chip select) via PWR register.
    fn nss_low(&self) {
        // PWR SUBGHZSPICR register address
        const PWR_SUBGHZSPICR: *mut u32 = 0x5800_0090 as *mut u32;
        const NSS_BIT: u32 = 1 << 15; // NSS is bit 15

        unsafe {
            let val = core::ptr::read_volatile(PWR_SUBGHZSPICR);
            core::ptr::write_volatile(PWR_SUBGHZSPICR, val & !NSS_BIT);
        }
    }

    /// Deassert NSS via PWR register.
    fn nss_high(&self) {
        const PWR_SUBGHZSPICR: *mut u32 = 0x5800_0090 as *mut u32;
        const NSS_BIT: u32 = 1 << 15;

        unsafe {
            let val = core::ptr::read_volatile(PWR_SUBGHZSPICR);
            core::ptr::write_volatile(PWR_SUBGHZSPICR, val | NSS_BIT);
        }
    }
}

impl<SPI: embedded_hal::spi::ErrorType> embedded_hal::spi::ErrorType for SubghzSpiDevice<SPI> {
    type Error = SPI::Error;
}

impl<SPI: embedded_hal_async::spi::SpiBus<u8>> SpiDevice for SubghzSpiDevice<SPI> {
    async fn transaction(
        &mut self,
        operations: &mut [Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        self.nss_low();

        let result = async {
            for op in operations {
                match op {
                    Operation::Read(buf) => {
                        self.spi.read(buf).await?;
                    }
                    Operation::Write(data) => {
                        self.spi.write(data).await?;
                    }
                    Operation::Transfer(read, write) => {
                        self.spi.transfer(read, write).await?;
                    }
                    Operation::TransferInPlace(buf) => {
                        self.spi.transfer_in_place(buf).await?;
                    }
                    Operation::DelayNs(ns) => {
                        // Use embassy_time for async delay
                        embassy_time::Timer::after_nanos(*ns as u64).await;
                    }
                }
            }
            Ok(())
        }
        .await;

        self.nss_high();
        result
    }
}

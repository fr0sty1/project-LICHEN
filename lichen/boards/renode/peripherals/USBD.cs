// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// nRF52840 USBD peripheral model for Renode. Implements registers, tasks,
// events, EVENTCAUSE (with READY bit to unblock polling), and interrupts
// exercised by Zephyr's nrf_usbd_common + usb_dc_nrfx / udc_nrf drivers.
// Simulates a permanently attached, powered USB device (no real host in Renode).
// Per trace from project-LICHEN-5ix1.4.5: covers PRE_KERNEL_1 init, ENABLE,
// EVENTCAUSE polling in usbd_enable(), USBEVENT handler for SUSPEND/RESUME/READY,
// EP0, INTEN, and basic DMA/EP status. IRQ wired to NVIC 39.
//
// This allows full LICHEN_NATIVE + USBD_CDC_ACM + MCUmgr in Renode builds
// for gateway/puck/bridge without firmware bypasses. BLE already wired by oqv7.2.
//
// Minimal viable for boot to main:ready + CoAP; full EP DMA/ISO left for future.
using System;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class NRF52840_USBD : IDoubleWordPeripheral, IKnownSize
    {
        public NRF52840_USBD(IMachine machine)
        {
            this.machine = machine;
            IRQ = new GPIO();
            Reset();
        }

        public long Size => 0x1000;

        public GPIO IRQ { get; }

        public void Reset()
        {
            eventCause = (1u << 11); // READY bit set to unblock usbd_enable() polling
            enable = 0;
            inten = 0;
            usbaddr = 0;
            eventsUsbReset = 0;
            eventsUsbevent = 0;
            eventsEp0Setup = 0;
            epDataStatus = 0;
            this.Log(LogLevel.Info, "NRF52840_USBD reset - simulating VBUS+READY state for Renode");
            UpdateInterrupt();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch (offset)
            {
                case 0x400: // EVENTCAUSE
                    this.Log(LogLevel.Debug, "EVENTCAUSE read: 0x{0:X8} (READY=1)", eventCause);
                    return eventCause;
                case 0x500: // ENABLE
                    return enable;
                case 0x700: // INTEN
                    return inten;
                case 0x800: // USBADDR
                    return usbaddr;
                case 0x804: // BMREQUESTTYPE (part of SETUP)
                    return 0; // simulate no pending setup or default
                case 0x100: // EVENTS_USBRESET example
                    return eventsUsbReset;
                case 0x104: // EVENTS_USBEVENT
                    return eventsUsbevent;
                case 0x108: // EVENTS_EP0SETUP
                    return eventsEp0Setup;
                case 0x404: // EPDATASTATUS (simplified)
                    return epDataStatus;
                default:
                    if (offset >= 0x100 && offset < 0x200)
                    {
                        this.Log(LogLevel.Debug, "EVENTS read at 0x{0:X}", offset);
                        return 0;
                    }
                    this.Log(LogLevel.Debug, "USBD unhandled read at 0x{0:X}", offset);
                    return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch (offset)
            {
                case 0x500: // ENABLE
                    enable = value;
                    if ((value & 1) != 0)
                    {
                        eventCause |= (1u << 11); // ensure READY
                        eventsUsbevent = 1;
                        this.Log(LogLevel.Info, "USBD ENABLE=1, READY set, simulating USBEVENT");
                        UpdateInterrupt();
                    }
                    break;
                case 0x400: // EVENTCAUSE - write to clear
                    eventCause &= ~value;
                    this.Log(LogLevel.Debug, "EVENTCAUSE cleared with 0x{0:X8}, remaining 0x{1:X8}", value, eventCause);
                    break;
                case 0x700: // INTENSET / INTENCLR logic simplified
                    inten |= value; // treat as set for simplicity
                    this.Log(LogLevel.Debug, "INTEN updated to 0x{0:X8}", inten);
                    UpdateInterrupt();
                    break;
                case 0x708: // INTENCLR
                    inten &= ~value;
                    UpdateInterrupt();
                    break;
                case 0x104: // clear USBEVENT
                    eventsUsbevent = 0;
                    break;
                case 0x108:
                    eventsEp0Setup = 0;
                    break;
                default:
                    this.Log(LogLevel.Debug, "USBD write 0x{0:X8} to 0x{1:X}", value, offset);
                    if ((offset & 0xF00) == 0x500) // tasks
                    {
                        // simulate task completion by setting related event
                        if (offset == 0x14) // e.g. TASKS_STARTEPOUT or similar
                        {
                            epDataStatus |= 1;
                            UpdateInterrupt();
                        }
                    }
                    break;
            }
        }

        private void UpdateInterrupt()
        {
            // Trigger interrupt if USBEVENT or other enabled events pending
            bool pending = (eventsUsbevent != 0 || eventsEp0Setup != 0) && (inten != 0);
            IRQ.Set(pending);
            if (pending)
            {
                this.Log(LogLevel.Debug, "USBD IRQ asserted");
            }
        }

        private uint eventCause;
        private uint enable;
        private uint inten;
        private uint usbaddr;
        private uint eventsUsbReset;
        private uint eventsUsbevent;
        private uint eventsEp0Setup;
        private uint epDataStatus;
        private readonly IMachine machine;
    }
}

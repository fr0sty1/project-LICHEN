// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// NRF52840_BLE (RADIO) peripheral for Renode on nRF52840 Meshtastic boards (T-Echo, RAK4631).
// Supports LICHEN BLE LCI (legacy NUS + CoAP/SLIP) and Meshtastic-compatible GATT.
// Follows USBD.cs pattern: minimal registers/tasks/events/interrupts exercised by Zephyr
// BT controller + custom GATT MMIO stub at 0x800 for KISS/LCI testing without real radio.
// Base @0x40001000, IRQ->nvic@1. No dead code. West build + Renode validation required.
// SetConnected() for test harness to simulate LCI peer. See bead project-LICHEN-r7h4.11.

using System;
using System.Collections.Generic;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class NRF52840_BLE : IDoubleWordPeripheral, IBytePeripheral, IKnownSize, IGPIOSender
    {
        public NRF52840_BLE(IMachine machine)
        {
            this.machine = machine;
            gattValue = new byte[256];
            configurableReads = new Dictionary<uint, uint>();
            Reset();
            IRQ = new GPIO();
        }

        public long Size => 0xA00;

        public GPIO IRQ { get; }

        // Allow test harness to set configurable read values
        public void SetReadValue(uint offset, uint value)
        {
            configurableReads[offset] = value;
            this.Log(LogLevel.Debug, "Configured read value at 0x{0:X}: 0x{1:X8}", offset, value);
        }

        // Simulate connection state change
        public void SetConnected(bool connected)
        {
            gattStatus = connected ? 1u : 0u;
            this.Log(LogLevel.Info, "BLE connection state: {0}", connected ? "connected" : "disconnected");
        }

        public void Reset()
        {
            // Radio registers
            eventsReady = 0;
            eventsAddress = 0;
            eventsPayload = 0;
            eventsEnd = 0;
            eventsDisabled = 0;
            shorts = 0;
            intenset = 0;
            packetPtr = 0;
            frequency = 0;
            txPower = 0;
            mode = 0;
            pcnf0 = 0;
            pcnf1 = 0;
            prefix0 = 0;
            prefix1 = 0;
            txAddress = 0;
            rxAddresses = 0;
            crcCnf = 0;
            crcPoly = 0;
            crcInit = 0;
            tifs = 0;
            dataWhiteIv = 0;
            bcc = 0;
            for (int i = 0; i < 8; i++)
            {
                dab[i] = 0;
                dap[i] = 0;
            }
            dacnf = 0;
            modeCnf0 = 0;
            sfd = 0;
            edcnt = 0;
            ccactrl = 0;
            power = 1;

            // GATT stub
            gattStatus = 0;
            gattHandle = 0;
            gattValueLen = 0;
            gattResult = 0;
            Array.Clear(gattValue, 0, gattValue.Length);

            // Clear configurable reads on reset
            configurableReads.Clear();
        }

        public uint ReadDoubleWord(long offset)
        {
            // Check for configurable overrides first
            if (configurableReads.TryGetValue((uint)offset, out uint configValue))
            {
                return configValue;
            }

            switch (offset)
            {
                // Events (read/clear)
                case 0x100: return eventsReady;
                case 0x104: return eventsAddress;
                case 0x108: return eventsPayload;
                case 0x10C: return eventsEnd;
                case 0x110: return eventsDisabled;

                // Config registers
                case 0x200: return shorts;
                case 0x304: return intenset;
                case 0x308: return intenset;  // INTENCLR reads as INTENSET

                // Status registers
                case 0x400: return 1;  // CRCSTATUS - always OK
                case 0x408: return 0;  // RXMATCH
                case 0x40C: return 0;  // RXCRC

                // Config registers
                case 0x504: return packetPtr;
                case 0x508: return frequency;
                case 0x510: return txPower;
                case 0x514: return mode;
                case 0x518: return pcnf0;
                case 0x51C: return pcnf1;
                case 0x524: return prefix0;
                case 0x528: return prefix1;
                case 0x52C: return txAddress;
                case 0x530: return rxAddresses;
                case 0x534: return crcCnf;
                case 0x538: return crcPoly;
                case 0x53C: return crcInit;
                case 0x544: return tifs;
                case 0x550: return dataWhiteIv;
                case 0x560: return bcc;
                case 0x640: return dacnf;
                case 0x650: return modeCnf0;
                case 0x660: return sfd;
                case 0x664: return edcnt;
                case 0x668: return 0;  // EDSAMPLE - no energy detected
                case 0x66C: return ccactrl;
                case 0xFFC: return power;

                // GATT stub
                case 0x800: return gattStatus;
                case 0x804: return gattHandle;
                case 0x808: return gattValueLen;
                case 0x810: return gattResult;

                default:
                    // DAB registers (0x600-0x61C)
                    if (offset >= 0x600 && offset < 0x620)
                    {
                        int idx = (int)((offset - 0x600) / 4);
                        return dab[idx];
                    }
                    // DAP registers (0x620-0x63C)
                    if (offset >= 0x620 && offset < 0x640)
                    {
                        int idx = (int)((offset - 0x620) / 4);
                        return dap[idx];
                    }
                    // GATT value buffer
                    if (offset >= 0x900 && offset < 0xA00)
                    {
                        return ReadGattValueWord(offset - 0x900);
                    }

                    this.Log(LogLevel.Debug, "Read from unhandled offset 0x{0:X}", offset);
                    return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch (offset)
            {
                // Tasks
                case 0x000:
                    this.Log(LogLevel.Debug, "TASKS_TXEN triggered");
                    eventsReady = 1;
                    UpdateInterrupt();
                    break;
                case 0x004:
                    this.Log(LogLevel.Debug, "TASKS_RXEN triggered");
                    eventsReady = 1;
                    UpdateInterrupt();
                    break;
                case 0x008:
                    this.Log(LogLevel.Debug, "TASKS_START triggered");
                    break;
                case 0x00C:
                    this.Log(LogLevel.Debug, "TASKS_STOP triggered");
                    eventsEnd = 1;
                    UpdateInterrupt();
                    break;
                case 0x010:
                    this.Log(LogLevel.Debug, "TASKS_DISABLE triggered");
                    eventsDisabled = 1;
                    UpdateInterrupt();
                    break;

                // Events (write to clear)
                case 0x100: eventsReady = value; break;
                case 0x104: eventsAddress = value; break;
                case 0x108: eventsPayload = value; break;
                case 0x10C: eventsEnd = value; break;
                case 0x110: eventsDisabled = value; break;

                // Config registers
                case 0x200: shorts = value; break;
                case 0x304:
                    intenset |= value;
                    UpdateInterrupt();
                    break;
                case 0x308:
                    intenset &= ~value;
                    UpdateInterrupt();
                    break;

                case 0x504: packetPtr = value; break;
                case 0x508:
                    frequency = value;
                    this.Log(LogLevel.Debug, "Frequency set to {0} MHz", 2400 + (value & 0x7F));
                    break;
                case 0x510:
                    txPower = value;
                    this.Log(LogLevel.Debug, "TX power set to 0x{0:X}", value);
                    break;
                case 0x514:
                    mode = value;
                    LogMode(value);
                    break;
                case 0x518: pcnf0 = value; break;
                case 0x51C: pcnf1 = value; break;
                case 0x524: prefix0 = value; break;
                case 0x528: prefix1 = value; break;
                case 0x52C: txAddress = value; break;
                case 0x530: rxAddresses = value; break;
                case 0x534: crcCnf = value; break;
                case 0x538: crcPoly = value; break;
                case 0x53C: crcInit = value; break;
                case 0x544: tifs = value; break;
                case 0x550: dataWhiteIv = value; break;
                case 0x560: bcc = value; break;
                case 0x640: dacnf = value; break;
                case 0x650: modeCnf0 = value; break;
                case 0x660: sfd = value; break;
                case 0x664: edcnt = value; break;
                case 0x66C: ccactrl = value; break;
                case 0xFFC:
                    power = value;
                    this.Log(LogLevel.Debug, "Power {0}", value != 0 ? "ON" : "OFF");
                    break;

                // GATT stub
                case 0x804:
                    gattHandle = value;
                    this.Log(LogLevel.Debug, "GATT handle set to 0x{0:X}", value);
                    break;
                case 0x808:
                    gattValueLen = value;
                    break;
                case 0x80C:
                    HandleGattOperation(value);
                    break;

                default:
                    // DAB registers (0x600-0x61C)
                    if (offset >= 0x600 && offset < 0x620)
                    {
                        int idx = (int)((offset - 0x600) / 4);
                        dab[idx] = value;
                        return;
                    }
                    // DAP registers (0x620-0x63C)
                    if (offset >= 0x620 && offset < 0x640)
                    {
                        int idx = (int)((offset - 0x620) / 4);
                        dap[idx] = value;
                        return;
                    }
                    // GATT value buffer
                    if (offset >= 0x900 && offset < 0xA00)
                    {
                        WriteGattValueWord(offset - 0x900, value);
                        return;
                    }

                    this.Log(LogLevel.Debug, "Write 0x{0:X8} to unhandled offset 0x{1:X}", value, offset);
                    break;
            }
        }

        public byte ReadByte(long offset)
        {
            // GATT value buffer - byte access
            if (offset >= 0x900 && offset < 0xA00)
            {
                return gattValue[offset - 0x900];
            }

            // For other registers, extract byte from word
            return (byte)(ReadDoubleWord(offset & ~3L) >> (int)((offset & 3) * 8));
        }

        public void WriteByte(long offset, byte value)
        {
            // GATT value buffer - byte access
            if (offset >= 0x900 && offset < 0xA00)
            {
                gattValue[offset - 0x900] = value;
                return;
            }

            // For simplicity, promote to word write
            WriteDoubleWord(offset & ~3L, value);
        }

        private void HandleGattOperation(uint operation)
        {
            switch (operation)
            {
                case 1: // Read
                    this.Log(LogLevel.Info, "GATT READ: handle=0x{0:X}, len={1}", gattHandle, gattValueLen);
                    LogGattValue("Read value");
                    gattResult = 0; // Success
                    break;
                case 2: // Write
                    this.Log(LogLevel.Info, "GATT WRITE: handle=0x{0:X}, len={1}", gattHandle, gattValueLen);
                    LogGattValue("Written value");
                    gattResult = 0; // Success
                    break;
                case 3: // Notify
                    this.Log(LogLevel.Info, "GATT NOTIFY: handle=0x{0:X}, len={1}", gattHandle, gattValueLen);
                    LogGattValue("Notify value");
                    gattResult = gattStatus == 1 ? 0u : 1u; // Fail if not connected
                    break;
                default:
                    this.Log(LogLevel.Warning, "Unknown GATT operation: {0}", operation);
                    gattResult = 2; // Invalid operation
                    break;
            }
        }

        private void LogGattValue(string prefix)
        {
            if (gattValueLen == 0 || gattValueLen > 256)
                return;

            var hex = new System.Text.StringBuilder();
            for (int i = 0; i < Math.Min(gattValueLen, 32u); i++)
            {
                hex.AppendFormat("{0:X2} ", gattValue[i]);
            }
            if (gattValueLen > 32)
            {
                hex.Append("...");
            }
            this.Log(LogLevel.Debug, "{0}: {1}", prefix, hex.ToString().TrimEnd());
        }

        private void LogMode(uint modeValue)
        {
            string modeName = modeValue switch
            {
                0 => "NRF_1MBIT",
                1 => "NRF_2MBIT",
                2 => "NRF_250KBIT",
                3 => "BLE_1MBIT",
                4 => "BLE_2MBIT",
                5 => "BLE_LR125KBIT",
                6 => "BLE_LR500KBIT",
                15 => "IEEE802154_250KBIT",
                _ => $"UNKNOWN({modeValue})"
            };
            this.Log(LogLevel.Debug, "Mode set to {0}", modeName);
        }

        private void UpdateInterrupt()
        {
            bool irqActive = false;

            // Check if any enabled interrupt has a pending event
            if ((intenset & 0x01) != 0 && eventsReady != 0) irqActive = true;
            if ((intenset & 0x02) != 0 && eventsAddress != 0) irqActive = true;
            if ((intenset & 0x04) != 0 && eventsPayload != 0) irqActive = true;
            if ((intenset & 0x08) != 0 && eventsEnd != 0) irqActive = true;
            if ((intenset & 0x10) != 0 && eventsDisabled != 0) irqActive = true;

            IRQ.Set(irqActive);
        }

        private uint ReadGattValueWord(long offset)
        {
            if (offset + 4 > gattValue.Length) return 0;
            return (uint)(gattValue[offset] |
                         (gattValue[offset + 1] << 8) |
                         (gattValue[offset + 2] << 16) |
                         (gattValue[offset + 3] << 24));
        }

        private void WriteGattValueWord(long offset, uint value)
        {
            if (offset + 4 > gattValue.Length) return;
            gattValue[offset] = (byte)(value & 0xFF);
            gattValue[offset + 1] = (byte)((value >> 8) & 0xFF);
            gattValue[offset + 2] = (byte)((value >> 16) & 0xFF);
            gattValue[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private readonly IMachine machine;
        private readonly byte[] gattValue;
        private readonly Dictionary<uint, uint> configurableReads;

        // Radio registers
        private uint eventsReady;
        private uint eventsAddress;
        private uint eventsPayload;
        private uint eventsEnd;
        private uint eventsDisabled;
        private uint shorts;
        private uint intenset;
        private uint packetPtr;
        private uint frequency;
        private uint txPower;
        private uint mode;
        private uint pcnf0;
        private uint pcnf1;
        private uint prefix0;
        private uint prefix1;
        private uint txAddress;
        private uint rxAddresses;
        private uint crcCnf;
        private uint crcPoly;
        private uint crcInit;
        private uint tifs;
        private uint dataWhiteIv;
        private uint bcc;
        private uint[] dab = new uint[8];
        private uint[] dap = new uint[8];
        private uint dacnf;
        private uint modeCnf0;
        private uint sfd;
        private uint edcnt;
        private uint ccactrl;
        private uint power;

        // GATT stub
        private uint gattStatus;
        private uint gattHandle;
        private uint gattValueLen;
        private uint gattResult;
    }
}

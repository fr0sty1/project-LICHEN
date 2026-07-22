// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// LR1110 LoRa radio peripheral for Renode - magic SPI interface.
// ponytail: no real register emulation, just intercept TX/RX commands.
//
// Based on SX1262.cs but adapted for LR1110's different command structure:
// - 2-byte big-endian opcodes (vs SX1262's 1-byte)
// - DIO9 interrupt line (vs DIO1)
// - Built-in GNSS and WiFi scanning (stubbed for now)
//
// Key opcodes (2-byte big-endian):
//   0x0206 WriteBuffer(offset, data...) - write to TX buffer
//   0x020A ReadBuffer(offset) -> data... - read from RX buffer
//   0x0209 SetTx(timeout) - trigger transmit
//   0x0208 SetRx(timeout) - enter receive mode
//   0x0111 GetStatus -> status byte
//   0x0012 ClearIrq(flags)
//   0x0020 GetRxBufferStatus
//   0x0021 GetPacketStatus
//
// TODO: GNSS scanning commands (0x04xx group)
// TODO: WiFi scanning commands (0x05xx group)

using System;
using System.Net.Sockets;
using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.SPI;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class LR1110 : ISPIPeripheral, IGPIOReceiver
    {
        public LR1110(IMachine machine, string simHost = "127.0.0.1", int simPort = 5555)
        {
            this.machine = machine;
            this.simHost = simHost;
            this.simPort = simPort;
            txBuffer = new byte[256];
            rxBuffer = new byte[256];
            Reset();
        }

        public int SimPort
        {
            get => simPort;
            set
            {
                Disconnect();
                simPort = value;
                this.Log(LogLevel.Info, "SimPort set to {0}", value);
            }
        }

        // GPIO pins - DIO9 for LR1110 (vs DIO1 for SX1262)
        public GPIO DIO9 { get; } = new GPIO();
        public GPIO Busy { get; } = new GPIO();

        public void OnGPIO(int number, bool value)
        {
            // RESET pin (active low)
            if (number == 0 && !value)
            {
                this.Log(LogLevel.Debug, "Reset asserted");
                Reset();
            }
            // Chip-select (active low, GPIO-driven via cs-gpios). Renode's SPIM
            // EasyDMA controller does not call FinishTransmission between DMA
            // transfers, so the opcode state machine would never reset. Use the
            // CS deassert (rising edge) to end each SPI transaction.
            else if (number == 1 && value)
            {
                FinishTransmission();
            }
        }

        public void Reset()
        {
            state = State.Idle;
            opcode = 0;
            opcodeByteCount = 0;
            byteIndex = 0;
            bufferOffset = 0;
            txLen = 0;
            rxLen = 0;
            rxRssi = 0;
            rxSnr = 0;
            irqFlags = 0;
            rxMode = false;
            Array.Clear(txBuffer, 0, txBuffer.Length);
            Array.Clear(rxBuffer, 0, rxBuffer.Length);
            Array.Clear(rxTimeoutBytes, 0, rxTimeoutBytes.Length);
            Busy.Set(false);
            DIO9.Set(false);
        }

        public void FinishTransmission()
        {
            state = State.Idle;
            opcodeByteCount = 0;
            byteIndex = 0;
        }

        public byte Transmit(byte data)
        {
            byte result = 0;

            switch (state)
            {
                case State.Idle:
                    // LR1110 uses 2-byte big-endian opcodes
                    if (opcodeByteCount == 0)
                    {
                        opcode = (ushort)(data << 8);
                        opcodeByteCount = 1;
                    }
                    else
                    {
                        opcode |= data;
                        opcodeByteCount = 0;
                        byteIndex = 0;
                        result = HandleOpcode(opcode);
                    }
                    break;

                case State.WriteBuffer:
                    if (byteIndex == 0)
                    {
                        bufferOffset = data;
                        if (bufferOffset >= txBuffer.Length)
                        {
                            state = State.Idle;
                            break;
                        }
                        byteIndex++;
                    }
                    else
                    {
                        var idx = bufferOffset + (byteIndex - 1);
                        if (idx < txBuffer.Length && idx >= 0)
                        {
                            txBuffer[idx] = data;
                            txLen = (ushort)Math.Max(txLen, idx + 1);
                        }
                        byteIndex++;
                    }
                    break;

                case State.ReadBuffer:
                    if (byteIndex == 0)
                    {
                        bufferOffset = data;
                        if (bufferOffset >= rxBuffer.Length)
                        {
                            state = State.Idle;
                            break;
                        }
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        byteIndex++;
                    }
                    else
                    {
                        var idx = bufferOffset + (byteIndex - 2);
                        result = (idx < rxBuffer.Length && idx >= 0) ? rxBuffer[idx] : (byte)0;
                        byteIndex++;
                    }
                    break;

                case State.SetTx:
                case State.SetPacketParams:
                case State.SetModulationParams:
                case State.ClearIrq:
                case State.SetDioIrqParams:
                    // Consume parameter bytes, ignore values
                    byteIndex++;
                    break;

                case State.SetRx:
                    // Collect 3 timeout bytes (24-bit big-endian)
                    if (byteIndex < 3)
                    {
                        rxTimeoutBytes[byteIndex] = data;
                        byteIndex++;
                        if (byteIndex == 3)
                        {
                            SendRxEnter();
                        }
                    }
                    break;

                case State.GetStatus:
                    // Return status: bits [6:4]=mode, bits [3:1]=cmd_status
                    // Mode: 0x2=STDBY_RC, 0x5=RX, 0x6=TX
                    result = 0x22; // STDBY_RC, command OK
                    break;

                case State.GetIrqStatus:
                    if (byteIndex == 0)
                    {
                        result = (byte)((irqFlags >> 24) & 0xFF);
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        result = (byte)((irqFlags >> 16) & 0xFF);
                        byteIndex++;
                    }
                    else if (byteIndex == 2)
                    {
                        result = (byte)((irqFlags >> 8) & 0xFF);
                        byteIndex++;
                    }
                    else
                    {
                        result = (byte)(irqFlags & 0xFF);
                    }
                    break;

                case State.GetRxBufferStatus:
                    if (byteIndex == 0)
                    {
                        result = (byte)rxLen;
                        byteIndex++;
                    }
                    else
                    {
                        result = 0; // RX buffer start offset
                    }
                    break;

                case State.GetPacketStatus:
                    // Return RSSI, SNR for LoRa
                    if (byteIndex == 0)
                    {
                        result = (byte)((-rxRssi / 2) & 0xFF); // LR1110 RSSI format
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        result = (byte)((rxSnr / 4) & 0xFF); // LR1110 SNR format
                        byteIndex++;
                    }
                    else
                    {
                        result = 0;
                        byteIndex++;
                    }
                    break;

                // TODO: GNSS scanning - stubbed
                case State.GnssScan:
                    // Stub: consume parameters, no actual scan
                    byteIndex++;
                    break;

                // TODO: WiFi scanning - stubbed
                case State.WifiScan:
                    // Stub: consume parameters, no actual scan
                    byteIndex++;
                    break;
            }

            return result;
        }

        private byte HandleOpcode(ushort op)
        {
            switch (op)
            {
                case 0x0206: // WriteBuffer
                    state = State.WriteBuffer;
                    break;

                case 0x020A: // ReadBuffer
                    state = State.ReadBuffer;
                    break;

                case 0x0209: // SetTx
                    state = State.SetTx;
                    if (rxMode)
                    {
                        SendRxExit();
                    }
                    TriggerTx();
                    break;

                case 0x0208: // SetRx
                    state = State.SetRx;
                    // Timeout bytes collected in Transmit(), then SendRxEnter() called
                    break;

                case 0x0111: // GetStatus
                    state = State.GetStatus;
                    break;

                case 0x0012: // ClearIrq
                    state = State.ClearIrq;
                    irqFlags = 0;
                    DIO9.Set(false);
                    break;

                case 0x0020: // GetRxBufferStatus
                    state = State.GetRxBufferStatus;
                    break;

                case 0x0021: // GetPacketStatus
                    state = State.GetPacketStatus;
                    break;

                case 0x0014: // GetIrqStatus
                    state = State.GetIrqStatus;
                    break;

                // Config commands - acknowledge but ignore
                case 0x0211: // SetPacketParams
                    state = State.SetPacketParams;
                    break;

                case 0x0210: // SetModulationParams
                    state = State.SetModulationParams;
                    break;

                case 0x0213: // SetDioIrqParams
                    state = State.SetDioIrqParams;
                    break;

                case 0x0080: // SetStandby
                    if (rxMode)
                    {
                        SendRxExit();
                    }
                    state = State.Idle;
                    break;

                // TODO: GNSS commands - stubbed
                case 0x0400: // GnssSetConstellationToUse
                case 0x0401: // GnssReadConstellationToUse
                case 0x0402: // GnssSetAlmanacUpdate
                case 0x0410: // GnssScan
                    this.Log(LogLevel.Debug, "GNSS opcode 0x{0:X4} - stubbed", op);
                    state = State.GnssScan;
                    break;

                // TODO: WiFi commands - stubbed
                case 0x0500: // WifiScan
                case 0x0501: // WifiScanTimeLimit
                case 0x0502: // WifiCountryCode
                case 0x0503: // WifiGetNbResults
                case 0x0504: // WifiReadResults
                    this.Log(LogLevel.Debug, "WiFi opcode 0x{0:X4} - stubbed", op);
                    state = State.WifiScan;
                    break;

                case 0x0200: // SetSleep
                case 0x0203: // SetRfFrequency
                case 0x0204: // SetTxParams
                case 0x0205: // SetPaConfig
                case 0x0207: // SetBufferBaseAddress
                    // Single commands or we don't care about params
                    state = State.Idle;
                    break;

                default:
                    this.Log(LogLevel.Debug, "Unknown opcode: 0x{0:X4}", op);
                    state = State.Idle;
                    break;
            }

            return 0; // Status byte placeholder
        }

        private void TriggerTx()
        {
            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "TX failed: not connected to lichen-sim");
                irqFlags |= 0x0040; // TxDone with implicit error
                return;
            }

            this.Log(LogLevel.Debug, "TX: {0} bytes", txLen);
            Busy.Set(true);

            try
            {
                // Protocol: [len:4][type:1][payload_len:2][payload]
                var msgLen = 3 + txLen;
                var msg = new byte[4 + msgLen];
                WriteLE32(msg, 0, (uint)msgLen);
                msg[4] = 0x10; // MSG_TX
                WriteLE16(msg, 5, txLen);
                Array.Copy(txBuffer, 0, msg, 7, txLen);

                stream.Write(msg, 0, msg.Length);

                var resp = ReadMessage();
                if (resp != null && resp.Length >= 5 && resp[0] == 0x11)
                {
                    this.Log(LogLevel.Debug, "TX done, airtime={0}us", ReadLE32(resp, 1));
                    irqFlags |= 0x0001; // TxDone
                }
                else
                {
                    this.Log(LogLevel.Warning, "TX failed");
                }
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "TX error: {0}", e.Message);
                Disconnect();
            }

            Busy.Set(false);
            txLen = 0;
            DIO9.Set(irqFlags != 0);
        }

        private void SendRxEnter()
        {
            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "RX_ENTER failed: not connected to lichen-sim");
                return;
            }

            // Convert LR1110 24-bit timeout (big-endian, 15.625us steps) to microseconds
            uint timeoutSteps = (uint)((rxTimeoutBytes[0] << 16) | (rxTimeoutBytes[1] << 8) | rxTimeoutBytes[2]);
            uint timeoutUs;
            if (timeoutSteps == 0xFFFFFF)
            {
                // Continuous RX
                timeoutUs = 0xFFFFFFFF;
            }
            else
            {
                // 15.625us per step = 15625/1000
                timeoutUs = (uint)((timeoutSteps * 15625UL) / 1000UL);
            }

            rxMode = true;
            this.Log(LogLevel.Debug, "RX_ENTER: timeout={0}us", timeoutUs == 0xFFFFFFFF ? "continuous" : timeoutUs.ToString());

            try
            {
                // Protocol: [len:4][type:1][timeout_us:4]
                var msg = new byte[9];
                WriteLE32(msg, 0, 5); // message length
                msg[4] = 0x24; // RX_ENTER
                WriteLE32(msg, 5, timeoutUs);

                stream.Write(msg, 0, msg.Length);

                // Block waiting for RX_PACKET or RX_TIMEOUT from simulation
                WaitForRxResponse();
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "RX_ENTER error: {0}", e.Message);
                Disconnect();
                rxMode = false;
            }
        }

        private void SendRxExit()
        {
            if (stream == null)
            {
                rxMode = false;
                return;
            }

            this.Log(LogLevel.Debug, "RX_EXIT");

            try
            {
                // Protocol: [len:4][type:1] - no payload
                var msg = new byte[5];
                WriteLE32(msg, 0, 1); // message length = 1 (just the type byte)
                msg[4] = 0x26; // MSG_RX_EXIT

                stream.Write(msg, 0, msg.Length);
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "RX_EXIT error: {0}", e.Message);
                Disconnect();
            }

            rxMode = false;
        }

        private void WaitForRxResponse()
        {
            // Block until we receive RX_PACKET (0x27) or RX_TIMEOUT (0x28)
            // The simulation pushes these when a packet arrives or timeout expires
            if (stream == null)
                return;

            Busy.Set(true);

            try
            {
                // Remove receive timeout - we need to block until response
                socket.ReceiveTimeout = 0;

                var resp = ReadMessage();
                if (resp == null || resp.Length < 1)
                {
                    this.Log(LogLevel.Warning, "RX: no response from simulation");
                    rxMode = false;
                    Busy.Set(false);
                    return;
                }

                byte msgType = resp[0];

                if (msgType == 0x27) // RX_PACKET
                {
                    // Format: type(1) + payload_len(2 LE) + payload + rssi(2 LE signed) + snr(2 LE signed)
                    if (resp.Length < 5) // Minimum: type + len + rssi + snr
                    {
                        this.Log(LogLevel.Warning, "RX_PACKET: message too short");
                        rxMode = false;
                        Busy.Set(false);
                        return;
                    }

                    rxLen = ReadLE16(resp, 1);
                    int payloadEnd = 3 + rxLen;

                    if (resp.Length < payloadEnd + 4)
                    {
                        this.Log(LogLevel.Warning, "RX_PACKET: payload/metadata truncated");
                        rxMode = false;
                        Busy.Set(false);
                        return;
                    }

                    // Copy payload to RX buffer
                    Array.Copy(resp, 3, rxBuffer, 0, Math.Min(rxLen, (ushort)256));

                    // Read RSSI and SNR (signed 16-bit LE)
                    rxRssi = (short)ReadLE16(resp, payloadEnd);
                    rxSnr = (short)ReadLE16(resp, payloadEnd + 2);

                    this.Log(LogLevel.Debug, "RX_PACKET: {0} bytes, RSSI={1}, SNR={2}", rxLen, rxRssi, rxSnr);

                    irqFlags |= 0x0002; // RxDone
                }
                else if (msgType == 0x28) // RX_TIMEOUT
                {
                    this.Log(LogLevel.Debug, "RX_TIMEOUT");
                    irqFlags |= 0x0200; // Timeout
                }
                else
                {
                    this.Log(LogLevel.Warning, "RX: unexpected message type 0x{0:X2}", msgType);
                }

                rxMode = false;
                Busy.Set(false);
                DIO9.Set(irqFlags != 0);
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "WaitForRxResponse error: {0}", e.Message);
                Disconnect();
                rxMode = false;
                Busy.Set(false);
            }
            finally
            {
                // Restore receive timeout for other operations
                if (socket != null)
                    socket.ReceiveTimeout = 100;
            }
        }

        private void EnsureConnected()
        {
            if (socket != null && socket.Connected)
                return;

            try
            {
                socket?.Close();
                socket = new TcpClient();
                socket.NoDelay = true;
                socket.ReceiveTimeout = 100;
                socket.Connect(simHost, simPort);
                stream = socket.GetStream();
                this.Log(LogLevel.Info, "Connected to lichen-sim at {0}:{1}", simHost, simPort);
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "Connect failed: {0}", e.Message);
                socket = null;
                stream = null;
            }
        }

        private void Disconnect()
        {
            stream = null;
            socket?.Close();
            socket = null;
        }

        private byte[] ReadMessage()
        {
            var lenBuf = new byte[4];
            int read = 0;
            while (read < 4)
            {
                int n = stream.Read(lenBuf, read, 4 - read);
                if (n <= 0) return null;
                read += n;
            }

            int len = (int)ReadLE32(lenBuf, 0);
            if (len == 0) return new byte[0];
            if (len > 1024) return null;

            var data = new byte[len];
            read = 0;
            while (read < len)
            {
                int n = stream.Read(data, read, len - read);
                if (n <= 0) return null;
                read += n;
            }
            return data;
        }

        private static void WriteLE16(byte[] buf, int offset, ushort value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
        }

        private static void WriteLE32(byte[] buf, int offset, uint value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
            buf[offset + 2] = (byte)((value >> 16) & 0xFF);
            buf[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static ushort ReadLE16(byte[] buf, int offset)
        {
            return (ushort)(buf[offset] | (buf[offset + 1] << 8));
        }

        private static uint ReadLE32(byte[] buf, int offset)
        {
            return (uint)(buf[offset] | (buf[offset + 1] << 8) |
                         (buf[offset + 2] << 16) | (buf[offset + 3] << 24));
        }

        private enum State
        {
            Idle,
            WriteBuffer,
            ReadBuffer,
            SetTx,
            SetRx,
            GetStatus,
            GetIrqStatus,
            GetRxBufferStatus,
            GetPacketStatus,
            SetPacketParams,
            SetModulationParams,
            ClearIrq,
            SetDioIrqParams,
            // TODO: GNSS/WiFi scanning - stubbed
            GnssScan,
            WifiScan,
        }

        private readonly IMachine machine;
        private readonly string simHost;
        private int simPort;
        private readonly byte[] txBuffer;
        private readonly byte[] rxBuffer;

        private TcpClient socket;
        private NetworkStream stream;

        private State state;
        private ushort opcode;  // 2-byte opcode for LR1110 (vs 1-byte for SX1262)
        private int opcodeByteCount;  // Track how many opcode bytes received
        private int byteIndex;
        private byte bufferOffset;
        private ushort txLen;
        private ushort rxLen;
        private short rxRssi;
        private short rxSnr;
        private uint irqFlags;  // 32-bit for LR1110 (vs 16-bit for SX1262)
        private bool rxMode;
        private byte[] rxTimeoutBytes = new byte[3];
    }
}

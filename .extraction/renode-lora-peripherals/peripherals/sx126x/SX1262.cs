// SPDX-License-Identifier: Apache-2.0
//
// SX1262 LoRa radio peripheral for Renode - magic SPI interface.
//
// Intercepts SX1262 opcodes. Two modes:
//   - Loopback: TX data loops back to RX buffer (single-node testing)
//   - Bridge: TCP connection to external RF simulator (multi-node)
//
// Key opcodes:
//   0x0E WriteBuffer(offset, data...) - write to TX buffer
//   0x1E ReadBuffer(offset) -> data... - read from RX buffer
//   0x83 SetTx(timeout) - trigger transmit
//   0x82 SetRx(timeout) - enter receive mode
//   0xC0 GetStatus -> status byte
//   0x12 GetIrqStatus -> IRQ flags
//   0x02 ClearIrqStatus(flags)

using System;
using System.Net.Sockets;
using System.Threading;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.SPI;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class SX1262 : ISPIPeripheral, IGPIOReceiver
    {
        public SX1262(IMachine machine, string simHost = "127.0.0.1", int simPort = 5555, bool loopback = false)
        {
            this.machine = machine;
            this.simHost = simHost;
            this.simPort = simPort;
            this.loopbackMode = loopback;
            txBuffer = new byte[256];
            rxBuffer = new byte[256];
            Reset();
        }

        /// <summary>
        /// Enable loopback mode for single-node testing without external simulator.
        /// In loopback mode, TX data is copied to RX buffer and triggers RxDone.
        /// </summary>
        public bool Loopback
        {
            get => loopbackMode;
            set
            {
                if (value != loopbackMode)
                {
                    Disconnect();
                    loopbackMode = value;
                    this.Log(LogLevel.Info, "Mode: {0}", value ? "loopback" : "bridge");
                }
            }
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

        public string SimHost
        {
            get => simHost;
            set
            {
                Disconnect();
                simHost = value;
                this.Log(LogLevel.Info, "SimHost set to {0}", value);
            }
        }

        // GPIO pins - directly expose for DTS wiring
        public GPIO IRQ { get; } = new GPIO();
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
            IRQ.Set(false);
        }

        public void FinishTransmission()
        {
            state = State.Idle;
            byteIndex = 0;
        }

        public byte Transmit(byte data)
        {
            byte result = 0;

            switch (state)
            {
                case State.Idle:
                    opcode = data;
                    byteIndex = 0;
                    result = HandleOpcode(data);
                    break;

                case State.WriteBuffer:
                    if (byteIndex == 0)
                    {
                        bufferOffset = data;
                        byteIndex++;
                    }
                    else
                    {
                        var idx = bufferOffset + (byteIndex - 1);
                        if (idx < txBuffer.Length)
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
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        // NOP byte per SX1262 protocol
                        byteIndex++;
                    }
                    else
                    {
                        var idx = bufferOffset + (byteIndex - 2);
                        result = idx < rxBuffer.Length ? rxBuffer[idx] : (byte)0;
                        byteIndex++;
                    }
                    break;

                case State.SetTx:
                case State.SetPacketParams:
                case State.SetModulationParams:
                case State.ClearIrqStatus:
                case State.SetDioIrqParams:
                    // Consume parameter bytes, ignore values
                    byteIndex++;
                    break;

                case State.SetRx:
                    // Collect 3 timeout bytes (24-bit big-endian from SX1262)
                    if (byteIndex < 3)
                    {
                        rxTimeoutBytes[byteIndex] = data;
                        byteIndex++;
                        if (byteIndex == 3)
                        {
                            EnterRxMode();
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
                        result = (byte)((-rxRssi / 2) & 0xFF); // SX1262 RSSI format
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        result = (byte)((rxSnr / 4) & 0xFF); // SX1262 SNR format
                        byteIndex++;
                    }
                    else
                    {
                        result = 0;
                        byteIndex++;
                    }
                    break;
            }

            return result;
        }

        private byte HandleOpcode(byte op)
        {
            switch (op)
            {
                case 0x0E: // WriteBuffer
                    state = State.WriteBuffer;
                    break;

                case 0x1E: // ReadBuffer
                    state = State.ReadBuffer;
                    break;

                case 0x83: // SetTx
                    state = State.SetTx;
                    if (rxMode)
                    {
                        ExitRxMode();
                    }
                    TriggerTx();
                    break;

                case 0x82: // SetRx
                    state = State.SetRx;
                    // Timeout bytes collected in Transmit(), then EnterRxMode() called
                    break;

                case 0xC0: // GetStatus
                    state = State.GetStatus;
                    break;

                case 0x12: // GetIrqStatus
                    state = State.GetIrqStatus;
                    break;

                case 0x02: // ClearIrqStatus
                    state = State.ClearIrqStatus;
                    irqFlags = 0;
                    IRQ.Set(false);
                    break;

                case 0x13: // GetRxBufferStatus
                    state = State.GetRxBufferStatus;
                    break;

                case 0x14: // GetPacketStatus
                    state = State.GetPacketStatus;
                    break;

                // Config commands - acknowledge but ignore
                case 0x8B: // SetPacketParams
                    state = State.SetPacketParams;
                    break;

                case 0x8A: // SetModulationParams
                    state = State.SetModulationParams;
                    break;

                case 0x08: // SetDioIrqParams
                    state = State.SetDioIrqParams;
                    break;

                case 0x80: // SetStandby
                    if (rxMode)
                    {
                        ExitRxMode();
                    }
                    state = State.Idle;
                    break;

                case 0x84: // SetCad
                case 0x94: // SetSleep
                case 0x86: // SetRfFrequency
                case 0x8E: // SetTxParams
                case 0x8F: // SetPaConfig
                case 0x89: // SetBufferBaseAddress
                case 0x96: // SetRegulatorMode
                case 0x9D: // SetTxFallbackMode
                case 0x98: // SetLoRaSymbNumTimeout
                    // Single-byte commands or we don't care about params
                    state = State.Idle;
                    break;

                default:
                    this.Log(LogLevel.Debug, "Unknown opcode: 0x{0:X2}", op);
                    state = State.Idle;
                    break;
            }

            return 0; // Status byte placeholder
        }

        private void TriggerTx()
        {
            this.Log(LogLevel.Debug, "TX: {0} bytes", txLen);
            Busy.Set(true);

            if (loopbackMode)
            {
                TriggerTxLoopback();
            }
            else
            {
                TriggerTxBridge();
            }

            Busy.Set(false);
            txLen = 0;
            IRQ.Set(irqFlags != 0);
        }

        private void TriggerTxLoopback()
        {
            // In loopback mode, TX data is immediately available for RX
            // Copy TX buffer to RX buffer
            Array.Copy(txBuffer, 0, rxBuffer, 0, txLen);
            rxLen = txLen;
            rxRssi = -30; // Simulated good signal
            rxSnr = 100;  // 10.0 dB * 10

            // If we were in RX mode, trigger RxDone; otherwise just TxDone
            if (pendingLoopbackRx)
            {
                irqFlags |= 0x0003; // TxDone + RxDone
                pendingLoopbackRx = false;
                this.Log(LogLevel.Debug, "Loopback: TX done, {0} bytes available in RX", rxLen);
            }
            else
            {
                irqFlags |= 0x0001; // TxDone only
                // Store for next RX
                loopbackDataAvailable = true;
                this.Log(LogLevel.Debug, "Loopback: TX done, data queued for next RX");
            }
        }

        private void TriggerTxBridge()
        {
            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "TX failed: not connected to simulator");
                irqFlags |= 0x0040; // TxDone with implicit error
                return;
            }

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
        }

        private void EnterRxMode()
        {
            // Convert SX1262 24-bit timeout (big-endian, 15.625us steps) to microseconds
            uint timeoutSteps = (uint)((rxTimeoutBytes[0] << 16) | (rxTimeoutBytes[1] << 8) | rxTimeoutBytes[2]);
            uint timeoutUs;
            if (timeoutSteps == 0xFFFFFF)
            {
                timeoutUs = 0xFFFFFFFF; // Continuous RX
            }
            else
            {
                timeoutUs = (uint)((timeoutSteps * 15625UL) / 1000UL);
            }

            rxMode = true;
            this.Log(LogLevel.Debug, "RX enter: timeout={0}us", timeoutUs == 0xFFFFFFFF ? "continuous" : timeoutUs.ToString());

            if (loopbackMode)
            {
                EnterRxModeLoopback();
            }
            else
            {
                EnterRxModeBridge(timeoutUs);
            }
        }

        private void EnterRxModeLoopback()
        {
            // In loopback mode, check if there's queued data from a previous TX
            if (loopbackDataAvailable)
            {
                // Data already in rxBuffer from previous TX
                irqFlags |= 0x0002; // RxDone
                loopbackDataAvailable = false;
                rxMode = false;
                IRQ.Set(true);
                this.Log(LogLevel.Debug, "Loopback: immediate RX, {0} bytes", rxLen);
            }
            else
            {
                // Mark that we're waiting for loopback data
                pendingLoopbackRx = true;
                this.Log(LogLevel.Debug, "Loopback: RX waiting for TX");
            }
        }

        private void EnterRxModeBridge(uint timeoutUs)
        {
            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "RX enter failed: not connected to simulator");
                return;
            }

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
                this.Log(LogLevel.Warning, "RX enter error: {0}", e.Message);
                Disconnect();
                rxMode = false;
            }
        }

        private void ExitRxMode()
        {
            if (loopbackMode)
            {
                pendingLoopbackRx = false;
                rxMode = false;
                this.Log(LogLevel.Debug, "Loopback: RX exit");
                return;
            }

            if (stream == null)
            {
                rxMode = false;
                return;
            }

            this.Log(LogLevel.Debug, "RX exit");

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
                this.Log(LogLevel.Warning, "RX exit error: {0}", e.Message);
                Disconnect();
            }

            rxMode = false;
        }

        private void WaitForRxResponse()
        {
            // Block until we receive RX_PACKET (0x27) or RX_TIMEOUT (0x28)
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
                    if (resp.Length < 5)
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

                    Array.Copy(resp, 3, rxBuffer, 0, Math.Min(rxLen, (ushort)256));
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
                IRQ.Set(irqFlags != 0);
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
                if (socket != null)
                    socket.ReceiveTimeout = 100;
            }
        }

        private void EnsureConnected()
        {
            if (loopbackMode)
                return;

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
                this.Log(LogLevel.Info, "Connected to simulator at {0}:{1}", simHost, simPort);
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
            ClearIrqStatus,
            SetDioIrqParams,
        }

        private readonly IMachine machine;
        private string simHost;
        private int simPort;
        private bool loopbackMode;
        private readonly byte[] txBuffer;
        private readonly byte[] rxBuffer;

        private TcpClient socket;
        private NetworkStream stream;

        private State state;
        private byte opcode;
        private int byteIndex;
        private byte bufferOffset;
        private ushort txLen;
        private ushort rxLen;
        private short rxRssi;
        private short rxSnr;
        private ushort irqFlags;
        private bool rxMode;
        private byte[] rxTimeoutBytes = new byte[3];

        // Loopback mode state
        private bool loopbackDataAvailable;
        private bool pendingLoopbackRx;
    }
}

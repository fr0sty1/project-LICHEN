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
                lock (connectionLock)
                {
                    Disconnect();
                    simPort = value;
                }
                this.Log(LogLevel.Info, "SimPort set to {0}", value);
            }
        }

        public string SimHost
        {
            get => simHost;
            set
            {
                lock (connectionLock)
                {
                    Disconnect();
                    simHost = value;
                }
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
            lock (stateLock)
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
                latchedIrqFlags = 0;
                clearIrqMask = 0;
                rxMode = false;
                rxOneShot = false;
                Array.Clear(txBuffer, 0, txBuffer.Length);
                Array.Clear(rxBuffer, 0, rxBuffer.Length);
                Array.Clear(rxTimeoutBytes, 0, rxTimeoutBytes.Length);
                Busy.Set(false);
                IRQ.Set(false);
            }
        }

        public void FinishTransmission()
        {
            lock (stateLock)
            {
                state = State.Idle;
                byteIndex = 0;
            }
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
                        lock (stateLock)
                        {
                            result = idx < rxBuffer.Length ? rxBuffer[idx] : (byte)0;
                        }
                        byteIndex++;
                    }
                    break;

                case State.SetTx:
                case State.SetPacketParams:
                case State.SetModulationParams:
                case State.SetDioIrqParams:
                    // Consume parameter bytes, ignore values
                    byteIndex++;
                    break;

                case State.ClearIrqStatus:
                    clearIrqMask = (ushort)((clearIrqMask << 8) | data);
                    byteIndex++;
                    if (byteIndex == 2)
                    {
                        lock (stateLock)
                        {
                            irqFlags &= (ushort)~clearIrqMask;
                            IRQ.Set(irqFlags != 0);
                        }
                    }
                    break;

                case State.SetRx:
                    // Collect 3 timeout bytes (24-bit big-endian from SX1262)
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
                    lock (stateLock)
                    {
                        if (rxMode)
                            result = 0x52;
                        else
                            result = 0x62;
                    }
                    break;

                case State.GetIrqStatus:
                    if (byteIndex == 0)
                    {
                        result = (byte)((latchedIrqFlags >> 8) & 0xFF);
                        byteIndex++;
                    }
                    else
                    {
                        result = (byte)(latchedIrqFlags & 0xFF);
                    }
                    break;

                case State.GetRxBufferStatus:
                    if (byteIndex == 0)
                    {
                        lock (stateLock)
                        {
                            result = (byte)rxLen;
                        }
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
                        lock (stateLock)
                        {
                            result = (byte)((-rxRssi / 2) & 0xFF); // SX1262 RSSI format
                        }
                        byteIndex++;
                    }
                    else if (byteIndex == 1)
                    {
                        lock (stateLock)
                        {
                            result = (byte)((rxSnr / 4) & 0xFF); // SX1262 SNR format
                        }
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
                {
                    state = State.SetTx;
                    bool exitRx;
                    lock (stateLock)
                    {
                        exitRx = rxMode;
                        if (exitRx)
                        {
                            rxMode = false;
                            rxOneShot = false;
                        }
                    }
                    if (exitRx)
                    {
                        SendRxExit();
                    }
                    TriggerTx();
                    break;
                }

                case 0x82: // SetRx
                    state = State.SetRx;
                    // Timeout bytes collected in Transmit(), then SendRxEnter() called
                    break;

                case 0xC0: // GetStatus
                    state = State.GetStatus;
                    break;

                case 0x12: // GetIrqStatus
                    state = State.GetIrqStatus;
                    lock (stateLock)
                    {
                        latchedIrqFlags = irqFlags;
                    }
                    break;

                case 0x02: // ClearIrqStatus
                    state = State.ClearIrqStatus;
                    clearIrqMask = 0;
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
                {
                    bool leaveRx;
                    lock (stateLock)
                    {
                        leaveRx = rxMode;
                        if (leaveRx)
                        {
                            rxMode = false;
                            rxOneShot = false;
                        }
                    }
                    if (leaveRx)
                    {
                        SendRxExit();
                    }
                    state = State.Idle;
                    break;
                }

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
            if (loopbackMode)
            {
                TriggerTxLoopback();
                return;
            }

            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "TX failed: not connected to simulator");
                lock (stateLock)
                {
                    irqFlags |= 0x0040; // TxDone with implicit error
                    IRQ.Set(true);
                }
                return;
            }

            this.Log(LogLevel.Debug, "TX: {0} bytes", txLen);

            try
            {
                // Protocol: [len:4][type:1][payload_len:2][payload]
                var msgLen = 3 + txLen;
                var msg = new byte[4 + msgLen];
                WriteLE32(msg, 0, (uint)msgLen);
                msg[4] = 0x10; // MSG_TX
                WriteLE16(msg, 5, txLen);
                Array.Copy(txBuffer, 0, msg, 7, txLen);

                lock (writeLock)
                {
                    stream.Write(msg, 0, msg.Length);
                }
                // TX_DONE (0x11) and the TxDone IRQ are handled asynchronously by
                // the reader thread, so this SPI transaction returns immediately
                // instead of blocking on the socket.
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "TX error: {0}", e.Message);
                Disconnect();
            }

            txLen = 0;
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

        private void SendRxEnter()
        {
            if (loopbackMode)
            {
                SendRxEnterLoopback();
                return;
            }

            EnsureConnected();
            if (stream == null)
            {
                this.Log(LogLevel.Warning, "RX_ENTER failed: not connected to simulator");
                return;
            }

            // Convert SX1262 24-bit timeout (big-endian, 15.625us steps) to microseconds
            uint timeoutSteps = (uint)((rxTimeoutBytes[0] << 16) | (rxTimeoutBytes[1] << 8) | rxTimeoutBytes[2]);
            uint timeoutUs;
            bool oneShot = timeoutSteps != 0xFFFFFF;
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

            lock (stateLock)
            {
                rxMode = true;
                rxOneShot = oneShot;
            }
            this.Log(LogLevel.Debug, "RX_ENTER: timeout={0}us oneShot={1}", timeoutUs == 0xFFFFFFFF ? "continuous" : timeoutUs.ToString(), oneShot);

            try
            {
                // Protocol: [len:4][type:1][timeout_us:4]
                var msg = new byte[9];
                WriteLE32(msg, 0, 5); // message length
                msg[4] = 0x24; // RX_ENTER
                WriteLE32(msg, 5, timeoutUs);

                lock (writeLock)
                {
                    stream.Write(msg, 0, msg.Length);
                }
                // RX_PACKET / RX_TIMEOUT arrive asynchronously and are handled by
                // the reader thread. Do NOT block the SPI bus here — blocking in
                // RX mode would prevent the node from ever leaving RX to transmit.
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "RX_ENTER error: {0}", e.Message);
                Disconnect();
                lock (stateLock)
                {
                    rxMode = false;
                    rxOneShot = false;
                }
            }
        }

        private void SendRxEnterLoopback()
        {
            lock (stateLock)
            {
                rxMode = true;
                rxOneShot = true;
            }

            // In loopback mode, check if there's queued data from a previous TX
            if (loopbackDataAvailable)
            {
                // Data already in rxBuffer from previous TX
                irqFlags |= 0x0002; // RxDone
                loopbackDataAvailable = false;
                rxMode = false;
                rxOneShot = false;
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

        private void SendRxExit()
        {
            if (loopbackMode)
            {
                lock (stateLock)
                {
                    pendingLoopbackRx = false;
                    rxMode = false;
                    rxOneShot = false;
                }
                this.Log(LogLevel.Debug, "Loopback: RX exit");
                return;
            }

            if (stream == null)
            {
                lock (stateLock)
                {
                    rxMode = false;
                    rxOneShot = false;
                }
                return;
            }

            this.Log(LogLevel.Debug, "RX_EXIT");

            try
            {
                // Protocol: [len:4][type:1] - no payload
                var msg = new byte[5];
                WriteLE32(msg, 0, 1); // message length = 1 (just the type byte)
                msg[4] = 0x26; // MSG_RX_EXIT

                lock (writeLock)
                {
                    stream.Write(msg, 0, msg.Length);
                }
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "RX_EXIT error: {0}", e.Message);
                Disconnect();
            }

            lock (stateLock)
            {
                rxMode = false;
                rxOneShot = false;
            }
        }

        private void EnsureConnected()
        {
            if (loopbackMode)
                return;

            lock (connectionLock)
            {
                if (socket != null && socket.Connected)
                    return;

                try
                {
                    Disconnect();
                    socket = new TcpClient();
                    socket.NoDelay = true;
                    socket.ReceiveTimeout = 100;
                    socket.Connect(simHost, simPort);
                    stream = socket.GetStream();
                    this.Log(LogLevel.Info, "Connected to simulator at {0}:{1}", simHost, simPort);
                    StartReader(socket, stream);
                }
                catch (Exception e)
                {
                    this.Log(LogLevel.Warning, "Connect failed: {0}", e.Message);
                    socket = null;
                    stream = null;
                }
            }
        }

        private void Disconnect()
        {
            lock (connectionLock)
            {
                var oldReader = readerThread;
                var oldSocket = socket;

                readerThread = null;
                stream = null;
                socket = null;
                oldSocket?.Close();
                if (oldReader != null && oldReader != System.Threading.Thread.CurrentThread)
                {
                    oldReader.Join();
                }
            }
        }

        // Start the background reader for the current connection. Reads block
        // (ReceiveTimeout = 0); Disconnect() closes the socket to break out.
        private void StartReader(TcpClient readerSocket, NetworkStream readerStream)
        {
            var thread = new System.Threading.Thread(
                () => ReaderLoop(readerSocket, readerStream))
            {
                IsBackground = true,
                Name = "sx1262-sim-reader",
            };
            readerThread = thread;
            thread.Start();
        }

        private void ReaderLoop(TcpClient readerSocket, NetworkStream readerStream)
        {
            try
            {
                readerSocket.ReceiveTimeout = 0; // block for full messages
            }
            catch (Exception)
            {
                // socket already gone
            }

            while (true)
            {
                byte[] resp;
                try
                {
                    resp = ReadMessage(readerStream);
                }
                catch (Exception)
                {
                    break; // socket closed / error
                }

                if (resp == null)
                {
                    break; // peer closed
                }
                if (resp.Length < 1)
                {
                    continue;
                }
                DispatchMessage(resp);
            }
        }

        // Dispatch an async message from the simulator to IRQ flags.
        // Runs on the reader thread, NOT the SPI/emulation thread.
        private void DispatchMessage(byte[] resp)
        {
            lock (stateLock)
            {
                switch (resp[0])
                {
                    case 0x11: // TX_DONE
                        this.Log(LogLevel.Debug, "TX done (async)");
                        irqFlags |= 0x0001; // TxDone
                        IRQ.Set(true);
                        break;

                    case 0x27: // RX_PACKET (async push)
                    case 0x21: // RX_POLL response
                    {
                        if (resp.Length < 5 || !rxMode)
                        {
                            break;
                        }
                        var packetLen = ReadLE16(resp, 1);
                        int payloadEnd = 3 + packetLen;
                        if (packetLen > rxBuffer.Length || resp.Length < payloadEnd + 4)
                        {
                            break;
                        }
                        rxLen = packetLen;
                        Array.Copy(resp, 3, rxBuffer, 0, rxLen);
                        rxRssi = (short)ReadLE16(resp, payloadEnd);
                        rxSnr = (short)ReadLE16(resp, payloadEnd + 2);
                        if (rxOneShot)
                        {
                            rxMode = false;
                            rxOneShot = false;
                        }
                        this.Log(LogLevel.Debug, "RX_PACKET {0} bytes (async) oneShot={1}", rxLen, rxOneShot);
                        irqFlags |= 0x0002; // RxDone
                        IRQ.Set(true);
                        break;
                    }

                    case 0x28: // RX_TIMEOUT
                        if (!rxMode)
                        {
                            break;
                        }
                        rxMode = false;
                        rxOneShot = false;
                        this.Log(LogLevel.Debug, "RX_TIMEOUT (async)");
                        irqFlags |= 0x0200; // Timeout
                        IRQ.Set(true);
                        break;

                    default:
                        this.Log(LogLevel.Warning, "reader: unexpected message 0x{0:X2}", resp[0]);
                        break;
                }
            }
        }

        private byte[] ReadMessage(NetworkStream readerStream)
        {
            var lenBuf = new byte[4];
            int read = 0;
            while (read < 4)
            {
                int n = readerStream.Read(lenBuf, read, 4 - read);
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
                int n = readerStream.Read(data, read, len - read);
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
        private ushort latchedIrqFlags;
        private ushort clearIrqMask;
        private bool rxMode;
        private bool rxOneShot;
        private byte[] rxTimeoutBytes = new byte[3];

        // Loopback mode state
        private bool loopbackDataAvailable;
        private bool pendingLoopbackRx;

        // Background reader: ALL socket reads happen here so the SPI Transmit()
        // path never blocks. A blocking read on the RX-enter path (the old
        // WaitForRxResponse) froze the SPI bus while the radio was in RX, which
        // meant a node could never leave RX to transmit — both test nodes then
        // deadlocked waiting for a packet neither could send. Messages from
        // the simulator (TX_DONE, RX_PACKET, RX_TIMEOUT) are now dispatched to
        // the IRQ flags asynchronously.
        //
        // One-shot RX contract:
        // - SendRxEnter with timeout != 0xFFFFFF sets rxMode=true, rxOneShot=true.
        // - On RX_PACKET: if (rxOneShot) { rxMode=false; rxOneShot=false; } (exits after 1st packet);
        //   continuous mode (0xFFFFFF timeout, rxOneShot=false) keeps rxMode=true to accept multiple packets.
        // - RX_TIMEOUT always clears both rxMode and rxOneShot.
        // - SetTx/SetStandby/SendRxExit clear both flags.
        // - GetStatus reflects current rxMode under lock.
        // - ALL rxMode/rxOneShot/irqFlags/rxLen/etc accesses use lock(stateLock)
        //   to eliminate races between SPI Transmit(), reader thread, OnGPIO CS
        //   FinishTransmission(), and SetRx state machine.
        private System.Threading.Thread readerThread;
        private readonly object writeLock = new object();
        private readonly object stateLock = new object();
        private readonly object connectionLock = new object();
    }
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// GPS/GNSS peripheral for Renode - L76K compatible UART output.
// ponytail: outputs canned NMEA sentences, no real GPS simulation.
//
// Outputs GGA and RMC sentences at 1Hz to simulate a GPS module.
// Position is configurable via properties. Time uses simulation time.
//
// Usage in .repl:
//   gps: Sensors.GPS @ uart1
//       latitude: 47.6062
//       longitude: -122.3321
//       altitude: 56.0
//
// L76K on T-Echo uses 9600 baud UART (default for most GPS modules).

using System;
using System.Collections.Generic;
using System.Text;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.UART;

namespace Antmicro.Renode.Peripherals.Sensors
{
    public class GPS : IUART
    {
        public GPS(IMachine machine)
        {
            this.machine = machine;
            txQueue = new Queue<byte>();

            // Default position: Seattle
            latitude = 47.6062;
            longitude = -122.3321;
            altitude = 56.0;

            // Track last output time to ensure 1Hz rate
            lastOutputTicks = 0;

            this.Log(LogLevel.Info, "GPS peripheral created at lat={0}, lon={1}, alt={2}",
                latitude, longitude, altitude);
        }

        public double Latitude
        {
            get => latitude;
            set
            {
                latitude = value;
                this.Log(LogLevel.Debug, "Latitude set to {0}", value);
            }
        }

        public double Longitude
        {
            get => longitude;
            set
            {
                longitude = value;
                this.Log(LogLevel.Debug, "Longitude set to {0}", value);
            }
        }

        public double Altitude
        {
            get => altitude;
            set
            {
                altitude = value;
                this.Log(LogLevel.Debug, "Altitude set to {0}", value);
            }
        }

        // IUART implementation
        public event Action<byte> CharReceived;

        public void WriteChar(byte value)
        {
            // GPS ignores input (could add command parsing later)
            this.Log(LogLevel.Debug, "GPS received: 0x{0:X2} '{1}'", value, (char)value);
        }

        public void Reset()
        {
            txQueue.Clear();
            lastOutputTicks = 0;
            this.Log(LogLevel.Debug, "GPS reset");
        }

        public uint BaudRate => 9600;

        public Bits StopBits => Bits.One;

        public Parity ParityBit => Parity.None;

        // Called to generate NMEA output - invoke from monitor or timer hook
        public void Tick()
        {
            // Check if 1 second has passed (assuming 1MHz tick rate)
            var currentTicks = (long)machine.ElapsedVirtualTime.TimeElapsed.Ticks;
            if (currentTicks - lastOutputTicks < 10000000) // 1 second in 100ns ticks
            {
                return;
            }
            lastOutputTicks = currentTicks;

            OutputNmeaSentences();
            FlushQueue();
        }

        // Force output regardless of timing (for testing)
        public void ForceOutput()
        {
            OutputNmeaSentences();
            FlushQueue();
        }

        private void OutputNmeaSentences()
        {
            // Get current simulation time for NMEA timestamp
            var ticks = (long)machine.ElapsedVirtualTime.TimeElapsed.Ticks;
            var totalSeconds = ticks / 10000000.0; // Convert 100ns ticks to seconds
            var hours = (int)(totalSeconds / 3600) % 24;
            var minutes = (int)(totalSeconds / 60) % 60;
            var seconds = (int)totalSeconds % 60;
            var msec = (int)((totalSeconds - Math.Floor(totalSeconds)) * 1000);

            // Format time as HHMMSS.sss
            var timeStr = string.Format("{0:D2}{1:D2}{2:D2}.{3:D3}",
                hours, minutes, seconds, msec);

            // Format date as DDMMYY (use fixed date for simulation)
            var dateStr = "060726"; // July 6, 2026

            // Output GGA sentence
            var gga = FormatGGA(timeStr);
            QueueSentence(gga);

            // Output RMC sentence
            var rmc = FormatRMC(timeStr, dateStr);
            QueueSentence(rmc);
        }

        private string FormatGGA(string timeStr)
        {
            // $GPGGA,HHMMSS.sss,DDMM.MMMM,N/S,DDDMM.MMMM,E/W,fix,sats,hdop,alt,M,geoid,M,,*CS
            var latDeg = (int)Math.Abs(latitude);
            var latMin = (Math.Abs(latitude) - latDeg) * 60.0;
            var latDir = latitude >= 0 ? 'N' : 'S';

            var lonDeg = (int)Math.Abs(longitude);
            var lonMin = (Math.Abs(longitude) - lonDeg) * 60.0;
            var lonDir = longitude >= 0 ? 'E' : 'W';

            var sentence = string.Format("GPGGA,{0},{1:D2}{2:F4},{3},{4:D3}{5:F4},{6},1,08,0.9,{7:F1},M,0.0,M,,",
                timeStr, latDeg, latMin, latDir, lonDeg, lonMin, lonDir, altitude);

            return AddChecksum(sentence);
        }

        private string FormatRMC(string timeStr, string dateStr)
        {
            // $GPRMC,HHMMSS.sss,A,DDMM.MMMM,N/S,DDDMM.MMMM,E/W,speed,course,DDMMYY,magvar,E/W*CS
            var latDeg = (int)Math.Abs(latitude);
            var latMin = (Math.Abs(latitude) - latDeg) * 60.0;
            var latDir = latitude >= 0 ? 'N' : 'S';

            var lonDeg = (int)Math.Abs(longitude);
            var lonMin = (Math.Abs(longitude) - lonDeg) * 60.0;
            var lonDir = longitude >= 0 ? 'E' : 'W';

            var sentence = string.Format("GPRMC,{0},A,{1:D2}{2:F4},{3},{4:D3}{5:F4},{6},0.0,0.0,{7},0.0,E",
                timeStr, latDeg, latMin, latDir, lonDeg, lonMin, lonDir, dateStr);

            return AddChecksum(sentence);
        }

        private string AddChecksum(string sentence)
        {
            // NMEA checksum: XOR of all characters between $ and *
            byte checksum = 0;
            foreach (var c in sentence)
            {
                checksum ^= (byte)c;
            }
            return string.Format("${0}*{1:X2}\r\n", sentence, checksum);
        }

        private void QueueSentence(string sentence)
        {
            this.Log(LogLevel.Debug, "GPS TX: {0}", sentence.TrimEnd());

            foreach (var c in sentence)
            {
                txQueue.Enqueue((byte)c);
            }
        }

        private void FlushQueue()
        {
            while (txQueue.Count > 0)
            {
                var b = txQueue.Dequeue();
                CharReceived?.Invoke(b);
            }
        }

        private readonly IMachine machine;
        private readonly Queue<byte> txQueue;

        private double latitude;
        private double longitude;
        private double altitude;
        private long lastOutputTicks;
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// Serial-to-LoRa bridge for RAK4631 (nRF52840 + SX1262)
// Defensive, paranoid, explores hardware at boot.

#include <Arduino.h>
#include <Adafruit_TinyUSB.h>  // Required for USB Serial on RAK4631
#include <RadioLib.h>
#include <SPI.h>

// =============================================================================
// Hardware Configuration - RAK4631
// =============================================================================

// SX1262 control pins (directly connected to nRF52840)
#define LORA_NSS   42   // P1.10 - SPI chip select
#define LORA_DIO1  47   // P1.15 - interrupt
#define LORA_BUSY  46   // P1.14 - busy status
#define LORA_RST   38   // P1.06 - reset

// SX1262 SPI pins - NOT on default Arduino SPI bus!
// RAK4631 routes SX1262 to different pins than the WisBlock SPI slot
#define LORA_SCK   43   // P1.11
#define LORA_MOSI  44   // P1.12
#define LORA_MISO  45   // P1.13

// RAK4631 LEDs
#define LED_GREEN  35
#define LED_BLUE   36

// SX1262 uses default SPI with custom pins set in setup()

// SX1262 limits (from datasheet)
#define SX1262_FREQ_MIN     150.0    // MHz
#define SX1262_FREQ_MAX     960.0    // MHz
#define SX1262_SF_MIN       5
#define SX1262_SF_MAX       12
#define SX1262_BW_MIN       7.8      // kHz
#define SX1262_BW_MAX       500.0    // kHz
#define SX1262_CR_MIN       5        // 4/5
#define SX1262_CR_MAX       8        // 4/8
#define SX1262_PWR_MIN      -9       // dBm
#define SX1262_PWR_MAX      22       // dBm

// Buffer limits
#define MAX_PACKET_LEN      255
#define MAX_LINE_LEN        600      // 255 bytes * 2 hex chars + command overhead
#define SERIAL_TIMEOUT_MS   100

// =============================================================================
// Global State
// =============================================================================

SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);

// Radio config with sane defaults
struct RadioConfig {
  float frequency = 915.0;
  float bandwidth = 125.0;
  uint8_t spreadingFactor = 10;
  uint8_t codingRate = 5;
  int8_t power = 22;
  uint16_t preambleLen = 8;
  bool crcEnabled = true;
  uint8_t syncWord = 0x12;  // 0x12=LoRaWAN private, 0x34=LoRaWAN public, 0x2B=Meshtastic
} config;

// Runtime stats
struct Stats {
  uint32_t txCount = 0;
  uint32_t txBytes = 0;
  uint32_t txErrors = 0;
  uint32_t rxCount = 0;
  uint32_t rxBytes = 0;
  uint32_t rxErrors = 0;
  uint32_t cmdCount = 0;
  uint32_t cmdErrors = 0;
  uint32_t bootTime = 0;
} stats;

volatile bool rxFlag = false;
volatile bool txDone = false;
bool radioInitialized = false;

char lineBuf[MAX_LINE_LEN + 1];
int lineLen = 0;

uint8_t pktBuf[MAX_PACKET_LEN];

// =============================================================================
// Utilities
// =============================================================================

void ledOn(int pin) { digitalWrite(pin, HIGH); }
void ledOff(int pin) { digitalWrite(pin, LOW); }

void blinkError(int count) {
  for (int i = 0; i < count; i++) {
    ledOn(LED_BLUE);
    delay(100);
    ledOff(LED_BLUE);
    delay(100);
  }
}

void reply(const char* status, const char* msg = nullptr) {
  Serial.print(status);
  if (msg) {
    Serial.print(" ");
    Serial.print(msg);
  }
  Serial.println();
  Serial.flush();
}

void replyOK(const char* msg = nullptr) { reply("OK", msg); }
void replyERR(const char* msg) { reply("ERR", msg); stats.cmdErrors++; }

// Bounded hex decode - returns -1 on error
int hexCharToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int hexDecode(const char* hex, uint8_t* out, int maxLen) {
  if (!hex || !out || maxLen <= 0) return -1;

  int len = 0;
  while (*hex && *(hex+1) && len < maxLen) {
    // Skip whitespace
    while (*hex == ' ') hex++;
    if (!*hex) break;

    int hi = hexCharToNibble(*hex++);
    if (hi < 0) return -1;

    int lo = hexCharToNibble(*hex++);
    if (lo < 0) return -1;

    out[len++] = (uint8_t)((hi << 4) | lo);
  }

  // Check for trailing garbage (non-whitespace after valid hex)
  while (*hex) {
    if (*hex != ' ' && *hex != '\r' && *hex != '\n') return -1;
    hex++;
  }

  return len;
}

void hexEncode(const uint8_t* data, int len, char* out, int outMax) {
  if (!data || !out || len <= 0 || outMax < len * 2 + 1) {
    if (out && outMax > 0) out[0] = '\0';
    return;
  }

  const char* hex = "0123456789abcdef";
  for (int i = 0; i < len && (i * 2 + 2) < outMax; i++) {
    *out++ = hex[data[i] >> 4];
    *out++ = hex[data[i] & 0x0f];
  }
  *out = '\0';
}

// =============================================================================
// Radio Interrupt Handlers
// =============================================================================

void rxInterrupt() {
  rxFlag = true;
}

void txInterrupt() {
  txDone = true;
}

// =============================================================================
// Hardware Exploration
// =============================================================================

void probeHardware() {
  Serial.println("# ============================================");
  Serial.println("# LICHEN Serial-LoRa Bridge");
  Serial.println("# Hardware Probe");
  Serial.println("# ============================================");

  // MCU info
  Serial.println("#");
  Serial.print("# MCU: nRF52840 @ ");
  Serial.print(SystemCoreClock / 1000000);
  Serial.println(" MHz");

  // Check SPI pins
  Serial.print("# SPI pins: NSS=");
  Serial.print(LORA_NSS);
  Serial.print(" DIO1=");
  Serial.print(LORA_DIO1);
  Serial.print(" BUSY=");
  Serial.print(LORA_BUSY);
  Serial.print(" RST=");
  Serial.println(LORA_RST);

  // Probe BUSY pin state
  pinMode(LORA_BUSY, INPUT);
  Serial.print("# BUSY pin state: ");
  Serial.println(digitalRead(LORA_BUSY) ? "HIGH" : "LOW");

  // Initialize radio
  Serial.println("#");
  Serial.println("# Initializing SX1262...");

  int state = radio.begin(
    config.frequency,
    config.bandwidth,
    config.spreadingFactor,
    config.codingRate,
    config.syncWord,
    config.power,
    config.preambleLen
  );

  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# FATAL: Radio init failed, code=");
    Serial.println(state);
    Serial.println("# Possible causes:");
    Serial.println("#   - Wrong SPI pins");
    Serial.println("#   - Radio not powered");
    Serial.println("#   - Damaged hardware");
    radioInitialized = false;
    return;
  }

  radioInitialized = true;
  Serial.println("# Radio initialized OK");

  // Read chip version/status
  Serial.println("#");
  Serial.println("# Radio capabilities:");
  Serial.print("#   Frequency range: ");
  Serial.print(SX1262_FREQ_MIN, 0);
  Serial.print(" - ");
  Serial.print(SX1262_FREQ_MAX, 0);
  Serial.println(" MHz");
  Serial.print("#   SF range: ");
  Serial.print(SX1262_SF_MIN);
  Serial.print(" - ");
  Serial.println(SX1262_SF_MAX);
  Serial.print("#   TX power range: ");
  Serial.print(SX1262_PWR_MIN);
  Serial.print(" - ");
  Serial.print(SX1262_PWR_MAX);
  Serial.println(" dBm");

  // Enable CRC
  state = radio.setCRC(config.crcEnabled ? 2 : 0);  // 2 = CRC16
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: setCRC failed, code=");
    Serial.println(state);
  }

  // Enable TCXO (RAK4631 has TCXO)
  state = radio.setTCXO(1.8);  // 1.8V TCXO
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: setTCXO failed, code=");
    Serial.println(state);
  }

  // Set DIO2 as RF switch control
  state = radio.setDio2AsRfSwitch(true);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: setDio2AsRfSwitch failed, code=");
    Serial.println(state);
  }

  // Read current RSSI (noise floor indication)
  float rssi = radio.getRSSI();
  Serial.print("#   Current RSSI (noise floor): ");
  Serial.print(rssi);
  Serial.println(" dBm");

  // Set up interrupts
  radio.setDio1Action(rxInterrupt);

  // Start receiving
  state = radio.startReceive();
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: startReceive failed, code=");
    Serial.println(state);
  }

  Serial.println("#");
  Serial.print("# Config: SF=");
  Serial.print(config.spreadingFactor);
  Serial.print(" BW=");
  Serial.print(config.bandwidth);
  Serial.print(" CR=4/");
  Serial.print(config.codingRate);
  Serial.print(" FREQ=");
  Serial.print(config.frequency, 3);
  Serial.print(" PWR=");
  Serial.print(config.power);
  Serial.println(" dBm");

  Serial.println("#");
  Serial.println("# ============================================");
  Serial.println("# Ready for commands");
  Serial.println("# Type HELP for command list");
  Serial.println("# ============================================");
}

// =============================================================================
// Command: HELP
// =============================================================================

void cmdHelp() {
  Serial.println("# Commands:");
  Serial.println("#   TX <hex>              - Transmit packet");
  Serial.println("#   CFG key=val ...       - Configure radio");
  Serial.println("#   STATUS                - Show current config");
  Serial.println("#   STATS                 - Show runtime statistics");
  Serial.println("#   RSSI                  - Read current RSSI");
  Serial.println("#   PROBE                 - Re-probe hardware");
  Serial.println("#   RESET                 - Reset radio");
  Serial.println("#   HELP                  - This message");
  Serial.println("#");
  Serial.println("# Config keys:");
  Serial.println("#   SF=5-12, BW=7.8-500, CR=5-8");
  Serial.println("#   FREQ=150-960 (MHz) or FREQ=150000000-960000000 (Hz)");
  Serial.println("#   PWR=-9 to 22 (dBm)");
  Serial.println("#   CRC=0/1, PREAMBLE=6-65535, SYNC=0x00-0xFF");
  Serial.println("#   SYNC: 0x12=LoRaWAN, 0x2B=Meshtastic");
  Serial.println("#");
  Serial.println("# Output:");
  Serial.println("#   RX <rssi> <snr> <hex> - Received packet");
  Serial.println("#   OK [msg]              - Command succeeded");
  Serial.println("#   ERR <msg>             - Command failed");
  Serial.println("#   # ...                 - Comment/debug");
  replyOK();
}

// =============================================================================
// Command: TX
// =============================================================================

void cmdTx(const char* args) {
  if (!radioInitialized) {
    replyERR("radio not initialized");
    return;
  }

  if (!args || !*args) {
    replyERR("missing hex payload");
    return;
  }

  int pktLen = hexDecode(args, pktBuf, MAX_PACKET_LEN);
  if (pktLen < 0) {
    replyERR("invalid hex");
    return;
  }
  if (pktLen == 0) {
    replyERR("empty payload");
    return;
  }

  ledOn(LED_GREEN);

  int state = radio.transmit(pktBuf, pktLen);

  ledOff(LED_GREEN);

  if (state == RADIOLIB_ERR_NONE) {
    stats.txCount++;
    stats.txBytes += pktLen;

    char msg[32];
    snprintf(msg, sizeof(msg), "sent %d bytes", pktLen);
    replyOK(msg);
  } else {
    stats.txErrors++;

    char msg[48];
    snprintf(msg, sizeof(msg), "transmit failed, code=%d", state);
    replyERR(msg);
  }

  // Return to receive mode
  int rxState = radio.startReceive();
  if (rxState != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: startReceive failed, code=");
    Serial.println(rxState);
  }
}

// =============================================================================
// Command: CFG
// =============================================================================

bool validateConfig(RadioConfig* cfg) {
  if (cfg->frequency < SX1262_FREQ_MIN || cfg->frequency > SX1262_FREQ_MAX) {
    replyERR("FREQ out of range (150-960 MHz)");
    return false;
  }
  if (cfg->spreadingFactor < SX1262_SF_MIN || cfg->spreadingFactor > SX1262_SF_MAX) {
    replyERR("SF out of range (5-12)");
    return false;
  }
  if (cfg->bandwidth < SX1262_BW_MIN || cfg->bandwidth > SX1262_BW_MAX) {
    replyERR("BW out of range (7.8-500 kHz)");
    return false;
  }
  if (cfg->codingRate < SX1262_CR_MIN || cfg->codingRate > SX1262_CR_MAX) {
    replyERR("CR out of range (5-8)");
    return false;
  }
  if (cfg->power < SX1262_PWR_MIN || cfg->power > SX1262_PWR_MAX) {
    replyERR("PWR out of range (-9 to 22 dBm)");
    return false;
  }
  if (cfg->preambleLen < 6 || cfg->preambleLen > 65535) {
    replyERR("PREAMBLE out of range (6-65535)");
    return false;
  }
  return true;
}

void cmdCfg(const char* args) {
  if (!radioInitialized) {
    replyERR("radio not initialized");
    return;
  }

  if (!args || !*args) {
    replyERR("missing config params");
    return;
  }

  // Parse into temporary config
  RadioConfig newConfig = config;

  char argsCopy[MAX_LINE_LEN];
  strncpy(argsCopy, args, sizeof(argsCopy) - 1);
  argsCopy[sizeof(argsCopy) - 1] = '\0';

  char* p = argsCopy;
  while (*p) {
    while (*p == ' ') p++;
    if (!*p) break;

    if (strncmp(p, "SF=", 3) == 0) {
      newConfig.spreadingFactor = atoi(p + 3);
    } else if (strncmp(p, "BW=", 3) == 0) {
      newConfig.bandwidth = atof(p + 3);
    } else if (strncmp(p, "CR=", 3) == 0) {
      newConfig.codingRate = atoi(p + 3);
    } else if (strncmp(p, "FREQ=", 5) == 0) {
      double val = atof(p + 5);
      // Auto-detect Hz vs MHz
      if (val > 1000000) {
        newConfig.frequency = val / 1000000.0;
      } else {
        newConfig.frequency = val;
      }
    } else if (strncmp(p, "PWR=", 4) == 0) {
      newConfig.power = atoi(p + 4);
    } else if (strncmp(p, "CRC=", 4) == 0) {
      newConfig.crcEnabled = atoi(p + 4) != 0;
    } else if (strncmp(p, "PREAMBLE=", 9) == 0) {
      newConfig.preambleLen = atoi(p + 9);
    } else if (strncmp(p, "SYNC=", 5) == 0) {
      // Accept hex (0x2B) or decimal (43)
      const char* val = p + 5;
      if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
        newConfig.syncWord = strtol(val, NULL, 16);
      } else {
        newConfig.syncWord = atoi(val);
      }
    } else {
      char key[16] = {0};
      int i = 0;
      while (*p && *p != '=' && *p != ' ' && i < 15) key[i++] = *p++;
      char msg[48];
      snprintf(msg, sizeof(msg), "unknown key: %s", key);
      replyERR(msg);
      return;
    }

    // Skip to next param
    while (*p && *p != ' ') p++;
  }

  // Validate before applying
  if (!validateConfig(&newConfig)) {
    return;  // Error already sent
  }

  // Apply config
  radio.standby();

  int state;
  bool failed = false;

  state = radio.setFrequency(newConfig.frequency);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setFrequency failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setBandwidth(newConfig.bandwidth);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setBandwidth failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setSpreadingFactor(newConfig.spreadingFactor);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setSpreadingFactor failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setCodingRate(newConfig.codingRate);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setCodingRate failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setOutputPower(newConfig.power);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setOutputPower failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setPreambleLength(newConfig.preambleLen);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setPreambleLength failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setCRC(newConfig.crcEnabled ? 2 : 0);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setCRC failed: ");
    Serial.println(state);
    failed = true;
  }

  state = radio.setSyncWord(newConfig.syncWord);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("# setSyncWord failed: ");
    Serial.println(state);
    failed = true;
  }

  if (failed) {
    replyERR("config apply failed (see # lines above)");
    // Try to restore old config
    radio.setFrequency(config.frequency);
    radio.setBandwidth(config.bandwidth);
    radio.setSpreadingFactor(config.spreadingFactor);
    radio.setCodingRate(config.codingRate);
    radio.setOutputPower(config.power);
    radio.startReceive();
    return;
  }

  // Success - save new config
  config = newConfig;

  radio.startReceive();

  char msg[96];
  snprintf(msg, sizeof(msg), "SF=%d BW=%.1f CR=%d FREQ=%.3f PWR=%d CRC=%d SYNC=0x%02X",
           config.spreadingFactor, config.bandwidth, config.codingRate,
           config.frequency, config.power, config.crcEnabled ? 1 : 0, config.syncWord);
  replyOK(msg);
}

// =============================================================================
// Command: STATUS
// =============================================================================

void cmdStatus() {
  if (!radioInitialized) {
    replyERR("radio not initialized");
    return;
  }

  char msg[128];
  snprintf(msg, sizeof(msg),
           "SF=%d BW=%.1f CR=%d FREQ=%.6f PWR=%d CRC=%d PREAMBLE=%d SYNC=0x%02X",
           config.spreadingFactor, config.bandwidth, config.codingRate,
           config.frequency, config.power, config.crcEnabled ? 1 : 0,
           config.preambleLen, config.syncWord);
  replyOK(msg);
}

// =============================================================================
// Command: STATS
// =============================================================================

void cmdStats() {
  Serial.print("OK tx=");
  Serial.print(stats.txCount);
  Serial.print("/");
  Serial.print(stats.txBytes);
  Serial.print("B/");
  Serial.print(stats.txErrors);
  Serial.print("err rx=");
  Serial.print(stats.rxCount);
  Serial.print("/");
  Serial.print(stats.rxBytes);
  Serial.print("B/");
  Serial.print(stats.rxErrors);
  Serial.print("err cmd=");
  Serial.print(stats.cmdCount);
  Serial.print("/");
  Serial.print(stats.cmdErrors);
  Serial.print("err uptime=");
  Serial.print((millis() - stats.bootTime) / 1000);
  Serial.println("s");
}

// =============================================================================
// Command: RSSI
// =============================================================================

void cmdRssi() {
  if (!radioInitialized) {
    replyERR("radio not initialized");
    return;
  }

  float rssi = radio.getRSSI();
  char msg[32];
  snprintf(msg, sizeof(msg), "%.1f dBm", rssi);
  replyOK(msg);
}

// =============================================================================
// Command: RESET
// =============================================================================

void cmdReset() {
  Serial.println("# Resetting radio...");

  radio.reset();
  delay(100);

  int state = radio.begin(
    config.frequency,
    config.bandwidth,
    config.spreadingFactor,
    config.codingRate,
    config.syncWord,
    config.power,
    config.preambleLen
  );

  if (state != RADIOLIB_ERR_NONE) {
    radioInitialized = false;
    char msg[48];
    snprintf(msg, sizeof(msg), "reinit failed, code=%d", state);
    replyERR(msg);
    return;
  }

  radio.setCRC(config.crcEnabled ? 2 : 0);
  radio.setTCXO(1.8);
  radio.setDio2AsRfSwitch(true);
  radio.setDio1Action(rxInterrupt);
  radio.startReceive();

  radioInitialized = true;
  replyOK("radio reset");
}

// =============================================================================
// Command Dispatcher
// =============================================================================

void processLine() {
  if (lineLen == 0) return;

  lineBuf[lineLen] = '\0';
  stats.cmdCount++;

  // Trim leading whitespace
  char* cmd = lineBuf;
  while (*cmd == ' ') cmd++;

  // Trim trailing whitespace
  int len = strlen(cmd);
  while (len > 0 && (cmd[len-1] == ' ' || cmd[len-1] == '\r' || cmd[len-1] == '\n')) {
    cmd[--len] = '\0';
  }

  if (len == 0) return;

  // Find command and args
  char* args = cmd;
  while (*args && *args != ' ') args++;
  if (*args) {
    *args++ = '\0';
    while (*args == ' ') args++;
  }

  // Dispatch
  if (strcasecmp(cmd, "TX") == 0) {
    cmdTx(args);
  } else if (strcasecmp(cmd, "CFG") == 0) {
    cmdCfg(args);
  } else if (strcasecmp(cmd, "STATUS") == 0) {
    cmdStatus();
  } else if (strcasecmp(cmd, "STATS") == 0) {
    cmdStats();
  } else if (strcasecmp(cmd, "RSSI") == 0) {
    cmdRssi();
  } else if (strcasecmp(cmd, "PROBE") == 0) {
    probeHardware();
  } else if (strcasecmp(cmd, "RESET") == 0) {
    cmdReset();
  } else if (strcasecmp(cmd, "HELP") == 0) {
    cmdHelp();
  } else {
    char msg[48];
    snprintf(msg, sizeof(msg), "unknown command: %s", cmd);
    replyERR(msg);
  }
}

// =============================================================================
// Receive Handler
// =============================================================================

void handleReceive() {
  if (!rxFlag) return;
  rxFlag = false;

  if (!radioInitialized) return;

  ledOn(LED_BLUE);

  int len = radio.getPacketLength();

  if (len <= 0) {
    ledOff(LED_BLUE);
    radio.startReceive();
    return;
  }

  if (len > MAX_PACKET_LEN) {
    stats.rxErrors++;
    Serial.print("# WARNING: packet too long (");
    Serial.print(len);
    Serial.println(" bytes), truncating");
    len = MAX_PACKET_LEN;
  }

  int state = radio.readData(pktBuf, len);

  if (state == RADIOLIB_ERR_NONE) {
    stats.rxCount++;
    stats.rxBytes += len;

    float rssi = radio.getRSSI();
    float snr = radio.getSNR();

    // Output: RX <rssi> <snr> <hex>
    Serial.print("RX ");
    Serial.print(rssi, 1);
    Serial.print(" ");
    Serial.print(snr, 1);
    Serial.print(" ");

    char hexBuf[MAX_PACKET_LEN * 2 + 1];
    hexEncode(pktBuf, len, hexBuf, sizeof(hexBuf));
    Serial.println(hexBuf);

  } else if (state == RADIOLIB_ERR_CRC_MISMATCH) {
    stats.rxErrors++;
    Serial.println("# RX CRC error");
  } else {
    stats.rxErrors++;
    Serial.print("# RX error, code=");
    Serial.println(state);
  }

  ledOff(LED_BLUE);

  // Restart receive
  int rxState = radio.startReceive();
  if (rxState != RADIOLIB_ERR_NONE) {
    Serial.print("# WARNING: startReceive failed, code=");
    Serial.println(rxState);
  }
}

// =============================================================================
// Setup
// =============================================================================

void setup() {
  // LEDs
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_BLUE, OUTPUT);
  ledOff(LED_GREEN);
  ledOff(LED_BLUE);

  // Blink to show we're alive
  for (int i = 0; i < 3; i++) {
    ledOn(LED_GREEN);
    delay(100);
    ledOff(LED_GREEN);
    delay(100);
  }

  // Serial - wait for USB connection
  Serial.begin(115200);
  while (!Serial) delay(10);
  Serial.println("# BOOT: Serial ready");

  // Configure SPI for SX1262 (different pins than default)
  Serial.println("# BOOT: SPI init...");
  SPI.setPins(LORA_MISO, LORA_SCK, LORA_MOSI);
  SPI.begin();
  Serial.println("# BOOT: SPI ready");

  stats.bootTime = millis();

  // Probe hardware
  probeHardware();
}

// =============================================================================
// Main Loop
// =============================================================================

void loop() {
  // Handle serial input (non-blocking)
  while (Serial.available()) {
    char c = Serial.read();

    if (c == '\n' || c == '\r') {
      if (lineLen > 0) {
        processLine();
        lineLen = 0;
      }
    } else if (lineLen < MAX_LINE_LEN) {
      lineBuf[lineLen++] = c;
    } else {
      // Line too long - discard and report error
      replyERR("line too long");
      lineLen = 0;
      // Drain remaining input
      while (Serial.available() && Serial.peek() != '\n') {
        Serial.read();
      }
    }
  }

  // Handle received packets
  handleReceive();
}

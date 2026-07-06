//! APRS-IS gateway translation.
//!
//! Translates between LICHEN Compact CoT (port 5681) and APRS-IS TCP format.
//! APRS-IS servers run on TCP port 14580 with a login/passcode authentication scheme.
//!
//! # APRS Position Format
//!
//! Standard uncompressed position: `!DDMM.mmN/DDDMM.mmW-comment`
//! - `!` = position without timestamp
//! - `DDMM.mm` = degrees and decimal minutes (latitude)
//! - `N`/`S` = hemisphere
//! - `DDDMM.mm` = degrees and decimal minutes (longitude)
//! - `E`/`W` = hemisphere
//! - `-` = symbol (house), `/` = symbol table (primary)
//! - comment = free text (altitude as `/A=NNNNNN` in feet)
//!
//! Full packet: `CALL>APRS,TCPIP*:!DDMM.mmN/DDDMM.mmW-comment\r\n`

use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// APRS-IS default TCP port.
pub const APRS_IS_PORT: u16 = 14580;

/// Compact CoT PLI (Position Location Information) from spec Section 10.1.1.
///
/// Binary encoding:
/// ```text
/// +--------+--------+--------+--------+--------+--------+
/// | subtype| latitude (int32) | longitude (int32)       |
/// +--------+--------+--------+--------+--------+--------+
/// | altitude| course | speed  | team   | role   |
/// | (int16) |(uint16)|(uint16)| (uint8)| (uint8)|
/// +--------+--------+--------+--------+--------+--------+
/// ```
///
/// Total: 18 bytes for full PLI.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactCot {
    /// CoT subtype byte (0x02-0x05 for PLI).
    pub subtype: u8,
    /// Latitude in microdegrees (int32).
    pub lat_microdeg: i32,
    /// Longitude in microdegrees (int32).
    pub lon_microdeg: i32,
    /// Altitude in decimeters (int16).
    pub alt_dm: i16,
    /// Course in centidegrees (0-35999).
    pub course_cdeg: u16,
    /// Speed in cm/s.
    pub speed_cm_s: u16,
    /// Team enum (1=Blue, 2=Red, etc.).
    pub team: u8,
    /// Role enum.
    pub role: u8,
}

/// CoT subtype bytes for PLI.
pub mod subtype {
    /// Friendly ground PLI (a-f-G-*).
    pub const FRIENDLY_GROUND: u8 = 0x02;
    /// Hostile ground (a-h-G-*).
    pub const HOSTILE_GROUND: u8 = 0x03;
    /// Neutral ground (a-n-G-*).
    pub const NEUTRAL_GROUND: u8 = 0x04;
    /// Unknown ground (a-u-G-*).
    pub const UNKNOWN_GROUND: u8 = 0x05;
}

/// Team color enum.
pub mod team {
    pub const BLUE: u8 = 0x01;
    pub const RED: u8 = 0x02;
    pub const GREEN: u8 = 0x03;
    pub const ORANGE: u8 = 0x04;
    pub const MAGENTA: u8 = 0x05;
    pub const MAROON: u8 = 0x06;
    pub const PURPLE: u8 = 0x07;
    pub const TEAL: u8 = 0x08;
    pub const WHITE: u8 = 0x09;
    pub const YELLOW: u8 = 0x0A;
}

impl CompactCot {
    /// Decode from 18-byte PLI wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        let subtype = data[0];
        if !(subtype::FRIENDLY_GROUND..=subtype::UNKNOWN_GROUND).contains(&subtype) {
            return None;
        }
        Some(Self {
            subtype,
            lat_microdeg: i32::from_be_bytes([data[1], data[2], data[3], data[4]]),
            lon_microdeg: i32::from_be_bytes([data[5], data[6], data[7], data[8]]),
            alt_dm: i16::from_be_bytes([data[9], data[10]]),
            course_cdeg: u16::from_be_bytes([data[11], data[12]]),
            speed_cm_s: u16::from_be_bytes([data[13], data[14]]),
            team: data[15],
            role: data[16],
            // data[17] unused/reserved
        })
    }

    /// Encode to 18-byte PLI wire format.
    pub fn to_bytes(&self) -> [u8; 18] {
        let mut out = [0u8; 18];
        out[0] = self.subtype;
        out[1..5].copy_from_slice(&self.lat_microdeg.to_be_bytes());
        out[5..9].copy_from_slice(&self.lon_microdeg.to_be_bytes());
        out[9..11].copy_from_slice(&self.alt_dm.to_be_bytes());
        out[11..13].copy_from_slice(&self.course_cdeg.to_be_bytes());
        out[13..15].copy_from_slice(&self.speed_cm_s.to_be_bytes());
        out[15] = self.team;
        out[16] = self.role;
        out[17] = 0; // reserved
        out
    }

    /// Latitude in decimal degrees.
    pub fn lat_deg(&self) -> f64 {
        self.lat_microdeg as f64 / 1_000_000.0
    }

    /// Longitude in decimal degrees.
    pub fn lon_deg(&self) -> f64 {
        self.lon_microdeg as f64 / 1_000_000.0
    }

    /// Altitude in meters.
    pub fn alt_m(&self) -> f32 {
        self.alt_dm as f32 / 10.0
    }

    /// Altitude in feet (for APRS).
    pub fn alt_ft(&self) -> i32 {
        // 1 decimeter = 0.328084 feet
        (self.alt_dm as i32 * 328084) / 1_000_000
    }
}

/// APRS-IS error type.
#[derive(Debug)]
#[non_exhaustive]
pub enum AprsError {
    Io(io::Error),
    LoginFailed(String),
    ParseError(String),
}

impl From<io::Error> for AprsError {
    fn from(e: io::Error) -> Self {
        AprsError::Io(e)
    }
}

impl std::fmt::Display for AprsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AprsError::Io(e) => write!(f, "I/O error: {}", e),
            AprsError::LoginFailed(msg) => write!(f, "login failed: {}", msg),
            AprsError::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for AprsError {}

/// APRS-IS TCP client.
pub struct AprsIsClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    callsign: String,
}

impl AprsIsClient {
    /// Connect to an APRS-IS server.
    ///
    /// # Arguments
    ///
    /// * `server` - Hostname or IP (e.g., "rotate.aprs2.net")
    /// * `port` - TCP port (typically 14580)
    pub fn connect(server: &str, port: u16) -> Result<Self, AprsError> {
        let addr = format!("{}:{}", server, port);
        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self {
            stream,
            reader,
            callsign: String::new(),
        })
    }

    /// Log into the APRS-IS server.
    ///
    /// # Arguments
    ///
    /// * `callsign` - Amateur radio callsign (e.g., "W1ABC-9")
    /// * `passcode` - APRS-IS passcode (computed from callsign)
    ///
    /// For receive-only access, use passcode -1.
    pub fn login(&mut self, callsign: &str, passcode: i32) -> Result<(), AprsError> {
        // Read server banner
        let mut banner = String::new();
        self.reader.read_line(&mut banner)?;

        // Send login
        let login_cmd = format!(
            "user {} pass {} vers LICHEN 0.1 filter r/0/0/100\r\n",
            callsign, passcode
        );
        self.stream.write_all(login_cmd.as_bytes())?;
        self.stream.flush()?;

        // Read login response
        let mut response = String::new();
        self.reader.read_line(&mut response)?;

        if response.contains("logresp") && response.contains("verified") {
            self.callsign = callsign.to_string();
            Ok(())
        } else if response.contains("logresp") && response.contains("unverified") {
            // Receive-only mode (passcode -1)
            self.callsign = callsign.to_string();
            Ok(())
        } else {
            Err(AprsError::LoginFailed(response))
        }
    }

    /// Send an APRS packet to the server.
    pub fn send(&mut self, packet: &str) -> Result<(), AprsError> {
        let line = if packet.ends_with("\r\n") {
            packet.to_string()
        } else {
            format!("{}\r\n", packet)
        };
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive the next APRS packet from the server.
    ///
    /// Returns None on timeout, Some(packet) on success.
    pub fn recv(&mut self) -> Result<Option<String>, AprsError> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None), // EOF
            Ok(_) => {
                // Skip server comments (lines starting with #)
                if line.starts_with('#') {
                    return Ok(None);
                }
                Ok(Some(line.trim_end().to_string()))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the logged-in callsign.
    pub fn callsign(&self) -> &str {
        &self.callsign
    }
}

/// Convert Compact CoT PLI to APRS position packet.
///
/// # Arguments
///
/// * `callsign` - Source callsign for the APRS packet
/// * `cot` - Compact CoT PLI data
///
/// # Returns
///
/// APRS packet string: `CALL>APRS,TCPIP*:!DDMM.mmN/DDDMM.mmW-/A=NNNNNN`
pub fn cot_to_aprs(callsign: &str, cot: &CompactCot) -> String {
    let lat = cot.lat_deg();
    let lon = cot.lon_deg();

    // Convert to APRS format: DDMM.mm
    let lat_deg = lat.abs().trunc() as u32;
    let lat_min = (lat.abs().fract() * 60.0) as f64;
    let lat_hemi = if lat >= 0.0 { 'N' } else { 'S' };

    let lon_deg = lon.abs().trunc() as u32;
    let lon_min = (lon.abs().fract() * 60.0) as f64;
    let lon_hemi = if lon >= 0.0 { 'E' } else { 'W' };

    // Symbol: / = primary table, - = house (generic position)
    // Could map team/subtype to different symbols in the future
    let symbol_table = '/';
    let symbol_code = '-';

    // Altitude in feet (APRS uses feet)
    let alt_ft = cot.alt_ft();

    // Format: CALL>APRS,TCPIP*:!DDMM.mmN/DDDMM.mmWc/A=NNNNNN
    // where / is symbol table, c is symbol code
    format!(
        "{}>APRS,TCPIP*:!{:02}{:05.2}{}{}{:03}{:05.2}{}{}/A={:06}",
        callsign,
        lat_deg,
        lat_min,
        lat_hemi,
        symbol_table,
        lon_deg,
        lon_min,
        lon_hemi,
        symbol_code,
        alt_ft
    )
}

/// Parse APRS position packet to Compact CoT PLI.
///
/// Supports uncompressed position formats:
/// - `!DDMM.mmN/DDDMM.mmW-comment` (position without timestamp)
/// - `@DDHHMMzDDMM.mmN/DDDMM.mmW-comment` (position with timestamp)
///
/// # Arguments
///
/// * `aprs` - Full APRS packet string
///
/// # Returns
///
/// `Some(CompactCot)` if parsing succeeds, `None` otherwise.
pub fn aprs_to_cot(aprs: &str) -> Option<CompactCot> {
    // Find the data portion (after the last colon)
    let data = aprs.split(':').last()?;

    // Identify position format
    let (pos_data, _has_timestamp) = if data.starts_with('!') || data.starts_with('=') {
        // Position without timestamp
        (&data[1..], false)
    } else if data.starts_with('@') || data.starts_with('/') {
        // Position with timestamp - skip 7 chars (DDHHMMz)
        if data.len() < 8 {
            return None;
        }
        (&data[8..], true)
    } else {
        return None;
    };

    // Need at least 19 chars: DDMM.mmN/DDDMM.mmWc
    if pos_data.len() < 19 {
        return None;
    }

    // Parse latitude: DDMM.mmN
    let lat_str = &pos_data[0..7];
    let lat_hemi = pos_data.chars().nth(7)?;
    let lat_deg: f64 = lat_str[0..2].parse().ok()?;
    let lat_min: f64 = lat_str[2..7].parse().ok()?;
    let mut lat = lat_deg + lat_min / 60.0;
    if lat_hemi == 'S' {
        lat = -lat;
    } else if lat_hemi != 'N' {
        return None;
    }

    // Skip symbol table character (position 8)
    let _symbol_table = pos_data.chars().nth(8)?;

    // Parse longitude: DDDMM.mmW
    let lon_str = &pos_data[9..17];
    let lon_hemi = pos_data.chars().nth(17)?;
    let lon_deg: f64 = lon_str[0..3].parse().ok()?;
    let lon_min: f64 = lon_str[3..8].parse().ok()?;
    let mut lon = lon_deg + lon_min / 60.0;
    if lon_hemi == 'W' {
        lon = -lon;
    } else if lon_hemi != 'E' {
        return None;
    }

    // Parse altitude from comment if present: /A=NNNNNN
    let comment = &pos_data[19..];
    let alt_dm = if let Some(idx) = comment.find("/A=") {
        let alt_str = &comment[idx + 3..];
        let end = alt_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(alt_str.len());
        if end > 0 {
            let alt_ft: i32 = alt_str[..end].parse().ok()?;
            // Convert feet to decimeters: 1 foot = 3.048 decimeters
            ((alt_ft as i64 * 3048) / 1000) as i16
        } else {
            0
        }
    } else {
        0
    };

    Some(CompactCot {
        subtype: subtype::FRIENDLY_GROUND, // Default to friendly
        lat_microdeg: (lat * 1_000_000.0) as i32,
        lon_microdeg: (lon * 1_000_000.0) as i32,
        alt_dm,
        course_cdeg: 0,
        speed_cm_s: 0,
        team: team::BLUE, // Default
        role: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_cot_roundtrip() {
        let cot = CompactCot {
            subtype: subtype::FRIENDLY_GROUND,
            lat_microdeg: 37_774_900, // 37.7749
            lon_microdeg: -122_419_400, // -122.4194
            alt_dm: 1000, // 100m
            course_cdeg: 9000, // 90 degrees
            speed_cm_s: 500, // 5 m/s
            team: team::BLUE,
            role: 1,
        };

        let bytes = cot.to_bytes();
        assert_eq!(bytes.len(), 18);

        let decoded = CompactCot::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn compact_cot_lat_lon_conversion() {
        let cot = CompactCot {
            subtype: subtype::FRIENDLY_GROUND,
            lat_microdeg: 37_774_900,
            lon_microdeg: -122_419_400,
            alt_dm: 1000,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: team::BLUE,
            role: 0,
        };

        assert!((cot.lat_deg() - 37.7749).abs() < 0.0001);
        assert!((cot.lon_deg() - (-122.4194)).abs() < 0.0001);
        assert!((cot.alt_m() - 100.0).abs() < 0.1);
    }

    #[test]
    fn cot_to_aprs_basic() {
        let cot = CompactCot {
            subtype: subtype::FRIENDLY_GROUND,
            lat_microdeg: 49_058_333, // 49.0583333 -> 49 03.50
            lon_microdeg: -72_029_167, // -72.0291667 -> 072 01.75
            alt_dm: 1000, // 100m = 328 feet
            course_cdeg: 0,
            speed_cm_s: 0,
            team: team::BLUE,
            role: 0,
        };

        let aprs = cot_to_aprs("W1TEST-9", &cot);

        // Should contain callsign and APRS path
        assert!(aprs.starts_with("W1TEST-9>APRS,TCPIP*:!"));

        // Should have position data
        assert!(aprs.contains("N/"));
        assert!(aprs.contains("W-"));

        // Should have altitude
        assert!(aprs.contains("/A="));
    }

    #[test]
    fn aprs_to_cot_basic() {
        let aprs = "W1TEST-9>APRS,TCPIP*:!4903.50N/07201.75W-/A=000328";

        let cot = aprs_to_cot(aprs).unwrap();

        // Latitude: 49 degrees 03.50 minutes = 49.0583333
        assert!((cot.lat_deg() - 49.0583333).abs() < 0.001);

        // Longitude: 72 degrees 01.75 minutes = -72.0291667 (West)
        assert!((cot.lon_deg() - (-72.0291667)).abs() < 0.001);

        // Altitude: 328 feet = ~100m = ~1000 decimeters
        assert!(cot.alt_dm > 900 && cot.alt_dm < 1100);
    }

    #[test]
    fn aprs_to_cot_with_timestamp() {
        let aprs = "W1TEST>APRS:@092345z4903.50N/07201.75W-Test station";

        let cot = aprs_to_cot(aprs).unwrap();
        assert!((cot.lat_deg() - 49.0583333).abs() < 0.001);
        assert!((cot.lon_deg() - (-72.0291667)).abs() < 0.001);
    }

    #[test]
    fn aprs_to_cot_southern_hemisphere() {
        let aprs = "VK2TEST>APRS:!3352.00S/15100.00E-Sydney";

        let cot = aprs_to_cot(aprs).unwrap();
        assert!(cot.lat_deg() < 0.0); // South
        assert!(cot.lon_deg() > 0.0); // East
    }

    #[test]
    fn aprs_to_cot_invalid_returns_none() {
        // Not a position packet
        assert!(aprs_to_cot("W1TEST>APRS:>Status message").is_none());

        // Too short
        assert!(aprs_to_cot("W1TEST>APRS:!49").is_none());

        // Invalid hemisphere
        assert!(aprs_to_cot("W1TEST>APRS:!4903.50X/07201.75W-").is_none());
    }

    #[test]
    fn cot_to_aprs_roundtrip() {
        let original = CompactCot {
            subtype: subtype::FRIENDLY_GROUND,
            lat_microdeg: 37_774_900,
            lon_microdeg: -122_419_400,
            alt_dm: 3048, // ~1000 feet
            course_cdeg: 0,
            speed_cm_s: 0,
            team: team::BLUE,
            role: 0,
        };

        let aprs = cot_to_aprs("TEST", &original);
        let recovered = aprs_to_cot(&aprs).unwrap();

        // Position should match within APRS precision (~18m)
        assert!((original.lat_deg() - recovered.lat_deg()).abs() < 0.001);
        assert!((original.lon_deg() - recovered.lon_deg()).abs() < 0.001);

        // Altitude should match within 10%
        let alt_diff = (original.alt_dm as i32 - recovered.alt_dm as i32).abs();
        assert!(alt_diff < 100);
    }

    #[test]
    fn compact_cot_invalid_subtype() {
        let mut data = [0u8; 18];
        data[0] = 0x01; // Chat subtype, not PLI

        assert!(CompactCot::from_bytes(&data).is_none());
    }

    #[test]
    fn compact_cot_too_short() {
        let data = [0u8; 10];
        assert!(CompactCot::from_bytes(&data).is_none());
    }
}

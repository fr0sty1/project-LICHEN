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

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

/// APRS-IS default TCP port.
pub const APRS_IS_PORT: u16 = 14580;

/// Maximum line length accepted from APRS-IS server.
///
/// SECURITY: Bounds memory usage against malicious servers. APRS packets are
/// typically under 256 bytes; 512 provides margin for server comments.
const MAX_LINE_LEN: usize = 512;

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
/// Total: 17 bytes for full PLI (1 byte subtype + 16 bytes payload).
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
    /// Decode from 17-byte PLI wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 17 {
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
        })
    }

    /// Encode to 17-byte PLI wire format.
    pub fn to_bytes(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0] = self.subtype;
        out[1..5].copy_from_slice(&self.lat_microdeg.to_be_bytes());
        out[5..9].copy_from_slice(&self.lon_microdeg.to_be_bytes());
        out[9..11].copy_from_slice(&self.alt_dm.to_be_bytes());
        out[11..13].copy_from_slice(&self.course_cdeg.to_be_bytes());
        out[13..15].copy_from_slice(&self.speed_cm_s.to_be_bytes());
        out[15] = self.team;
        out[16] = self.role;
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
    ///
    /// Uses rounded integer arithmetic. Sub-foot precision is intentionally
    /// lost since APRS position reports use whole feet.
    pub fn alt_ft(&self) -> i32 {
        // 1 decimeter = 0.328084 feet
        // Use i64 intermediate and round to nearest foot (+500000 for rounding)
        ((self.alt_dm as i64 * 328084 + 500000) / 1_000_000) as i32
    }
}

/// APRS-IS error type.
#[derive(Debug)]
#[non_exhaustive]
pub enum AprsError {
    Io(io::Error),
    LoginFailed(String),
    ParseError(String),
    /// Callsign contains invalid characters.
    InvalidCallsign(String),
    /// An inbound APRS-IS line exceeded the wire-size limit.
    LineTooLong {
        limit: usize,
    },
    /// The connection ended after a partial line without a line terminator.
    UnterminatedLine,
}

/// Validate an APRS callsign.
///
/// SECURITY: Callsigns are interpolated into protocol messages sent over TCP.
/// Allowing CR/LF would enable command injection. Only A-Z, 0-9, and hyphen
/// are permitted.
///
/// Valid format: 1-9 characters from [A-Z0-9-], typically like "W1ABC" or "W1ABC-9".
pub fn validate_callsign(callsign: &str) -> Result<(), AprsError> {
    if callsign.is_empty() || callsign.len() > 9 {
        return Err(AprsError::InvalidCallsign(format!(
            "callsign must be 1-9 characters, got {}",
            callsign.len()
        )));
    }
    for c in callsign.chars() {
        if !matches!(c, 'A'..='Z' | '0'..='9' | '-') {
            return Err(AprsError::InvalidCallsign(format!(
                "invalid character '{}' in callsign (only A-Z, 0-9, hyphen allowed)",
                c.escape_default()
            )));
        }
    }
    Ok(())
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
            AprsError::InvalidCallsign(msg) => write!(f, "invalid callsign: {}", msg),
            AprsError::LineTooLong { limit } => {
                write!(f, "APRS-IS line exceeds {limit} bytes")
            }
            AprsError::UnterminatedLine => write!(f, "unterminated APRS-IS line"),
        }
    }
}

impl std::error::Error for AprsError {}

/// Whether the APRS-IS connection is verified for transmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AprsVerification {
    /// Verified with valid passcode — can transmit and receive.
    Verified,
    /// Unverified (passcode -1) — receive-only.
    Unverified,
}

/// APRS-IS TCP client.
pub struct AprsIsClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    callsign: String,
    verification: Option<AprsVerification>,
    poisoned: bool,
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
            verification: None,
            poisoned: false,
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
    ///
    /// # Errors
    ///
    /// Returns `InvalidCallsign` if the callsign contains characters other than
    /// A-Z, 0-9, or hyphen.
    pub fn login(&mut self, callsign: &str, passcode: i32) -> Result<(), AprsError> {
        // SECURITY: Validate callsign to prevent CR/LF injection
        validate_callsign(callsign)?;

        // Read server banner
        let _ = self.read_required_line("missing APRS-IS banner")?;

        // Send login
        let login_cmd = format!(
            "user {} pass {} vers LICHEN 0.1 filter r/0/0/100\r\n",
            callsign, passcode
        );
        self.write_bytes(login_cmd.as_bytes())?;

        // Read login response
        let response = self.read_required_line("missing APRS-IS login response")?;

        if response.contains("logresp") && response.contains("verified") {
            self.callsign = callsign.to_string();
            self.verification = if response.contains("unverified") {
                Some(AprsVerification::Unverified)
            } else {
                Some(AprsVerification::Verified)
            };
            Ok(())
        } else {
            Err(AprsError::LoginFailed(response))
        }
    }

    /// Send an APRS packet to the server.
    pub fn send(&mut self, packet: &str) -> Result<(), AprsError> {
        self.ensure_connected()?;
        let line = if packet.ends_with("\r\n") {
            packet.to_string()
        } else {
            format!("{}\r\n", packet)
        };
        self.write_bytes(line.as_bytes())
    }

    /// Receive the next APRS packet from the server.
    ///
    /// Returns None on timeout or EOF, Some(packet) on success. Server comment
    /// lines (starting with #) are skipped internally — the method loops until
    /// it finds a real packet or hits timeout/EOF.
    ///
    /// # Errors
    ///
    /// Returns `LineTooLong` if a line exceeds [`MAX_LINE_LEN`] bytes or
    /// `UnterminatedLine` for partial lines at EOF. This keeps reads bounded
    /// before allocation against malicious servers or session poisoning.
    pub fn recv(&mut self) -> Result<Option<String>, AprsError> {
        loop {
            match self.read_line()? {
                None => return Ok(None),
                Some(line) => {
                    // Skip server comments (lines starting with #) and continue
                    if line.starts_with('#') {
                        continue;
                    }
                    return Ok(Some(line.trim_end().to_string()));
                }
            }
        }
    }

    fn read_line(&mut self) -> Result<Option<String>, AprsError> {
        self.ensure_connected()?;
        match read_line_bounded(&mut self.reader) {
            Ok(line) => Ok(line),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    fn read_required_line(&mut self, message: &'static str) -> Result<String, AprsError> {
        match self.read_line()? {
            Some(line) => Ok(line),
            None => {
                self.poison();
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, message).into())
            }
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), AprsError> {
        self.ensure_connected()?;
        if let Err(error) = self
            .stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
        {
            self.poison();
            return Err(error.into());
        }
        Ok(())
    }

    fn poison(&mut self) {
        self.poisoned = true;
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn ensure_connected(&self) -> Result<(), AprsError> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "APRS-IS connection is unusable",
            )
            .into());
        }
        Ok(())
    }

    /// Get the logged-in callsign.
    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    /// Get the verification status after login.
    ///
    /// Returns `None` if [`login`](Self::login) has not been called yet.
    /// Returns `Some(Verified)` if the passcode was valid (can transmit).
    /// Returns `Some(Unverified)` if using passcode -1 (receive-only).
    pub fn verification(&self) -> Option<AprsVerification> {
        self.verification
    }

    /// Check if this connection can transmit (is verified).
    pub fn can_transmit(&self) -> bool {
        !self.poisoned && self.verification == Some(AprsVerification::Verified)
    }
}

fn read_line_bounded<R: BufRead>(reader: &mut R) -> Result<Option<String>, AprsError> {
    let mut bytes = Vec::with_capacity(MAX_LINE_LEN + 1);
    let result = reader
        .take((MAX_LINE_LEN + 1) as u64)
        .read_until(b'\n', &mut bytes);

    if let Err(error) = result {
        if bytes.is_empty()
            && matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )
        {
            return Ok(None);
        }
        return Err(error.into());
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_LINE_LEN {
        return Err(AprsError::LineTooLong {
            limit: MAX_LINE_LEN,
        });
    }
    if !bytes.ends_with(b"\n") {
        return Err(AprsError::UnterminatedLine);
    }

    if !bytes.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-ASCII bytes in APRS line",
        )
        .into());
    }

    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
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
///
/// # Errors
///
/// Returns `InvalidCallsign` if the callsign contains characters other than
/// A-Z, 0-9, or hyphen.
pub fn cot_to_aprs(callsign: &str, cot: &CompactCot) -> Result<String, AprsError> {
    // SECURITY: Validate callsign to prevent CR/LF injection
    validate_callsign(callsign)?;

    let lat = cot.lat_deg();
    let lon = cot.lon_deg();

    // Convert to APRS format: DDMM.mm
    let lat_deg = lat.abs().trunc() as u32;
    let lat_min = lat.abs().fract() * 60.0;
    let lat_hemi = if lat >= 0.0 { 'N' } else { 'S' };

    let lon_deg = lon.abs().trunc() as u32;
    let lon_min = lon.abs().fract() * 60.0;
    let lon_hemi = if lon >= 0.0 { 'E' } else { 'W' };

    // Symbol: / = primary table, - = house (generic position)
    // Could map team/subtype to different symbols in the future
    let symbol_table = '/';
    let symbol_code = '-';

    // Altitude in feet (APRS uses feet)
    let alt_ft = cot.alt_ft();

    // Format: CALL>APRS,TCPIP*:!DDMM.mmN/DDDMM.mmWc/A=NNNNNN
    // where / is symbol table, c is symbol code
    Ok(format!(
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
    ))
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
    let data = aprs.split(':').next_back()?;

    // APRS position format is ASCII-only; reject non-ASCII to avoid
    // panics from byte-index slicing on multi-byte UTF-8.
    if !data.is_ascii() {
        return None;
    }

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
        let end = alt_str
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(alt_str.len());
        if end > 0 {
            let alt_ft: i32 = alt_str[..end].parse().ok()?;
            // Convert feet to decimeters: 1 foot = 3.048 decimeters
            // Clamp to i16 range to prevent overflow (i16::MAX = ~10,749 feet)
            let alt_dm_unclamped = (alt_ft as i64 * 3048) / 1000;
            alt_dm_unclamped.clamp(i16::MIN as i64, i16::MAX as i64) as i16
        } else {
            0
        }
    } else {
        0
    };

    Some(CompactCot {
        subtype: subtype::FRIENDLY_GROUND,
        lat_microdeg: (lat * 1_000_000.0).round() as i32,
        lon_microdeg: (lon * 1_000_000.0).round() as i32,
        alt_dm,
        course_cdeg: 0,
        speed_cm_s: 0,
        team: team::BLUE,
        role: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn loopback_client() -> (AprsIsClient, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stream = TcpStream::connect(address).unwrap();
        let server = listener.accept().unwrap().0;
        let reader = BufReader::new(stream.try_clone().unwrap());
        let client = AprsIsClient {
            stream,
            reader,
            callsign: String::new(),
            verification: None,
            poisoned: false,
        };
        (client, server)
    }

    #[test]
    fn bounded_line_accepts_512_wire_bytes() {
        let mut input = vec![b'A'; 511];
        input.push(b'\n');
        assert_eq!(
            read_line_bounded(&mut Cursor::new(input))
                .unwrap()
                .unwrap()
                .len(),
            512
        );
    }

    #[test]
    fn bounded_line_accepts_512_wire_bytes_with_crlf() {
        let mut input = vec![b'A'; 510];
        input.extend_from_slice(b"\r\n");
        assert_eq!(
            read_line_bounded(&mut Cursor::new(input))
                .unwrap()
                .unwrap()
                .len(),
            512
        );
    }

    #[test]
    fn bounded_line_rejects_513_wire_bytes() {
        let mut input = vec![b'A'; 512];
        input.push(b'\n');
        assert!(matches!(
            read_line_bounded(&mut Cursor::new(input)),
            Err(AprsError::LineTooLong { limit: 512 })
        ));
    }

    #[test]
    fn bounded_line_stops_after_513_bytes() {
        let mut input = Cursor::new(vec![b'A'; 4096]);
        assert!(matches!(
            read_line_bounded(&mut input),
            Err(AprsError::LineTooLong { limit: 512 })
        ));
        assert_eq!(input.position(), 513);
    }

    #[test]
    fn bounded_line_rejects_unterminated_eof() {
        assert!(matches!(
            read_line_bounded(&mut Cursor::new(vec![b'A'; 511])),
            Err(AprsError::UnterminatedLine)
        ));
    }

    #[test]
    fn bounded_line_accepts_empty_eof() {
        assert!(read_line_bounded(&mut Cursor::new(Vec::new()))
            .unwrap()
            .is_none());
    }

    #[test]
    fn bounded_line_rejects_invalid_utf8() {
        let error = read_line_bounded(&mut Cursor::new(vec![0xff, b'\n'])).unwrap_err();
        assert!(
            matches!(error, AprsError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn oversized_line_poisons_buffered_connection() {
        let (mut client, mut server) = loopback_client();
        client.verification = Some(AprsVerification::Verified);
        let mut input = vec![b'A'; 512];
        input.extend_from_slice(b"\nVALID\n");
        server.write_all(&input).unwrap();

        assert!(client.can_transmit());
        assert!(matches!(
            client.recv(),
            Err(AprsError::LineTooLong { limit: 512 })
        ));
        assert!(!client.can_transmit());
        assert!(matches!(
            client.recv(),
            Err(AprsError::Io(ref error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            client.send("TEST>APRS:payload"),
            Err(AprsError::Io(ref error)) if error.kind() == io::ErrorKind::NotConnected
        ));
    }

    #[test]
    fn missing_login_response_poisons_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = listener.accept().unwrap().0;
            stream.write_all(b"# banner\n").unwrap();
            let mut command = [0u8; 128];
            let _ = stream.read(&mut command).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let mut client = AprsIsClient::connect("127.0.0.1", address.port()).unwrap();

        assert!(matches!(
            client.login("N0CALL", -1),
            Err(AprsError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert!(matches!(
            client.send("N0CALL>APRS:payload"),
            Err(AprsError::Io(ref error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        server.join().unwrap();
    }

    #[test]
    fn compact_cot_roundtrip() {
        let cot = CompactCot {
            subtype: subtype::FRIENDLY_GROUND,
            lat_microdeg: 37_774_900,   // 37.7749
            lon_microdeg: -122_419_400, // -122.4194
            alt_dm: 1000,               // 100m
            course_cdeg: 9000,          // 90 degrees
            speed_cm_s: 500,            // 5 m/s
            team: team::BLUE,
            role: 1,
        };

        let bytes = cot.to_bytes();
        assert_eq!(bytes.len(), 17);

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
            lat_microdeg: 49_058_333,  // 49.0583333 -> 49 03.50
            lon_microdeg: -72_029_167, // -72.0291667 -> 072 01.75
            alt_dm: 1000,              // 100m = 328 feet
            course_cdeg: 0,
            speed_cm_s: 0,
            team: team::BLUE,
            role: 0,
        };

        let aprs = cot_to_aprs("W1TEST-9", &cot).unwrap();

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

        let aprs = cot_to_aprs("TEST", &original).unwrap();
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

    #[test]
    fn compact_cot_invalid_subtype_at_boundary() {
        let mut data = [0u8; 17];
        data[0] = 0x06; // Invalid subtype (above UNKNOWN_GROUND)
        assert!(CompactCot::from_bytes(&data).is_none());
    }

    #[test]
    fn aprs_to_cot_altitude_overflow_clamped() {
        // 40,000 feet would overflow i16 when converted to decimeters
        // 40000 ft * 3.048 dm/ft = 121920 dm, which exceeds i16::MAX (32767)
        let aprs = "W1TEST-9>APRS,TCPIP*:!4903.50N/07201.75W-/A=040000";
        let cot = aprs_to_cot(aprs).unwrap();
        // Should clamp to i16::MAX instead of overflowing
        assert_eq!(cot.alt_dm, i16::MAX);
    }

    #[test]
    fn validate_callsign_valid() {
        // Valid callsigns
        assert!(validate_callsign("W1ABC").is_ok());
        assert!(validate_callsign("W1ABC-9").is_ok());
        assert!(validate_callsign("VK2TEST").is_ok());
        assert!(validate_callsign("N0CALL").is_ok());
        assert!(validate_callsign("A").is_ok());
        assert!(validate_callsign("123456789").is_ok());
    }

    #[test]
    fn validate_callsign_rejects_crlf() {
        // SECURITY: CR/LF injection must be rejected
        assert!(validate_callsign("W1ABC\r\n").is_err());
        assert!(validate_callsign("W1ABC\n").is_err());
        assert!(validate_callsign("W1ABC\r").is_err());
        assert!(validate_callsign("\nW1ABC").is_err());
    }

    #[test]
    fn validate_callsign_rejects_lowercase() {
        // APRS callsigns are uppercase only
        assert!(validate_callsign("w1abc").is_err());
        assert!(validate_callsign("W1abc").is_err());
    }

    #[test]
    fn validate_callsign_rejects_special_chars() {
        assert!(validate_callsign("W1ABC>APRS").is_err());
        assert!(validate_callsign("W1ABC:test").is_err());
        assert!(validate_callsign("W1ABC,TCPIP").is_err());
        assert!(validate_callsign("W1 ABC").is_err());
    }

    #[test]
    fn validate_callsign_length_limits() {
        // Empty callsign
        assert!(validate_callsign("").is_err());
        // Too long (>9 chars)
        assert!(validate_callsign("W1ABCDEFGH").is_err());
    }

    #[test]
    fn cot_to_aprs_rejects_invalid_callsign() {
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

        // CR/LF injection attempt
        assert!(cot_to_aprs("W1ABC\r\nINJECT", &cot).is_err());
        // Other invalid chars
        assert!(cot_to_aprs("W1ABC>APRS", &cot).is_err());
    }

    #[test]
    fn max_line_len_allows_typical_aprs_packets() {
        const {
            assert!(MAX_LINE_LEN >= 256, "MAX_LINE_LEN too small for APRS");
        }
        const {
            assert!(MAX_LINE_LEN <= 4096, "MAX_LINE_LEN unnecessarily large");
        }

        let typical_packet = "W1TEST-9>APRS,TCPIP*:!4903.50N/07201.75W-Test station /A=000328";
        assert!(
            typical_packet.len() < MAX_LINE_LEN,
            "typical packet should fit within MAX_LINE_LEN"
        );
    }
}

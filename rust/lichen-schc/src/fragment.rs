//! Rule Set Version 2 SCHC ACK-on-Error fragmentation (RFC 8724 section 8).

use lichen_core::error::{BufferTooSmall, TooShort};

pub const FRAGMENT_M: u8 = 1;
pub const FRAGMENT_N: u8 = 6;
pub const FRAGMENT_T: u8 = 0;
pub const ALL_1_FCN: u8 = (1 << FRAGMENT_N) - 1;
pub const MIC_LENGTH: usize = 4;
pub const DEFAULT_WINDOW_SIZE: usize = 32;
pub const MAX_WINDOW_SIZE: usize = 62;
pub const RETRANSMISSION_TIMEOUT_S: u32 = 10;
pub const MAX_ACK_REQUESTS: u8 = 3;
pub const INACTIVITY_TIMEOUT_S: u32 = 60;
pub const TILE_SIZE: usize = 187;
pub const WINDOW_SIZE: usize = 63;
pub const BITMAP_MASK: u64 = (1u64 << WINDOW_SIZE) - 1;
pub const MAX_PACKET_SIZE: usize = 23562;
pub const MAX_SCHC_PACKET: usize = 1281;
pub const RULE_ID_A_TO_B: u8 = 0x78;
pub const RULE_ID_B_TO_A: u8 = 0x79;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FragmentError {
    TooShort(TooShort),
    BufferTooSmall(BufferTooSmall),
    UnsupportedRule,
    InvalidWindow,
    InvalidFcn,
    InvalidTileLength,
    InvalidRcs,
    NonZeroPadding,
    MalformedAck,
    NonCanonicalAck,
    UnassignedBitmapBit,
    EmptyPacket,
    InvalidReceiverLimit,
    PacketTooLarge,
    InvalidState,
}

impl core::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "fragmentation message {e}"),
            Self::BufferTooSmall(e) => write!(f, "fragmentation message {e}"),
            Self::UnsupportedRule => write!(f, "unsupported fragmentation rule"),
            Self::InvalidWindow => write!(f, "invalid window"),
            Self::InvalidFcn => write!(f, "invalid FCN"),
            Self::InvalidTileLength => write!(f, "invalid tile length"),
            Self::InvalidRcs => write!(f, "invalid RCS"),
            Self::NonZeroPadding => write!(f, "non-zero end padding"),
            Self::MalformedAck => write!(f, "malformed ACK or control"),
            Self::NonCanonicalAck => write!(f, "non-canonical compressed ACK"),
            Self::UnassignedBitmapBit => write!(f, "unassigned bitmap bit is set"),
            Self::EmptyPacket => write!(f, "empty packets cannot be fragmented"),
            Self::InvalidReceiverLimit => write!(f, "receiver limit out of range"),
            Self::PacketTooLarge => write!(f, "packet exceeds receiver reassembly limit"),
            Self::InvalidState => write!(f, "invalid fragmentation state"),
        }
    }
}

impl core::error::Error for FragmentError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for FragmentError {
    fn from(value: TooShort) -> Self {
        Self::TooShort(value)
    }
}

impl From<BufferTooSmall> for FragmentError {
    fn from(value: BufferTooSmall) -> Self {
        Self::BufferTooSmall(value)
    }
}

fn check_rule(rule_id: u8) -> Result<(), FragmentError> {
    if matches!(rule_id, RULE_ID_A_TO_B | RULE_ID_B_TO_A) {
        Ok(())
    } else {
        Err(FragmentError::UnsupportedRule)
    }
}

/// CRC-32/ISO-HDLC over the SCHC Packet followed by the All-1 zero pad bit,
/// byte-extended as one zero octet.
pub fn compute_mic(data: &[u8]) -> [u8; MIC_LENGTH] {
    let mut crc = 0xffff_ffffu32;
    for byte in data.iter().copied().chain(core::iter::once(0)) {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    (!crc).to_be_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub rule_id: u8,
    pub window: u8,
    pub fcn: u8,
    pub payload: &'a [u8],
    pub mic: [u8; MIC_LENGTH],
}

impl<'a> Fragment<'a> {
    pub const fn is_all_1(&self) -> bool {
        self.fcn == ALL_1_FCN
    }

    pub const fn is_all_0(&self) -> bool {
        self.fcn == 0
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        check_rule(self.rule_id)?;
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.fcn > ALL_1_FCN {
            return Err(FragmentError::InvalidFcn);
        }
        if self.is_all_1() {
            if !(1..=TILE_SIZE).contains(&self.payload.len()) {
                return Err(FragmentError::InvalidTileLength);
            }
        } else if self.payload.len() != TILE_SIZE || self.mic != [0; MIC_LENGTH] {
            return Err(FragmentError::InvalidTileLength);
        } else if self.window == 1 && self.is_all_0() {
            return Err(FragmentError::InvalidFcn);
        }

        let content_len = self.payload.len() + if self.is_all_1() { MIC_LENGTH } else { 0 };
        let needed = content_len + 2;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[..needed].fill(0);
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << FRAGMENT_N) | (self.fcn & ((1 << FRAGMENT_N) - 1));
        let mut index = 1usize;
        if self.is_all_1() {
            for byte in self.mic {
                out[1 + index] |= byte >> 7;
                out[2 + index] = byte << 1;
                index += 1;
            }
        }
        for &byte in self.payload {
            out[1 + index] |= byte >> 7;
            out[2 + index] = byte << 1;
            index += 1;
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let rule_id = data[0];
        let window = (data[1] >> FRAGMENT_N) & 1;
        let fcn = data[1] & ((1 << FRAGMENT_N) - 1);
        let rest = &data[2..];
        if fcn == ALL_1_FCN {
            if rest.len() < MIC_LENGTH {
                return Err(TooShort::new(2 + MIC_LENGTH, data.len()).into());
            }
            let mut mic = [0u8; MIC_LENGTH];
            mic.copy_from_slice(&rest[..MIC_LENGTH]);
            Ok(Fragment {
                rule_id,
                window,
                fcn,
                payload: &rest[MIC_LENGTH..],
                mic,
            })
        } else {
            Ok(Fragment {
                rule_id,
                window,
                fcn,
                payload: rest,
                mic: [0u8; MIC_LENGTH],
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub rule_id: u8,
    pub window: u8,
    /// Position 0 (FCN 62) is bit 62; position 62 (FCN 0 or All-1) is bit 0.
    pub bitmap: u64,
    pub complete: bool,
}

impl Ack {
    pub fn new(rule_id: u8, window: u8, bitmap: u64, complete: bool) -> Self {
        Self {
            rule_id,
            window,
            bitmap: bitmap & BITMAP_MASK,
            complete,
        }
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        check_rule(self.rule_id)?;
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.complete {
            if self.bitmap != 0 {
                return Err(FragmentError::MalformedAck);
            }
            if out.len() < 2 {
                return Err(BufferTooSmall::new(2, out.len()).into());
            }
            out[0] = self.rule_id;
            out[1] = (self.window << 7) | 0x40;
            return Ok(2);
        }

        let trailing = (self.bitmap & BITMAP_MASK).trailing_ones() as usize;
        let (kept, restored, padding) = if trailing > 0 {
            let kept = WINDOW_SIZE - trailing;
            (kept, (8 - ((2 + kept) % 8)) % 8, 0)
        } else {
            (WINDOW_SIZE, 0, 7)
        };
        let n = kept + restored;
        let total_bits = 2 + n + padding;
        let needed = 1 + total_bits / 8;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[..needed].fill(0);
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << FRAGMENT_N) | (if self.complete { 1 } else { 0 });
        out[2] = n as u8;
        for position in 0..restored {
            set_bit(&mut out[1..needed], 2 + kept + position, true);
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FragmentError> {
        Self::from_bytes_for(data, None)
    }

    pub fn from_bytes_for(data: &[u8], assigned: Option<u64>) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let window = (data[1] >> FRAGMENT_N) & 1;
        let n = data[2] as usize;
        let body_bytes = n.div_ceil(8);
        let required = 3 + body_bytes;
        if data.len() < required {
            return Err(TooShort::new(required, data.len()).into());
        }
        let body = &data[3..];
        let mut bitmap = [false; MAX_WINDOW_SIZE];
        for i in 0..n.min(MAX_WINDOW_SIZE) {
            let byte = body[i / 8];
            bitmap[i] = (byte >> (7 - (i % 8))) & 1 != 0;
        }
        let bit_count = (data.len() - 1) * 8 - 2;
        let mut bitmap = 0u64;
        if bit_count >= WINDOW_SIZE {
            let padding = bit_count - WINDOW_SIZE;
            if padding > 7 || (0..padding).any(|i| get_bit(&data[1..], 2 + WINDOW_SIZE + i)) {
                return Err(FragmentError::MalformedAck);
            }
            for position in 0..WINDOW_SIZE {
                if get_bit(&data[1..], 2 + position) {
                    bitmap |= 1u64 << (62 - position);
                }
            }
        } else {
            for position in 0..bit_count {
                if get_bit(&data[1..], 2 + position) {
                    bitmap |= 1u64 << (62 - position);
                }
            }
            for position in bit_count..WINDOW_SIZE {
                bitmap |= 1u64 << (62 - position);
            }
        }
        let ack = Self::new(data[0], window, bitmap, false);
        let mut canonical = [0u8; 10];
        let length = ack.write_to(&mut canonical)?;
        if &canonical[..length] != data {
            return Err(FragmentError::NonCanonicalAck);
        }
        if assigned.is_some_and(|mask| bitmap & !mask & BITMAP_MASK != 0) {
            return Err(FragmentError::UnassignedBitmapBit);
        }
        Ok(ack)
    }
}

fn set_bit(bytes: &mut [u8], bit: usize, value: bool) {
    if value {
        bytes[bit / 8] |= 1 << (7 - bit % 8);
    }
}

fn get_bit(bytes: &[u8], bit: usize) -> bool {
    bytes[bit / 8] & (1 << (7 - bit % 8)) != 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    AckRequest { rule_id: u8, window: u8 },
    SenderAbort { rule_id: u8 },
    ReceiverAbort { rule_id: u8 },
}

impl Control {
    pub fn write_to(self, out: &mut [u8]) -> Result<usize, FragmentError> {
        let (rule_id, body, needed) = match self {
            Self::AckRequest { rule_id, window } if window <= 1 => (rule_id, window << 7, 2),
            Self::AckRequest { .. } => return Err(FragmentError::InvalidWindow),
            Self::SenderAbort { rule_id } => (rule_id, 0xfe, 2),
            Self::ReceiverAbort { rule_id } => (rule_id, 0xff, 3),
        };
        check_rule(rule_id)?;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = rule_id;
        out[1] = body;
        if needed == 3 {
            out[2] = 0xff;
        }
        Ok(needed)
    }
}

pub const fn ack_request(rule_id: u8, window: u8) -> Control {
    Control::AckRequest { rule_id, window }
}

pub const fn sender_abort(rule_id: u8) -> Control {
    Control::SenderAbort { rule_id }
}

pub const fn receiver_abort(rule_id: u8) -> Control {
    Control::ReceiverAbort { rule_id }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderStatus {
    Ready,
    Active,
    Succeeded,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderOutput {
    None,
    Success,
    Abort {
        written: bool,
    },
    Retransmit {
        window: u8,
        missing: u64,
        position: u8,
        request: bool,
    },
    AckRequest {
        written: bool,
    },
}

#[derive(Debug)]
pub struct FragmentSender<'a> {
    payload: &'a [u8],
    pub rule_id: u8,
    count: usize,
    mic: [u8; MIC_LENGTH],
    attempts: u8,
    status: SenderStatus,
}

impl<'a> FragmentSender<'a> {
    pub fn new(
        payload: &'a [u8],
        rule_id: u8,
        receiver_limit: usize,
    ) -> Result<Self, FragmentError> {
        check_rule(rule_id)?;
        if !(1..=MAX_PACKET_SIZE).contains(&receiver_limit) {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        if payload.is_empty() {
            return Err(FragmentError::EmptyPacket);
        }
        if payload.len() > receiver_limit {
            return Err(FragmentError::PacketTooLarge);
        }
        let mic = compute_mic(payload);
        Ok(FragmentSender {
            payload,
            rule_id,
            count: payload.len().div_ceil(TILE_SIZE),
            mic,
            attempts: 0,
            status: SenderStatus::Ready,
        })
    }

    pub const fn fragment_count(&self) -> usize {
        self.count
    }

    pub const fn window_count(&self) -> usize {
        self.final_window() as usize + 1
    }

    pub const fn final_window(&self) -> u8 {
        ((self.count - 1) / WINDOW_SIZE) as u8
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn status(&self) -> SenderStatus {
        self.status
    }

    pub fn start(&mut self) -> Result<(), FragmentError> {
        if self.status != SenderStatus::Ready {
            return Err(FragmentError::InvalidState);
        }
        self.status = SenderStatus::Active;
        self.attempts = 1;
        Ok(())
    }

    pub fn get_fragment(&self, index: usize) -> Option<Fragment<'a>> {
        if index >= self.count {
            return None;
        }
        let final_fragment = index + 1 == self.count;
        let start = index * TILE_SIZE;
        let end = (start + TILE_SIZE).min(self.payload.len());
        Some(Fragment {
            rule_id: self.rule_id,
            window: (index / WINDOW_SIZE) as u8,
            fcn: if final_fragment {
                ALL_1_FCN
            } else {
                62 - (index % WINDOW_SIZE) as u8
            },
            payload: &self.payload[start..end],
            mic: if final_fragment {
                self.mic
            } else {
                [0; MIC_LENGTH]
            },
        })
    }

    pub fn iter(&self) -> FragmentIter<'_, 'a> {
        FragmentIter {
            sender: self,
            index: 0,
        }
    }

    pub fn assigned_bitmap(&self, window: u8) -> u64 {
        self.iter()
            .filter(|fragment| fragment.window == window)
            .fold(0, |bitmap, fragment| bitmap | fragment_bit(fragment))
    }

    pub fn handle_ack_bytes(&mut self, data: &[u8]) -> Result<SenderOutput, FragmentError> {
        if self.status != SenderStatus::Active || data.first().copied() != Some(self.rule_id) {
            return Ok(SenderOutput::None);
        }
        let mut control = [0u8; 3];
        let abort_len = receiver_abort(self.rule_id).write_to(&mut control)?;
        if data == &control[..abort_len] {
            self.status = SenderStatus::Aborted;
            return Ok(SenderOutput::None);
        }
        let ack = Ack::from_bytes(data)?;
        if ack.complete {
            return Ok(self.handle_ack(ack));
        }
        if ack.window > self.final_window() {
            return Ok(SenderOutput::None);
        }
        let ack = Ack::from_bytes_for(data, Some(self.assigned_bitmap(ack.window)))?;
        Ok(self.handle_ack(ack))
    }

    pub fn handle_ack(&mut self, ack: Ack) -> SenderOutput {
        if self.status != SenderStatus::Active || ack.rule_id != self.rule_id {
            return SenderOutput::None;
        }
        if ack.complete {
            if ack.window != self.final_window() {
                return SenderOutput::None;
            }
            self.status = SenderStatus::Succeeded;
            return SenderOutput::Success;
        }
        if ack.window > self.final_window() {
            return SenderOutput::None;
        }
        let assigned = self.assigned_bitmap(ack.window);
        if ack.bitmap & !assigned & BITMAP_MASK != 0 {
            return SenderOutput::None;
        }
        let missing = assigned & !ack.bitmap;
        if missing == 0 {
            if ack.window == self.final_window() {
                return self.abort_output();
            }
            return SenderOutput::None;
        }
        if self.attempts >= MAX_ACK_REQUESTS {
            return self.abort_output();
        }
        self.attempts += 1;
        let all1_missing = ack.window == self.final_window() && missing & 1 != 0;
        SenderOutput::Retransmit {
            window: ack.window,
            missing,
            position: 0,
            request: !all1_missing,
        }
    }

    pub fn timeout(&mut self) -> Result<SenderOutput, FragmentError> {
        if self.status != SenderStatus::Active {
            return Err(FragmentError::InvalidState);
        }
        if self.attempts >= MAX_ACK_REQUESTS {
            return Ok(self.abort_output());
        }
        self.attempts += 1;
        Ok(SenderOutput::AckRequest { written: false })
    }

    fn abort_output(&mut self) -> SenderOutput {
        self.status = SenderStatus::Aborted;
        SenderOutput::Abort { written: false }
    }

    /// Write the next selected retransmission/control message without allocation.
    pub fn write_next(
        &self,
        output: &mut SenderOutput,
        out: &mut [u8],
    ) -> Result<Option<usize>, FragmentError> {
        match output {
            SenderOutput::None | SenderOutput::Success => Ok(None),
            SenderOutput::Abort { written } => {
                if *written {
                    return Ok(None);
                }
                let length = sender_abort(self.rule_id).write_to(out)?;
                *written = true;
                Ok(Some(length))
            }
            SenderOutput::AckRequest { written } => {
                if self.status != SenderStatus::Active || *written {
                    return Ok(None);
                }
                let length = ack_request(self.rule_id, self.final_window()).write_to(out)?;
                *written = true;
                Ok(Some(length))
            }
            SenderOutput::Retransmit {
                window,
                missing,
                position,
                request,
            } => {
                if self.status != SenderStatus::Active {
                    return Ok(None);
                }
                let mut current = *position;
                while usize::from(current) < WINDOW_SIZE {
                    if *missing & (1u64 << (62 - current)) == 0 {
                        current += 1;
                        continue;
                    }
                    if let Some(fragment) = self.fragment_at_position(*window, current) {
                        let length = fragment.write_to(out)?;
                        *position = current + 1;
                        return Ok(Some(length));
                    }
                    current += 1;
                }
                if *request {
                    let length = ack_request(self.rule_id, self.final_window()).write_to(out)?;
                    *position = WINDOW_SIZE as u8;
                    *request = false;
                    return Ok(Some(length));
                }
                Ok(None)
            }
        }
    }

    fn fragment_at_position(&self, window: u8, position: u8) -> Option<Fragment<'a>> {
        self.iter().find(|fragment| {
            fragment.window == window
                && if fragment.is_all_1() {
                    position == 62
                } else {
                    position == 62 - fragment.fcn
                }
        })
    }
}

fn fragment_bit(fragment: Fragment<'_>) -> u64 {
    if fragment.is_all_1() {
        1
    } else {
        1u64 << fragment.fcn
    }
}

pub struct FragmentIter<'s, 'p> {
    sender: &'s FragmentSender<'p>,
    index: usize,
}

impl<'p> Iterator for FragmentIter<'_, 'p> {
    type Item = Fragment<'p>;

    fn next(&mut self) -> Option<Self::Item> {
        let fragment = self.sender.get_fragment(self.index)?;
        self.index += 1;
        Some(fragment)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverResponse {
    Ack(Ack),
    ReceiverAbort { rule_id: u8 },
}

impl ReceiverResponse {
    pub fn write_to(self, out: &mut [u8]) -> Result<usize, FragmentError> {
        match self {
            Self::Ack(ack) => ack.write_to(out),
            Self::ReceiverAbort { rule_id } => receiver_abort(rule_id).write_to(out),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiverResult {
    pub response: Option<ReceiverResponse>,
    pub packet_len: Option<usize>,
    pub mic_ok: Option<bool>,
    pub aborted: bool,
}

pub struct FragmentReceiver<'a> {
    storage: &'a mut [u8],
    limit: usize,
    rule_id: Option<u8>,
    bitmaps: [u64; 2],
    all1: bool,
    all1_window: u8,
    all1_mic: [u8; MIC_LENGTH],
    final_tile: [u8; TILE_SIZE],
    final_len: usize,
    attempts: u8,
    done: bool,
    packet_len: Option<usize>,
}

impl<'a> FragmentReceiver<'a> {
    pub fn new(storage: &'a mut [u8]) -> Result<Self, FragmentError> {
        let limit = storage.len().min(MAX_PACKET_SIZE);
        if limit == 0 {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        Ok(Self {
            storage,
            limit,
            rule_id: None,
            bitmaps: [0; 2],
            all1: false,
            all1_window: 0,
            all1_mic: [0; MIC_LENGTH],
            final_tile: [0; TILE_SIZE],
            final_len: 0,
            attempts: 0,
            done: false,
            packet_len: None,
        })
    }

    pub fn with_limit(storage: &'a mut [u8], limit: usize) -> Result<Self, FragmentError> {
        if !(1..=MAX_PACKET_SIZE).contains(&limit) || limit > storage.len() {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        let mut receiver = Self::new(storage)?;
        receiver.limit = limit;
        Ok(receiver)
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn is_done(&self) -> bool {
        self.done
    }

    pub fn packet(&self) -> Option<&[u8]> {
        self.packet_len.map(|length| &self.storage[..length])
    }

    pub fn receive_bytes(&mut self, data: &[u8]) -> Result<ReceiverResult, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        check_rule(data[0])?;
        let rule_id = data[0];
        let mut control = [0u8; 3];
        for abort in [sender_abort(rule_id), receiver_abort(rule_id)] {
            let length = abort.write_to(&mut control)?;
            if data == &control[..length] {
                self.release();
                return Ok(ReceiverResult {
                    aborted: true,
                    ..ReceiverResult::default()
                });
            }
        }
        let window = data[1] >> 7;
        let request_len = ack_request(rule_id, window).write_to(&mut control)?;
        if data == &control[..request_len] {
            if self.done {
                self.reset();
            }
            return self.receive_ack_request(rule_id);
        }
        match Fragment::from_bytes(data) {
            Ok(fragment) => {
                if self.done {
                    self.reset();
                }
                Ok(self.receive(&fragment))
            }
            Err(_) if self.done => Ok(ReceiverResult::default()),
            Err(_) => Ok(self.abort(rule_id)),
        }
    }

    pub fn receive(&mut self, fragment: &Fragment<'_>) -> ReceiverResult {
        let valid = check_rule(fragment.rule_id).is_ok()
            && fragment.window <= 1
            && fragment.fcn <= ALL_1_FCN
            && (fragment.is_all_1() || fragment.window == 0 || fragment.fcn != 0)
            && (fragment.is_all_1() && (1..=TILE_SIZE).contains(&fragment.payload.len())
                || !fragment.is_all_1()
                    && fragment.payload.len() == TILE_SIZE
                    && fragment.mic == [0; MIC_LENGTH]);
        if self.done {
            if !valid {
                return ReceiverResult::default();
            }
            self.reset();
        }
        if !valid {
            return self.abort(fragment.rule_id);
        }
        if let Some(active) = self.rule_id {
            if active != fragment.rule_id {
                return self.abort(active);
            }
        } else {
            self.rule_id = Some(fragment.rule_id);
        }

        if fragment.is_all_1() {
            return self.receive_all1(fragment);
        }
        if fragment.window == 1 && fragment.fcn == 0 {
            return self.abort(fragment.rule_id);
        }
        if self.all1
            && (fragment.window > self.all1_window
                || (fragment.window == self.all1_window && fragment.fcn == 0))
        {
            return self.abort(fragment.rule_id);
        }
        let ordinal = usize::from(fragment.window) * WINDOW_SIZE + 62 - usize::from(fragment.fcn);
        let end = (ordinal + 1) * TILE_SIZE;
        if end > self.limit {
            return self.abort(fragment.rule_id);
        }
        let bit = 1u64 << fragment.fcn;
        let bitmap = &mut self.bitmaps[usize::from(fragment.window)];
        let destination = &mut self.storage[ordinal * TILE_SIZE..end];
        if *bitmap & bit != 0 {
            if destination != fragment.payload {
                return self.abort(fragment.rule_id);
            }
            return ReceiverResult::default();
        }
        destination.copy_from_slice(fragment.payload);
        *bitmap |= bit;
        ReceiverResult::default()
    }

    fn receive_all1(&mut self, fragment: &Fragment<'_>) -> ReceiverResult {
        if self
            .bitmaps
            .iter()
            .skip(usize::from(fragment.window) + 1)
            .any(|&b| b != 0)
            || self.bitmaps[usize::from(fragment.window)] & 1 != 0
        {
            return self.abort(fragment.rule_id);
        }
        if self.all1 {
            if self.all1_window != fragment.window
                || self.all1_mic != fragment.mic
                || self.final_tile[..self.final_len] != *fragment.payload
            {
                return self.abort(fragment.rule_id);
            }
            return self.finalize();
        }
        let retained = (self.bitmaps[0].count_ones() + self.bitmaps[1].count_ones()) as usize
            * TILE_SIZE
            + fragment.payload.len();
        if retained > self.limit {
            return self.abort(fragment.rule_id);
        }
        self.all1 = true;
        self.all1_window = fragment.window;
        self.all1_mic = fragment.mic;
        self.final_len = fragment.payload.len();
        self.final_tile[..self.final_len].copy_from_slice(fragment.payload);
        self.finalize()
    }

    fn receive_ack_request(&mut self, rule_id: u8) -> Result<ReceiverResult, FragmentError> {
        if let Some(active) = self.rule_id {
            if active != rule_id {
                return Ok(self.abort(active));
            }
        } else {
            self.rule_id = Some(rule_id);
        }
        if self.all1 {
            return Ok(self.finalize());
        }
        let window = u8::from(self.bitmaps[0] == BITMAP_MASK);
        Ok(self.respond(Ack::new(
            rule_id,
            window,
            self.bitmaps[usize::from(window)],
            false,
        )))
    }

    fn finalize(&mut self) -> ReceiverResult {
        let rule_id = self.rule_id.unwrap_or(RULE_ID_A_TO_B);
        if self.all1_window == 1 && self.bitmaps[0] != BITMAP_MASK {
            return self.respond(Ack::new(rule_id, 0, self.bitmaps[0], false));
        }
        let final_base = usize::from(self.all1_window) * WINDOW_SIZE;
        let bitmap = self.bitmaps[usize::from(self.all1_window)];
        let regular_count = if bitmap == 0 {
            0
        } else {
            WINDOW_SIZE - bitmap.trailing_zeros() as usize
        };
        let required = if regular_count == 0 {
            0
        } else {
            BITMAP_MASK & !(BITMAP_MASK >> regular_count)
        };
        if bitmap & required != required {
            return self.respond(Ack::new(rule_id, self.all1_window, bitmap | 1, false));
        }
        let packet_len = (final_base + regular_count) * TILE_SIZE + self.final_len;
        if packet_len > self.limit {
            return self.abort(rule_id);
        }
        let final_offset = (final_base + regular_count) * TILE_SIZE;
        self.storage[final_offset..packet_len].copy_from_slice(&self.final_tile[..self.final_len]);
        if compute_mic(&self.storage[..packet_len]) == self.all1_mic {
            self.packet_len = Some(packet_len);
            let result = self.respond_with_packet(Ack::new(rule_id, self.all1_window, 0, true));
            self.done = true;
            result
        } else {
            self.respond_with_mic_failure(Ack::new(rule_id, self.all1_window, bitmap | 1, false))
        }
    }

    fn respond(&mut self, ack: Ack) -> ReceiverResult {
        if self.attempts >= MAX_ACK_REQUESTS {
            return self.abort(ack.rule_id);
        }
        self.attempts += 1;
        ReceiverResult {
            response: Some(ReceiverResponse::Ack(ack)),
            ..ReceiverResult::default()
        }
    }

    fn respond_with_packet(&mut self, ack: Ack) -> ReceiverResult {
        let packet_len = self.packet_len;
        let mut result = self.respond(ack);
        if !result.aborted {
            result.packet_len = packet_len;
            result.mic_ok = Some(true);
        }
        result
    }

    fn respond_with_mic_failure(&mut self, ack: Ack) -> ReceiverResult {
        let mut result = self.respond(ack);
        if !result.aborted {
            result.mic_ok = Some(false);
        }
        result
    }

    fn abort(&mut self, rule_id: u8) -> ReceiverResult {
        self.release();
        ReceiverResult {
            response: Some(ReceiverResponse::ReceiverAbort { rule_id }),
            aborted: true,
            ..ReceiverResult::default()
        }
    }

    pub fn expire(&mut self) -> Option<ReceiverResponse> {
        let rule_id = self.rule_id?;
        if self.done {
            return None;
        }
        self.release();
        Some(ReceiverResponse::ReceiverAbort { rule_id })
    }

    pub fn release(&mut self) {
        self.reset();
        self.done = true;
    }

    fn reset(&mut self) {
        self.bitmaps = [0; 2];
        self.all1 = false;
        self.rule_id = None;
        self.final_len = 0;
        self.attempts = 0;
        self.packet_len = None;
        self.done = false;
    }
}

#[derive(Debug)]
pub struct RetransmitIter<'s, 'b> {
    sender: &'s FragmentSender<'s>,
    start: usize,
    end: usize,
    bitmap: &'b [bool],
    pos: usize,
}

impl<'s, 'b> Iterator for RetransmitIter<'s, 'b> {
    type Item = Fragment<'s>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.end {
                return None;
            }
            let abs_pos = self.pos;
            let rel_pos = abs_pos - self.start;
            self.pos += 1;
            let received = rel_pos < self.bitmap.len() && self.bitmap[rel_pos];
            if !received {
                return self.sender.get_fragment(abs_pos);
            }
        }
    }
}

// ─── std-only: all_fragments + FragmentReceiver ───────────────────────────────

#[cfg(feature = "std")]
pub use std_ext::*;

#[cfg(feature = "std")]
mod std_ext {
    extern crate std;
    use std::collections::{HashMap, HashSet};
    use std::vec::Vec;

    use super::*;

    impl<'a> FragmentSender<'a> {
        /// Collect all fragments into a Vec (convenience for tests and sim).
        pub fn all_fragments(&self) -> Vec<Fragment<'a>> {
            self.iter().collect()
        }

        pub fn fragments_in_window_vec(&self, abs_window: usize) -> Vec<Fragment<'a>> {
            self.fragments_in_window(abs_window).collect()
        }
    }

    /// Reassembles a single datagram from ACK-on-Error fragments.
    #[derive(Debug)]
    pub struct FragmentReceiver {
        window_size: usize,
        rule_id: Option<u8>,
        tiles: HashMap<usize, Vec<u8>>,
        current_window: usize,
        completed_windows: HashSet<usize>,
        all1_seen: bool,
        all1_window: usize,
        all1_payload: Vec<u8>,
        mic: [u8; MIC_LENGTH],
        pub done: bool,
        pub reassembled: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ReceiverResult {
        pub ack: Option<Ack>,
        pub reassembled: Option<Vec<u8>>,
        pub mic_ok: Option<bool>,
    }

    impl FragmentReceiver {
        pub fn new(window_size: usize) -> Self {
            FragmentReceiver {
                window_size,
                rule_id: 0,
                tiles: HashMap::new(),
                current_window: 0,
                completed_windows: HashSet::new(),
                all1_seen: false,
                all1_window: 0,
                all1_payload: Vec::new(),
                mic: [0u8; MIC_LENGTH],
                done: false,
                reassembled: None,
            }
        }

        fn abs_window(&self, frag: &Fragment<'_>) -> usize {
            if !frag.is_all_1() {
                let pos = self.window_size - 1 - frag.fcn as usize;
                let parity = frag.window as usize;
                let current_parity = self.current_window % 2;
                let mut older = if parity == current_parity {
                    if self.current_window >= 2 {
                        self.current_window - 2
                    } else {
                        0
                    }
                } else {
                    if self.current_window >= 1 {
                        self.current_window - 1
                    } else {
                        0
                    }
                };
                while older > 0 {
                    if !self.completed_windows.contains(&older) {
                        let older_idx = older * self.window_size + pos;
                        if self.tiles.contains_key(&older_idx) {
                            // duplicate or filled; continue to find gap or treat as current
                        } else {
                            // gap in incomplete older window: likely retransmission
                            return older;
                        }
                    } else if self.tiles.contains_key(&(older * self.window_size + pos)) {
                        return older;
                    }
                    older = older.saturating_sub(2);
                }
            }
            if frag.window == (self.current_window % 2) as u8 {
                self.current_window
            } else {
                self.current_window + 1
            }
        }

        fn window_bitmap(&self, abs_window: usize) -> Vec<bool> {
            let base = abs_window * self.window_size;
            (0..self.window_size)
                .map(|p| self.tiles.contains_key(&(base + p)))
                .collect()
        }

        fn window_full(&self, abs_window: usize) -> bool {
            let base = abs_window * self.window_size;
            (0..self.window_size).all(|p| self.tiles.contains_key(&(base + p)))
        }

        pub fn receive(&mut self, frag: &Fragment<'_>) -> ReceiverResult {
            if self.done {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            if self.rule_id == 0 {
                self.rule_id = frag.rule_id;
            } else if self.rule_id != frag.rule_id {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            let abs_window = self.abs_window(frag);
            if self.completed_windows.contains(&abs_window) {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            if abs_window > self.current_window {
                self.current_window = abs_window;
            }

            if frag.is_all_1() {
                self.all1_seen = true;
                self.all1_window = abs_window;
                self.all1_payload = frag.payload.to_vec();
                self.mic = frag.mic;
                return self.finalize();
            }

            if frag.fcn as usize >= self.window_size {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            let pos = self.window_size - 1 - frag.fcn as usize;
            let global_idx = abs_window * self.window_size + pos;
            if !self.tiles.contains_key(&global_idx) {
                self.tiles.insert(global_idx, frag.payload.to_vec());
            }

            if self.all1_seen {
                return self.finalize();
            }

            if frag.is_all_0() || self.window_full(abs_window) {
                let bitmap = self.window_bitmap(abs_window);
                if self.window_full(abs_window) {
                    self.completed_windows.insert(abs_window);
                    self.current_window = abs_window + 1;
                }
                return ReceiverResult {
                    ack: Some(Ack::new(
                        self.rule_id,
                        (abs_window % 2) as u8,
                        &bitmap,
                        false,
                    )),
                    reassembled: None,
                    mic_ok: None,
                };
            }
            ReceiverResult {
                ack: None,
                reassembled: None,
                mic_ok: None,
            }
        }

        fn finalize(&mut self) -> ReceiverResult {
            let bitmap = self.window_bitmap(self.all1_window);
            let nack = Ack::new(self.rule_id, (self.all1_window % 2) as u8, &bitmap, false);

            // O(n) contiguity check: if we have n tiles and max index is n-1,
            // all indices 0..n must be present (HashMap keys are unique).
            let n = self.tiles.len();
            let contiguous = n > 0 && self.tiles.keys().max() == Some(&(n - 1));
            if !contiguous {
                return ReceiverResult {
                    ack: Some(nack),
                    reassembled: None,
                    mic_ok: None,
                };
            }

            let mut data: Vec<u8> = Vec::new();
            for i in 0..n {
                data.extend_from_slice(self.tiles[&i].as_slice());
            }
            data.extend_from_slice(&self.all1_payload);

            if compute_mic(&data) == self.mic {
                self.done = true;
                self.reassembled = Some(data.clone());
                ReceiverResult {
                    ack: Some(Ack::new(
                        self.rule_id,
                        (self.all1_window % 2) as u8,
                        &bitmap,
                        true,
                    )),
                    reassembled: Some(data),
                    mic_ok: Some(true),
                }
            } else {
                ReceiverResult {
                    ack: Some(nack),
                    reassembled: None,
                    mic_ok: Some(false),
                }
            }
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_includes_zero_octet() {
        assert_eq!(compute_mic(b"123456789"), [0x00, 0xc4, 0x9e, 0x49]);
    }

    #[test]
    fn literal_regular_fragment() {
        let tile = [0u8; TILE_SIZE];
        let fragment = Fragment {
            rule_id: 0x78,
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; MIC_LENGTH],
        };
        let mut wire = [0xff; TILE_SIZE + 2];
        assert_eq!(fragment.write_to(&mut wire), Ok(wire.len()));
        assert_eq!(&wire[..2], &[0x78, 0x7c]);
        assert!(wire[2..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn literal_ack_and_controls() {
        let ack = Ack::new(0x78, 1, 0, true);
        let mut wire = [0; 10];
        assert_eq!(ack.write_to(&mut wire), Ok(2));
        assert_eq!(&wire[..2], &[0x78, 0xc0]);
        assert_eq!(sender_abort(0x78).write_to(&mut wire), Ok(2));
        assert_eq!(&wire[..2], &[0x78, 0xfe]);
        assert_eq!(receiver_abort(0x78).write_to(&mut wire), Ok(3));
        assert_eq!(&wire[..3], &[0x78, 0xff, 0xff]);
    }
}

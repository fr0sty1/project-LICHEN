// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! SimRadio TCP client for LICHEN simulator.
//!
//! Connects to the Python simulator over TCP and implements the Radio trait.
//! Uses 4-byte LE length-prefix framing.

use crate::{ChannelConfig, Radio, RadioConfig, RadioError, RxPacket};
use std::io::{Read, Write};
use std::net::TcpStream;

// Wire protocol message types (from python/src/lichen/sim/protocol.py)
const MSG_OK: u8 = 0x00;
const MSG_REGISTER: u8 = 0x01;
const MSG_TX: u8 = 0x10;
const MSG_TX_DONE: u8 = 0x11;
const MSG_TX_FAIL: u8 = 0x12;
const MSG_RX_ENTER: u8 = 0x24;
const MSG_RX_PACKET: u8 = 0x27;
const MSG_RX_TIMEOUT_PUSH: u8 = 0x28;
const MSG_CAD: u8 = 0x40;
const MSG_CAD_RESULT: u8 = 0x41;
const MSG_ERR: u8 = 0xFF;

type SimError = RadioError<std::io::Error>;

/// SimRadio TCP client connected to the LICHEN simulator.
pub struct SimRadio {
    stream: TcpStream,
    config: RadioConfig,
}

impl SimRadio {
    /// Connect to simulator and register node.
    pub fn connect(
        addr: &str,
        sim_id: &str,
        node_id: &str,
        position: (f64, f64, f64),
    ) -> Result<Self, SimError> {
        let stream = TcpStream::connect(addr).map_err(RadioError::Bus)?;
        let mut radio = Self {
            stream,
            config: RadioConfig::default(),
        };
        radio.register(sim_id, node_id, position)?;
        Ok(radio)
    }

    fn register(
        &mut self,
        sim_id: &str,
        node_id: &str,
        (x, y, z): (f64, f64, f64),
    ) -> Result<(), SimError> {
        let sim_bytes = sim_id.as_bytes();
        let node_bytes = node_id.as_bytes();
        let mut msg = Vec::with_capacity(1 + 2 + sim_bytes.len() + node_bytes.len() + 24);
        msg.push(MSG_REGISTER);
        msg.push(sim_bytes.len() as u8);
        msg.extend_from_slice(sim_bytes);
        msg.push(node_bytes.len() as u8);
        msg.extend_from_slice(node_bytes);
        msg.extend_from_slice(&x.to_le_bytes());
        msg.extend_from_slice(&y.to_le_bytes());
        msg.extend_from_slice(&z.to_le_bytes());

        self.send_msg(&msg)?;
        let resp = self.recv_msg()?;
        if resp.first() == Some(&MSG_OK) {
            Ok(())
        } else {
            Err(RadioError::Protocol)
        }
    }

    fn send_msg(&mut self, data: &[u8]) -> Result<(), SimError> {
        let len = (data.len() as u32).to_le_bytes();
        self.stream.write_all(&len).map_err(RadioError::Bus)?;
        self.stream.write_all(data).map_err(RadioError::Bus)?;
        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Vec<u8>, SimError> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(RadioError::Bus)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).map_err(RadioError::Bus)?;
        Ok(buf)
    }
}

impl Radio for SimRadio {
    type Error = SimError;

    async fn transmit(&mut self, channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        // Format: MSG_TX(1) + len(2, LE) + channel(1) + payload
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.push(MSG_TX);
        msg.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        msg.push(channel);
        msg.extend_from_slice(payload);

        self.send_msg(&msg)?;

        let resp = self.recv_msg()?;
        match resp.first() {
            Some(&MSG_TX_DONE) => Ok(()),
            Some(&MSG_TX_FAIL) | Some(&MSG_ERR) => Err(RadioError::Hardware),
            _ => Err(RadioError::Protocol),
        }
    }

    async fn cca(&mut self, channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        // Format: MSG_CAD(1) + timeout_ms(4, LE) + channel(1)
        let mut msg = [0u8; 6];
        msg[0] = MSG_CAD;
        msg[1..5].copy_from_slice(&100u32.to_le_bytes()); // 100ms timeout
        msg[5] = channel;

        self.send_msg(&msg)?;

        let resp = self.recv_msg()?;
        match (resp.first(), resp.get(1)) {
            (Some(&MSG_CAD_RESULT), Some(&detected)) => Ok(detected == 0), // clear if not detected
            _ => Err(RadioError::Protocol),
        }
    }

    async fn receive(
        &mut self,
        channel: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        // Format: MSG_RX_ENTER(1) + timeout_us(4, LE) + channel(1)
        let timeout_us = timeout_ms.saturating_mul(1000);
        let mut msg = [0u8; 6];
        msg[0] = MSG_RX_ENTER;
        msg[1..5].copy_from_slice(&timeout_us.to_le_bytes());
        msg[5] = channel;

        self.send_msg(&msg)?;

        let resp = self.recv_msg()?;
        match resp.first() {
            Some(&MSG_RX_PACKET) => {
                if resp.len() < 7 {
                    return Err(RadioError::Protocol);
                }
                let payload_len = u16::from_le_bytes([resp[1], resp[2]]) as usize;
                if resp.len() < 3 + payload_len + 4 {
                    return Err(RadioError::Protocol);
                }
                if payload_len > buf.len() {
                    return Err(RadioError::Protocol);
                }
                buf[..payload_len].copy_from_slice(&resp[3..3 + payload_len]);
                let rssi_off = 3 + payload_len;
                let rssi = i16::from_le_bytes([resp[rssi_off], resp[rssi_off + 1]]);
                let snr = i16::from_le_bytes([resp[rssi_off + 2], resp[rssi_off + 3]]);
                Ok(Some(RxPacket {
                    len: payload_len,
                    rssi: Some(rssi),
                    snr: Some(snr as i8),
                }))
            }
            Some(&MSG_RX_TIMEOUT_PUSH) => Ok(None),
            Some(&MSG_ERR) => Err(RadioError::Hardware),
            _ => Err(RadioError::Protocol),
        }
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
    }

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Ok(())
    }
}

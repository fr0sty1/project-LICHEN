-- SPDX-License-Identifier: GPL-3.0-or-later
-- SPDX-FileCopyrightText: The contributors to the LICHEN project
--
-- lichen.lua — Wireshark Lua dissector for LICHEN link-layer frames
--
-- Decodes LICHEN link-layer frames (spec section 4) captured in pcapng
-- files written by lichen.sim.pcap (LINKTYPE_USER0 / DLT 147). Also
-- handles Custom EPB options (RSSI, SNR, SRC_NODE, DST_NODE).
--
-- Frame wire layout (spec 4.1):
--   +--------+--------+-------+--------+----------+---------+--------+
--   | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload | MIC    |
--   +--------+--------+-------+--------+----------+---------+--------+
--      1B       1B       1B      2B       0/2/8B     var      4/8B
--
-- LLSec byte (spec 4.2), LSB first:
--   bits 0-1  Addr Mode  (0=none/broadcast, 1=16-bit, 2=EUI-64, 3=elided)
--   bits 2-4  MIC Length (0=32-bit/4B, 1=64-bit/8B)
--   bit  5    Signature present (Ed25519)
--   bit  6    Encrypted (AES-CCM)
--   bit  7    Reserved (must be 0)
--
-- Installation:
--   Copy to ~/.config/wireshark/ (Linux/macOS) or %APPDATA%\Wireshark\ (Windows)
--   then restart Wireshark or use Tools → Reload Lua Plugins.

local lichen_proto = Proto("lichen", "LICHEN LoRa Link Frame")

-- -----------------------------------------------------------------------
-- Protocol fields
-- -----------------------------------------------------------------------

-- Top-level frame fields
local f_length   = ProtoField.uint8 ("lichen.length",   "Frame Length",    base.DEC)
local f_llsec    = ProtoField.uint8 ("lichen.llsec",    "LLSec Flags",     base.HEX)
local f_epoch    = ProtoField.uint8 ("lichen.epoch",    "Epoch",           base.DEC)
local f_seqnum   = ProtoField.uint16("lichen.seqnum",   "SeqNum",          base.DEC)
local f_dst_addr = ProtoField.bytes ("lichen.dst_addr", "Dst Addr")
local f_payload  = ProtoField.bytes ("lichen.payload",  "SCHC Payload")
local f_mic      = ProtoField.bytes ("lichen.mic",      "MIC")

-- LLSec sub-fields (displayed inside the LLSec tree node)
local f_addr_mode = ProtoField.uint8("lichen.llsec.addr_mode",   "Addr Mode",          base.DEC, {
    [0] = "None (broadcast)",
    [1] = "Short (16-bit)",
    [2] = "Extended (EUI-64)",
    [3] = "Elided (from IPv6 dst)",
}, 0x03)
local f_mic_len   = ProtoField.uint8("lichen.llsec.mic_len",     "MIC Length",         base.DEC, {
    [0] = "32-bit (4 bytes)",
    [1] = "64-bit (8 bytes)",
}, 0x1C)
local f_sig_pres  = ProtoField.bool ("lichen.llsec.sig",         "Signature Present",  8, nil, 0x20)
local f_encrypted = ProtoField.bool ("lichen.llsec.encrypted",   "Encrypted (AES-CCM)", 8, nil, 0x40)

-- Radio metadata from custom EPB options (shown separately)
local f_rssi     = ProtoField.int32 ("lichen.rssi",     "RSSI",            base.DEC)
local f_snr      = ProtoField.int32 ("lichen.snr",      "SNR",             base.DEC)
local f_src_node = ProtoField.string("lichen.src_node", "Source Node")
local f_dst_node = ProtoField.string("lichen.dst_node", "Destination Node")

lichen_proto.fields = {
    f_length, f_llsec, f_epoch, f_seqnum, f_dst_addr, f_payload, f_mic,
    f_addr_mode, f_mic_len, f_sig_pres, f_encrypted,
    f_rssi, f_snr, f_src_node, f_dst_node,
}

-- -----------------------------------------------------------------------
-- Address mode helpers
-- -----------------------------------------------------------------------

local ADDR_LEN = { [0]=0, [1]=2, [2]=8, [3]=0 }
local ADDR_NAME = { [0]="broadcast", [1]="short", [2]="eui64", [3]="elided" }
local MIC_LEN   = { [0]=4, [1]=8 }

-- -----------------------------------------------------------------------
-- Dissector
-- -----------------------------------------------------------------------

function lichen_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("LICHEN")

    local buf_len = buffer:len()
    if buf_len < 1 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Frame too short (0 bytes)")
        return
    end

    local subtree = tree:add(lichen_proto, buffer(), "LICHEN LoRa Link Frame")

    -- Length byte
    local length = buffer(0, 1):uint()
    subtree:add(f_length, buffer(0, 1)):append_text(" (body bytes)")

    if buf_len < length + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
            string.format("Buffer truncated: need %d body bytes, have %d", length, buf_len - 1))
        return
    end

    -- Minimum body: LLSec(1) + Epoch(1) + SeqNum(2) = 4
    if length < 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
            string.format("Body too short: %d bytes (need >= 4)", length))
        return
    end

    -- LLSec byte
    local llsec_val = buffer(1, 1):uint()
    local llsec_tree = subtree:add(f_llsec, buffer(1, 1))
    llsec_tree:add(f_addr_mode,  buffer(1, 1))
    llsec_tree:add(f_mic_len,    buffer(1, 1))
    llsec_tree:add(f_sig_pres,   buffer(1, 1))
    llsec_tree:add(f_encrypted,  buffer(1, 1))

    if bit.band(llsec_val, 0x80) ~= 0 then
        llsec_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Reserved bit 7 is set")
    end

    local addr_mode = bit.band(llsec_val, 0x03)
    local mic_field = bit.band(bit.rshift(llsec_val, 2), 0x07)
    local sig_pres  = bit.band(llsec_val, 0x20) ~= 0
    local encrypted = bit.band(llsec_val, 0x40) ~= 0

    if mic_field > 1 then
        subtree:add_expert_info(PI_PROTOCOL, PI_WARN,
            string.format("Reserved MIC-length value: %d", mic_field))
        return
    end

    local addr_len = ADDR_LEN[addr_mode]
    local mic_len  = MIC_LEN[mic_field]

    -- Epoch
    subtree:add(f_epoch, buffer(2, 1))

    -- SeqNum (big-endian)
    subtree:add(f_seqnum, buffer(3, 2))

    local offset = 5  -- 1 (Length) + 1 (LLSec) + 1 (Epoch) + 2 (SeqNum)

    -- Sanity check remaining space
    if buf_len < offset + addr_len + mic_len then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
            string.format("Frame too short for Dst Addr (%d B) + MIC (%d B)", addr_len, mic_len))
        return
    end

    -- Dst Addr
    if addr_len > 0 then
        local addr_item = subtree:add(f_dst_addr, buffer(offset, addr_len))
        if addr_mode == 1 then
            -- 16-bit short address: format as 0x0042
            addr_item:append_text(string.format(" (0x%04X)", buffer(offset, 2):uint()))
        elseif addr_mode == 2 then
            -- EUI-64: format as xx:xx:xx:xx:xx:xx:xx:xx
            local bytes = {}
            for i = 0, 7 do
                bytes[i+1] = string.format("%02X", buffer(offset + i, 1):uint())
            end
            addr_item:append_text(" (" .. table.concat(bytes, ":") .. ")")
        end
        offset = offset + addr_len
    else
        if addr_mode == 0 then
            subtree:add_expert_info(PI_COMMENT, PI_NOTE, "Dst: broadcast")
        else
            subtree:add_expert_info(PI_COMMENT, PI_NOTE, "Dst: elided (from IPv6 destination)")
        end
    end

    -- SCHC Payload (everything between addr and MIC)
    local payload_end = 1 + length - mic_len  -- absolute offset in buffer
    local payload_len = payload_end - offset
    if payload_len > 0 then
        subtree:add(f_payload, buffer(offset, payload_len))
    end
    offset = payload_end

    -- MIC
    subtree:add(f_mic, buffer(offset, mic_len)):append_text(
        string.format(" (%d-bit)", mic_len * 8))

    -- Summary column
    local flags = {}
    if sig_pres  then flags[#flags+1] = "SIG"  end
    if encrypted then flags[#flags+1] = "ENC"  end
    local flag_str = #flags > 0 and (" [" .. table.concat(flags, ",") .. "]") or ""

    pinfo.cols.info:set(string.format(
        "LICHEN  ep=%d seq=%d  dst=%s  %dB payload%s",
        buffer(2,1):uint(),
        buffer(3,2):uint(),
        ADDR_NAME[addr_mode],
        payload_len > 0 and payload_len or 0,
        flag_str
    ))
end

-- -----------------------------------------------------------------------
-- Register for LINKTYPE_USER0 (DLT 147)
-- -----------------------------------------------------------------------

local wtap_encap_table = DissectorTable.get("wtap_encap")
if wtap_encap_table then
    wtap_encap_table:add(wtap.USER0, lichen_proto)
end

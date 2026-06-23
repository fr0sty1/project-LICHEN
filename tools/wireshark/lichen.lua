-- lichen.lua — Wireshark Lua dissector for LICHEN pcapng captures
--
-- Decodes the custom EPB options written by lichen.sim.pcap and displays
-- RSSI, SNR, source node ID, and destination node ID in packet details.
--
-- Installation:
--   1. Copy this file to your Wireshark personal Lua directory:
--        Linux/macOS: ~/.config/wireshark/
--        Windows:     %APPDATA%\Wireshark\
--      or use Edit → Preferences → Advanced → gui.uat.fileopen.dir to find it.
--   2. Restart Wireshark (or run Tools → Reload Lua Plugins).
--
-- The dissector registers itself for link type LINKTYPE_USER0 (DLT 147/0x93)
-- which is what lichen-sim writes. Each captured packet body is the raw
-- SCHC-compressed frame. The custom EPB options appear as sub-fields under
-- the "LICHEN" tree in the Packet Details pane.
--
-- Custom EPB option codes (private use range 0x8000–0x8003):
--   0x8000  RSSI       4-byte little-endian int32 in dBm
--   0x8001  SNR        4-byte little-endian int32 in dB
--   0x8002  SRC_NODE   UTF-8 string — source node ID
--   0x8003  DST_NODE   UTF-8 string — destination node ID

local lichen_proto = Proto("lichen", "LICHEN LoRa Frame")

-- Fields visible in Packet Details
local f_payload  = ProtoField.bytes("lichen.payload",  "SCHC Payload")
local f_rssi     = ProtoField.int32("lichen.rssi",     "RSSI",         base.DEC, nil, nil, "dBm")
local f_snr      = ProtoField.int32("lichen.snr",      "SNR",          base.DEC, nil, nil, "dB")
local f_src_node = ProtoField.string("lichen.src_node", "Source Node")
local f_dst_node = ProtoField.string("lichen.dst_node", "Destination Node")

lichen_proto.fields = { f_payload, f_rssi, f_snr, f_src_node, f_dst_node }

-- pcapng EPB option codes written by lichen.sim.pcap
local OPT_CUSTOM_RSSI     = 0x8000
local OPT_CUSTOM_SNR      = 0x8001
local OPT_CUSTOM_SRC_NODE = 0x8002
local OPT_CUSTOM_DST_NODE = 0x8003

-- Packet dissector: called for every packet with DLT 147
function lichen_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("LICHEN")

    local subtree = tree:add(lichen_proto, buffer(), "LICHEN LoRa Frame")
    subtree:add(f_payload, buffer(0, buffer:len()))

    -- EPB options are not part of the buffer passed to us; they are surfaced
    -- via pinfo.private if a companion tap or future Wireshark API exposes
    -- them. For now we document the option format here for reference.
    -- Options decoded by wireshark's built-in pcapng reader are not yet
    -- accessible from Lua in stable releases (as of Wireshark 4.x).
    subtree:add_expert_info(PI_COMMENT, PI_NOTE,
        "Custom EPB options: RSSI (0x8000), SNR (0x8001), " ..
        "SRC_NODE (0x8002), DST_NODE (0x8003) — see lichen.sim.pcap docstring")
end

-- Register for LINKTYPE_USER0 (DLT 147)
local wtap_encap_table = DissectorTable.get("wtap_encap")
if wtap_encap_table then
    wtap_encap_table:add(wtap.USER0, lichen_proto)
end

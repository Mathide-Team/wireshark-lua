-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/flxo/nng-wireshark-dissector (nng.lua),
-- commit ca594eb9113100b39ca8502748b8d95be0babe1a du 07/04/2026.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- NNG (nanomsg next-generation) SP protocol dissector for Wireshark
-- Covers the TCP and UDP transport wire protocols as defined in:
-- https://github.com/nanomsg/nng
--
-- TCP wire format:
--   Handshake (8 bytes each direction):
--     [0x00] ['S'] ['P'] [0x00] [proto_hi] [proto_lo] [0x00] [0x00]
--   Data frames:
--     [8-byte big-endian length] [SP header] [body]
--     length = header_len + body_len
--
-- UDP wire format (experimental transport):
--   All packets have an 8-byte header (little-endian):
--     [ver: u8 = 0x01] [opcode: u8] [type: u16 LE] [params: 2x u16 LE]
--   Opcodes:
--     0 = DATA   params[0] = payload length
--     1 = CREQ   params[0] = recvmax, params[1] = refresh (seconds)
--     2 = CACK   params[0] = recvmax, params[1] = refresh (seconds)
--     3 = DISC   params[0] = reason
--     4 = MESH
--   DATA payload: [SP header][body] (same SP header format as TCP)
--
-- SP header format per protocol (precedes body in payload):
--   REQ (0x30):          [request_id: u32, high bit set]
--   REP (0x31):          [hop0: u32]...[request_id: u32, high bit set]
--   SURVEYOR (0x62):     [survey_id: u32, high bit set]
--   RESPONDENT (0x63):   [hop0: u32]...[survey_id: u32, high bit set]
--   PAIR1 (0x11):        [hop_count: u32]
--   PAIR0/BUS/PUB/SUB/PUSH/PULL: (empty)
--
-- Protocol IDs use NNI_PROTO(major, minor) = major * 16 + minor

local nng = Proto("nng", "NNG SP Protocol")

-- ---------------------------------------------------------------------------
-- Protocol ID table
-- ---------------------------------------------------------------------------
local proto_names = {
    [0x10] = "pair v0",
    [0x11] = "pair v1",
    [0x20] = "pub v0",
    [0x21] = "sub v0",
    [0x30] = "req v0",
    [0x31] = "rep v0",
    [0x50] = "push v0",
    [0x51] = "pull v0",
    [0x62] = "surveyor v0",
    [0x63] = "respondent v0",
    [0x70] = "bus v0",
}

-- UDP opcodes
local UDP_OPCODE_DATA = 0
local UDP_OPCODE_CREQ = 1
local UDP_OPCODE_CACK = 2
local UDP_OPCODE_DISC = 3
local UDP_OPCODE_MESH = 4

local udp_opcode_names = {
    [UDP_OPCODE_DATA] = "DATA",
    [UDP_OPCODE_CREQ] = "CREQ",
    [UDP_OPCODE_CACK] = "CACK",
    [UDP_OPCODE_DISC] = "DISC",
    [UDP_OPCODE_MESH] = "MESH",
}

local udp_disc_reasons = {
    [0] = "Closed",
    [1] = "Bad SP type",
    [3] = "Refused",
    [4] = "Message too large",
    [5] = "Negotiation failed",
    [6] = "Inactive",
    [7] = "Protocol error",
    [8] = "Resources exhausted",
}

-- Header type per protocol
local HEADER_BACKTRACE = 1  -- REQ/REP, SURVEY/RESPONDENT
local HEADER_HOP_COUNT = 2  -- PAIR1

local header_type = {
    [0x30] = HEADER_BACKTRACE,  -- req
    [0x31] = HEADER_BACKTRACE,  -- rep
    [0x62] = HEADER_BACKTRACE,  -- surveyor
    [0x63] = HEADER_BACKTRACE,  -- respondent
    [0x11] = HEADER_HOP_COUNT,  -- pair v1
}

-- Whether a backtrace protocol uses "Survey ID" vs "Request ID"
local is_survey = {
    [0x62] = true,
    [0x63] = true,
}

-- ---------------------------------------------------------------------------
-- Header fields
-- ---------------------------------------------------------------------------
local f_hs_magic   = ProtoField.bytes("nng.hs.magic",     "Magic",          base.SPACE)
local f_hs_proto   = ProtoField.uint16("nng.hs.proto",    "Protocol ID",    base.HEX, proto_names)
local f_hs_rsvd    = ProtoField.uint16("nng.hs.rsvd",     "Reserved",       base.HEX)

local f_msg_len    = ProtoField.uint64("nng.msg.len",      "Message Length", base.DEC)
local f_msg_data   = ProtoField.bytes("nng.msg.data",      "Message Data",   base.SPACE)

-- Backtrace fields (REQ/REP, SURVEY/RESPONDENT)
local f_bt_hop     = ProtoField.uint32("nng.hdr.hop",      "Backtrace Hop",  base.HEX)
local f_req_id     = ProtoField.uint32("nng.hdr.reqid",    "Request ID",     base.HEX)
local f_surv_id    = ProtoField.uint32("nng.hdr.survid",   "Survey ID",      base.HEX)

-- PAIR1 hop count
local f_hop_count  = ProtoField.uint32("nng.hdr.hopcount", "Hop Count",      base.DEC)

local f_body       = ProtoField.bytes("nng.msg.body",      "Body",           base.SPACE)

-- UDP transport fields
local f_udp_ver     = ProtoField.uint8("nng.udp.ver",       "Version",        base.DEC)
local f_udp_opcode  = ProtoField.uint8("nng.udp.opcode",    "Opcode",         base.DEC, udp_opcode_names)
local f_udp_type    = ProtoField.uint16("nng.udp.type",     "Protocol ID",    base.HEX, proto_names)
local f_udp_length  = ProtoField.uint16("nng.udp.length",   "Payload Length", base.DEC)
local f_udp_recvmax = ProtoField.uint16("nng.udp.recvmax",  "Recv Max",       base.DEC)
local f_udp_refresh = ProtoField.uint16("nng.udp.refresh",  "Refresh (s)",    base.DEC)
local f_udp_reason  = ProtoField.uint16("nng.udp.reason",   "Reason",         base.DEC, udp_disc_reasons)
local f_udp_rsvd    = ProtoField.uint16("nng.udp.rsvd",     "Reserved",       base.HEX)

nng.fields = {
    f_hs_magic, f_hs_proto, f_hs_rsvd,
    f_msg_len, f_msg_data,
    f_bt_hop, f_req_id, f_surv_id,
    f_hop_count, f_body,
    f_udp_ver, f_udp_opcode, f_udp_type,
    f_udp_length, f_udp_recvmax, f_udp_refresh, f_udp_reason, f_udp_rsvd,
}

-- ---------------------------------------------------------------------------
-- Per-connection state tracking
-- ---------------------------------------------------------------------------
-- We track the handshake protocol ID per direction so we can label data
-- frames with their protocol later.
-- TCP:  key = tcp.stream .. "-" .. srcport
-- UDP:  key = src .. ":" .. srcport .. "-" .. dst .. ":" .. dstport

local stream_proto = {}  -- stream_key -> protocol id seen in handshake

function nng.init()
    stream_proto = {}
end

local function stream_key(pinfo)
    local tcp_stream = pinfo.private["tcp.stream"]
    if tcp_stream then
        return tostring(tcp_stream) .. "-" .. tostring(pinfo.src_port)
    end
    -- UDP: use full address/port tuple
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
       .. "-" .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
end

local function peer_key(pinfo)
    local tcp_stream = pinfo.private["tcp.stream"]
    if tcp_stream then
        return tostring(tcp_stream) .. "-" .. tostring(pinfo.dst_port)
    end
    -- UDP: reverse direction
    return tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
       .. "-" .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
end

-- ---------------------------------------------------------------------------
-- Heuristic: detect NNG handshake
-- ---------------------------------------------------------------------------
local function is_handshake(tvb, offset)
    if tvb:len() - offset < 8 then return false end
    return tvb(offset, 1):uint() == 0x00
       and tvb(offset + 1, 1):uint() == 0x53  -- 'S'
       and tvb(offset + 2, 1):uint() == 0x50  -- 'P'
       and tvb(offset + 3, 1):uint() == 0x00
       and tvb(offset + 6, 1):uint() == 0x00
       and tvb(offset + 7, 1):uint() == 0x00
end

-- ---------------------------------------------------------------------------
-- Dissect a single handshake (8 bytes)
-- ---------------------------------------------------------------------------
local function dissect_handshake(tvb, pinfo, tree, offset)
    local subtree = tree:add(nng, tvb(offset, 8), "NNG Handshake")
    subtree:add(f_hs_magic, tvb(offset, 4))
    subtree:add(f_hs_proto, tvb(offset + 4, 2))
    subtree:add(f_hs_rsvd,  tvb(offset + 6, 2))

    local proto_id = tvb(offset + 4, 2):uint()
    local name = proto_names[proto_id] or string.format("unknown (0x%04x)", proto_id)

    pinfo.cols.protocol:set("NNG")
    pinfo.cols.info:set("Handshake [" .. name .. "]")

    -- Remember what protocol this side speaks
    stream_proto[stream_key(pinfo)] = proto_id

    return offset + 8
end

-- ---------------------------------------------------------------------------
-- Dissect backtrace header (REQ/REP, SURVEY/RESPONDENT)
--
-- On the wire the SP header is a sequence of big-endian u32 values.
-- Intermediate hops have the high bit clear; the final entry (the
-- request / survey ID) has the high bit set (0x80000000).
-- ---------------------------------------------------------------------------
local function dissect_backtrace(tvb, offset, msg_end, hdr_tree, proto_id)
    local survey = is_survey[proto_id]
    local id_field = survey and f_surv_id or f_req_id
    local id_label = survey and "Survey ID" or "Request ID"
    local hdr_start = offset
    local hops = 0

    while offset + 4 <= msg_end do
        local val = tvb(offset, 4):uint()
        local is_last = bit.band(val, 0x80000000) ~= 0

        if is_last then
            local masked = bit.band(val, 0x7FFFFFFF)
            local item = hdr_tree:add(id_field, tvb(offset, 4))
            item:append_text(string.format(" (0x%08x, seq %u)", val, masked))
            offset = offset + 4
            hops = hops + 1
            break
        else
            hdr_tree:add(f_bt_hop, tvb(offset, 4))
            offset = offset + 4
            hops = hops + 1
        end
    end

    local hdr_len = offset - hdr_start
    hdr_tree:set_len(hdr_len)

    return offset, hops, id_label
end

-- ---------------------------------------------------------------------------
-- Dissect PAIR1 hop count header
-- ---------------------------------------------------------------------------
local function dissect_hop_count(tvb, offset, msg_end, hdr_tree)
    if offset + 4 > msg_end then
        return offset
    end

    hdr_tree:add(f_hop_count, tvb(offset, 4))
    offset = offset + 4

    hdr_tree:set_len(4)
    return offset
end

-- ---------------------------------------------------------------------------
-- Shared SP payload dissection (used by both TCP and UDP paths)
-- ---------------------------------------------------------------------------
local function dissect_sp_payload(tvb, pinfo, subtree, payload_offset, payload_len, proto_id, name)
    local msg_end = payload_offset + payload_len
    local htype = proto_id and header_type[proto_id]

    if htype == HEADER_BACKTRACE and payload_len >= 4 then
        local hdr_tree = subtree:add(nng, tvb(payload_offset, 0), "SP Header")
        local body_start, hops, id_label = dissect_backtrace(
            tvb, payload_offset, msg_end, hdr_tree, proto_id)
        local body_len = msg_end - body_start

        if body_len > 0 then
            subtree:add(f_body, tvb(body_start, body_len))
        end

        if hops > 1 then
            pinfo.cols.info:set(string.format("Data [%s] %s + %d hops, %d bytes",
                name or "?", id_label, hops - 1, body_len))
        else
            pinfo.cols.info:set(string.format("Data [%s] %s, %d bytes",
                name or "?", id_label, body_len))
        end

    elseif htype == HEADER_HOP_COUNT and payload_len >= 4 then
        local hdr_tree = subtree:add(nng, tvb(payload_offset, 0), "SP Header")
        local body_start = dissect_hop_count(tvb, payload_offset, msg_end, hdr_tree)
        local body_len = msg_end - body_start
        local hop_val = tvb(payload_offset, 4):uint()

        if body_len > 0 then
            subtree:add(f_body, tvb(body_start, body_len))
        end

        pinfo.cols.info:set(string.format("Data [%s] hops=%d, %d bytes",
            name or "pair v1", hop_val, body_len))

    else
        subtree:add(f_msg_data, tvb(payload_offset, payload_len))
        pinfo.cols.info:set(string.format("Data%s %d bytes",
            name and (" [" .. name .. "]") or "", payload_len))
    end
end

-- ---------------------------------------------------------------------------
-- UDP transport dissector
-- ---------------------------------------------------------------------------
-- Detect NNG UDP header: version 1, valid opcode, known protocol ID
local function is_udp_nng(tvb, offset)
    if tvb:len() - offset < 8 then return false end
    if tvb(offset, 1):uint() ~= 0x01 then return false end
    local opcode = tvb(offset + 1, 1):uint()
    if opcode > UDP_OPCODE_MESH then return false end
    local proto_id = tvb(offset + 2, 2):le_uint()
    if not proto_names[proto_id] then return false end
    -- For DATA packets, verify payload length fits the datagram
    if opcode == UDP_OPCODE_DATA then
        local payload_len = tvb(offset + 4, 2):le_uint()
        if payload_len > tvb:len() - offset - 8 then return false end
    end
    return true
end

local function dissect_udp_nng(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 8 then return 0 end

    local opcode   = tvb(1, 1):uint()
    local proto_id = tvb(2, 2):le_uint()
    local name     = proto_names[proto_id] or string.format("unknown (0x%04x)", proto_id)
    local op_name  = udp_opcode_names[opcode] or "?"

    pinfo.cols.protocol:set("NNG")

    if opcode == UDP_OPCODE_CREQ or opcode == UDP_OPCODE_CACK then
        local subtree = tree:add(nng, tvb(0, 8), "NNG " .. op_name)
        subtree:add(f_udp_ver,     tvb(0, 1))
        subtree:add(f_udp_opcode,  tvb(1, 1))
        subtree:add_le(f_udp_type, tvb(2, 2))
        subtree:add_le(f_udp_recvmax, tvb(4, 2))
        subtree:add_le(f_udp_refresh, tvb(6, 2))

        local recvmax = tvb(4, 2):le_uint()
        local refresh = tvb(6, 2):le_uint()
        pinfo.cols.info:set(string.format("%s [%s] recvmax=%d refresh=%ds",
            op_name, name, recvmax, refresh))

        -- Track protocol for this direction
        stream_proto[stream_key(pinfo)] = proto_id
        return len

    elseif opcode == UDP_OPCODE_DISC then
        local subtree = tree:add(nng, tvb(0, 8), "NNG DISC")
        subtree:add(f_udp_ver,     tvb(0, 1))
        subtree:add(f_udp_opcode,  tvb(1, 1))
        subtree:add_le(f_udp_type, tvb(2, 2))
        subtree:add_le(f_udp_reason, tvb(4, 2))
        subtree:add_le(f_udp_rsvd,   tvb(6, 2))

        local reason_id = tvb(4, 2):le_uint()
        local reason = udp_disc_reasons[reason_id]
            or string.format("unknown (%d)", reason_id)
        pinfo.cols.info:set(string.format("DISC [%s] %s", name, reason))
        return len

    elseif opcode == UDP_OPCODE_DATA then
        local payload_len = tvb(4, 2):le_uint()
        local payload_offset = 8

        local subtree = tree:add(nng, tvb(0, payload_offset + payload_len), "NNG Data")
        subtree:add(f_udp_ver,     tvb(0, 1))
        subtree:add(f_udp_opcode,  tvb(1, 1))
        subtree:add_le(f_udp_type, tvb(2, 2))
        subtree:add_le(f_udp_length, tvb(4, 2))

        if payload_len == 0 then
            pinfo.cols.info:set(string.format("Data [%s] (empty)", name))
            return len
        end

        dissect_sp_payload(tvb, pinfo, subtree, payload_offset, payload_len, proto_id, name)
        return len

    else
        -- MESH or unknown opcode — show raw
        local subtree = tree:add(nng, tvb(0, len), "NNG " .. op_name)
        subtree:add(f_udp_ver,     tvb(0, 1))
        subtree:add(f_udp_opcode,  tvb(1, 1))
        subtree:add_le(f_udp_type, tvb(2, 2))
        if len > 8 then
            subtree:add(f_msg_data, tvb(8, len - 8))
        end
        pinfo.cols.info:set(string.format("%s [%s]", op_name, name))
        return len
    end
end

-- ---------------------------------------------------------------------------
-- Dissect a single TCP data message: 8-byte length + payload
-- Returns new offset, or negative value = bytes still needed
-- ---------------------------------------------------------------------------
local function dissect_message(tvb, pinfo, tree, offset)
    local remaining = tvb:len() - offset

    -- Need at least the 8-byte length header
    if remaining < 8 then
        return -(8 - remaining)
    end

    local msg_len = tvb(offset, 8):uint64():tonumber()

    -- Sanity guard: reject absurdly large lengths (> 256 MB) to avoid
    -- misidentifying random TCP traffic as NNG.
    if msg_len > 268435456 then
        return nil  -- not NNG
    end

    local total = 8 + msg_len
    if remaining < total then
        -- We have the header but not the full payload yet; ask for reassembly
        return -(total - remaining)
    end

    pinfo.cols.protocol:set("NNG")

    -- Determine the protocol for this connection direction
    local proto_id = stream_proto[stream_key(pinfo)]
        or stream_proto[peer_key(pinfo)]
    local name = proto_id and proto_names[proto_id] or nil

    local subtree = tree:add(nng, tvb(offset, total), "NNG Message")
    subtree:add(f_msg_len, tvb(offset, 8))

    if msg_len == 0 then
        pinfo.cols.info:set(string.format("Data%s (empty)",
            name and (" [" .. name .. "]") or ""))
        return offset + total
    end

    local payload_offset = offset + 8
    dissect_sp_payload(tvb, pinfo, subtree, payload_offset, msg_len, proto_id, name)

    return offset + total
end

-- ---------------------------------------------------------------------------
-- Main dissector entry point
-- ---------------------------------------------------------------------------
function nng.dissector(tvb, pinfo, tree)
    local is_tcp = pinfo.private["tcp.stream"] ~= nil

    -- UDP transport uses a different wire format
    if not is_tcp then
        if is_udp_nng(tvb, 0) then
            return dissect_udp_nng(tvb, pinfo, tree)
        end
        return 0
    end

    -- TCP transport: handshakes + length-prefixed data frames
    local offset = 0
    local pdu_count = 0

    while offset < tvb:len() do
        -- Try handshake first
        if is_handshake(tvb, offset) then
            offset = dissect_handshake(tvb, pinfo, tree, offset)
            pdu_count = pdu_count + 1
        else
            local result = dissect_message(tvb, pinfo, tree, offset)
            if result == nil then
                -- Not NNG data
                return 0
            elseif result < 0 then
                -- Need more bytes for reassembly
                pinfo.desegment_len = -result
                pinfo.desegment_offset = offset
                return
            else
                offset = result
                pdu_count = pdu_count + 1
            end
        end
    end

    if pdu_count > 1 then
        pinfo.cols.info:append(string.format(" (+%d PDUs)", pdu_count - 1))
    end

    return offset
end

-- ---------------------------------------------------------------------------
-- Heuristic dissectors
-- ---------------------------------------------------------------------------
local function tcp_heuristic_checker(tvb, pinfo, tree)
    if tvb:len() < 8 then
        return false
    end
    if not is_handshake(tvb, 0) then
        return false
    end

    nng.dissector(tvb, pinfo, tree)
    pinfo.conversation = nng
    return true
end

local function udp_heuristic_checker(tvb, pinfo, tree)
    if not is_udp_nng(tvb, 0) then
        return false
    end

    dissect_udp_nng(tvb, pinfo, tree)
    pinfo.conversation = nng
    return true
end

nng:register_heuristic("tcp", tcp_heuristic_checker)
nng:register_heuristic("udp", udp_heuristic_checker)

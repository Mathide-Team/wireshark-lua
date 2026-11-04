-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/Tomer-Harari/vita49.2-wireshark-dissector (vita49.lua),
-- commit 1f5ab2ba2b5c072596c89e742c7cd524b262d638 du 04/08/2026 (dernière modification du fichier :
-- commit 1f5ab2ba2b5c072596c89e742c7cd524b262d638 du 04/08/2026).
-- Licence amont : MIT, « Copyright (c) 2026 Tomer Harari » (LICENSE du dépôt) — voir README.md et LICENSE.
-- vita49.lua - Wireshark dissector for VITA 49.2 (VRT) with DIFI awareness
--
-- Dissects VRT packets carried over UDP: the full prologue per ANSI/VITA
-- 49.2-2017 section 5.1 (header, stream ID, class ID, TSI/TSF timestamps), the
-- trailer of signal data packets, the payload, and - for context packets -
-- a full CIF0/CIF1 field walk (section 9.1): every enabled field is decoded at its
-- correct size, with the 64-bit radix-20 frequency fields (section 9.5.1) shown
-- in Hz. Recognizes the DIFI profile by its OUI (0x6A621E) and names its
-- packet classes. Multiple VRT packets per UDP datagram are walked using
-- the Packet Size field.
--
-- Also decodes the signal-data trailer bit pairs (section 5.1.6), the command
-- packet preamble - CAM word, Message ID, Controllee/Controller IDs
-- (section 8.2) - renders UTC integer timestamps as calendar time, and
-- registers a heuristic so VRT streams are recognized on any UDP port.
--
-- Expert checks:
--   * packet count gaps, tracked per (type, stream ID, class) - the scope
--     the standard gives the counter (section 5.1.1.7)
--   * Packet Size disagreeing with the remaining datagram bytes
--   * sample loss signalled in a data packet trailer
--
-- Install: copy into Wireshark's "Personal Lua Plugins" folder, or run
--   tshark -X lua_script:vita49.lua -r capture.pcap
-- Ports: UDP 4991 by default (the DIFI convention), editable in
-- Preferences; other ports are caught by the heuristic.

local vrt = Proto("vita49", "VITA 49.2 Radio Transport")

local PACKET_TYPES = {
    [0] = "Signal Data (no Stream ID)",
    [1] = "Signal Data",
    [2] = "Extension Data (no Stream ID)",
    [3] = "Extension Data",
    [4] = "Context",
    [5] = "Extension Context",
    [6] = "Command",
    [7] = "Extension Command",
}

local TSI_NAMES = { [0] = "none", [1] = "UTC", [2] = "GPS", [3] = "other" }
local TSF_NAMES = { [0] = "none", [1] = "sample count",
                    [2] = "real time (ps)", [3] = "free running" }

local DIFI_OUI = 0x6A621E
local DIFI_CLASSES = {
    ["0:0"] = "DIFI Standard Flow Data",
    ["0:1"] = "DIFI Standard Context",
    ["1:4"] = "DIFI Version Context",
}

local f = vrt.fields
f.ptype   = ProtoField.uint8 ("vita49.type",    "Packet Type", base.DEC, PACKET_TYPES)
f.cid     = ProtoField.bool  ("vita49.cid",     "Class ID present")
f.ind     = ProtoField.uint8 ("vita49.ind",     "Indicator bits", base.HEX)
f.trailer_p = ProtoField.bool("vita49.trailer_present", "Trailer present")
f.tsi     = ProtoField.uint8 ("vita49.tsi",     "TSI (integer timestamp)", base.DEC, TSI_NAMES)
f.tsf     = ProtoField.uint8 ("vita49.tsf",     "TSF (fractional timestamp)", base.DEC, TSF_NAMES)
f.seq     = ProtoField.uint8 ("vita49.seq",     "Packet Count", base.DEC)
f.size    = ProtoField.uint16("vita49.size",    "Packet Size (words)", base.DEC)
f.sid     = ProtoField.uint32("vita49.sid",     "Stream ID", base.HEX)
f.oui     = ProtoField.uint24("vita49.oui",     "Class OUI", base.HEX)
f.iclass  = ProtoField.uint16("vita49.info_class",   "Information Class", base.HEX)
f.pclass  = ProtoField.uint16("vita49.packet_class", "Packet Class", base.HEX)
f.tsint   = ProtoField.uint32("vita49.ts_int",  "Integer Timestamp", base.DEC)
f.tsfrac  = ProtoField.uint64("vita49.ts_frac", "Fractional Timestamp", base.DEC)
f.payload = ProtoField.bytes ("vita49.payload", "Payload")
f.paywords= ProtoField.uint16("vita49.payload_words", "Payload Words", base.DEC)
f.trailer = ProtoField.uint32("vita49.trailer", "Trailer", base.HEX)
f.difi    = ProtoField.string("vita49.difi",    "DIFI Class")

-- Context Information Fields (section 9.1)
f.cif0        = ProtoField.uint32("vita49.cif0", "CIF0", base.HEX)
f.cif1        = ProtoField.uint32("vita49.cif1", "CIF1", base.HEX)
f.ref_point   = ProtoField.uint32("vita49.ref_point", "Reference Point ID", base.HEX)
f.bandwidth   = ProtoField.double("vita49.bandwidth_hz", "Bandwidth (Hz)")
f.if_freq     = ProtoField.double("vita49.if_freq_hz", "IF Reference Frequency (Hz)")
f.rf_freq     = ProtoField.double("vita49.rf_freq_hz", "RF Reference Frequency (Hz)")
f.rf_offset   = ProtoField.double("vita49.rf_offset_hz", "RF Frequency Offset (Hz)")
f.if_band_off = ProtoField.double("vita49.if_band_offset_hz", "IF Band Offset (Hz)")
f.ref_level   = ProtoField.float ("vita49.ref_level_dbm", "Reference Level (dBm)")
f.gain1       = ProtoField.float ("vita49.gain1_db", "Gain Stage 1 (dB)")
f.gain2       = ProtoField.float ("vita49.gain2_db", "Gain Stage 2 (dB)")
f.overrange   = ProtoField.uint32("vita49.over_range", "Over-Range Count", base.DEC)
f.sample_rate = ProtoField.double("vita49.sample_rate_hz", "Sample Rate (Hz)")
f.ts_adjust   = ProtoField.uint64("vita49.ts_adjust_fs", "Timestamp Adjustment (fs)", base.DEC)
f.ts_calib    = ProtoField.uint32("vita49.ts_calib", "Timestamp Calibration Time", base.DEC)
f.temperature = ProtoField.float ("vita49.temperature_c", "Temperature (degC)")
f.device_id   = ProtoField.bytes ("vita49.device_id", "Device Identifier")
f.state_event = ProtoField.uint32("vita49.state_event", "State/Event Indicators", base.HEX)
f.data_format = ProtoField.uint64("vita49.data_format", "Data Packet Payload Format", base.HEX)
f.cif_raw     = ProtoField.bytes ("vita49.cif_field", "CIF field (raw)")
f.v49_ver     = ProtoField.uint32("vita49.v49_spec_version", "V49 Spec Version", base.HEX)
f.build_ydr   = ProtoField.uint32("vita49.build_ydr", "Year/Day/Revision word", base.HEX)
f.ts_utc      = ProtoField.string("vita49.ts_utc", "Timestamp (UTC)")

-- signal-data trailer (section 5.1.6): enable/indicator bit pairs
local TRAILER_BITS = {
    {31, 19, "Calibrated Time"},
    {30, 18, "Valid Data"},
    {29, 17, "Reference Lock"},
    {28, 16, "AGC/MGC"},
    {27, 15, "Detected Signal"},
    {26, 14, "Spectral Inversion"},
    {25, 13, "Over-Range"},
    {24, 12, "Sample Loss"},
}
f.trl_flag    = ProtoField.string("vita49.trailer_flag", "Trailer Indicator")
f.trl_ecount  = ProtoField.uint8 ("vita49.trailer_context_count",
                                  "Associated Context Packet Count", base.DEC)

-- command preamble (section 8.2)
local ACTION_NAMES = { [0] = "no-action", [1] = "dry-run",
                       [2] = "execute", [3] = "reserved" }
f.cam         = ProtoField.uint32("vita49.cam", "CAM (Control/Ack Mode)", base.HEX)
f.cam_ce_en   = ProtoField.bool  ("vita49.cam_controllee", "Controllee ID present", 32, nil, 0x80000000)
f.cam_cr_en   = ProtoField.bool  ("vita49.cam_controller", "Controller ID present", 32, nil, 0x20000000)
f.cam_partial = ProtoField.bool  ("vita49.cam_partial", "Partial-action permitted", 32, nil, 0x08000000)
f.cam_warn    = ProtoField.bool  ("vita49.cam_warnings", "Warnings requested", 32, nil, 0x04000000)
f.cam_err     = ProtoField.bool  ("vita49.cam_errors", "Errors requested", 32, nil, 0x02000000)
f.cam_action  = ProtoField.uint32("vita49.cam_action", "Action", base.DEC, ACTION_NAMES, 0x01800000)
f.cam_nack    = ProtoField.bool  ("vita49.cam_nack", "Not-Ack only", 32, nil, 0x00400000)
f.msg_id      = ProtoField.uint32("vita49.message_id", "Message ID", base.HEX)
f.controllee  = ProtoField.uint32("vita49.controllee_id", "Controllee ID", base.HEX)
f.controller  = ProtoField.uint32("vita49.controller_id", "Controller ID", base.HEX)
f.cmd_ack     = ProtoField.bool  ("vita49.cmd_ack", "Acknowledge packet")
f.cmd_cancel  = ProtoField.bool  ("vita49.cmd_cancel", "Cancellation packet")

local ex_seq  = ProtoExpert.new("vita49.seq_gap.expert",
    "Packet count gap (lost or reordered packets)",
    expert.group.SEQUENCE, expert.severity.WARN)
local ex_size = ProtoExpert.new("vita49.bad_size.expert",
    "Packet Size exceeds the remaining datagram bytes",
    expert.group.MALFORMED, expert.severity.ERROR)
local ex_cif  = ProtoExpert.new("vita49.cif_var.expert",
    "Variable-size CIF field present; detailed decode stops here",
    expert.group.UNDECODED, expert.severity.NOTE)
local ex_loss = ProtoExpert.new("vita49.sample_loss.expert",
    "Trailer signals sample loss in this packet",
    expert.group.SEQUENCE, expert.severity.WARN)
vrt.experts = { ex_seq, ex_size, ex_cif, ex_loss }

vrt.prefs.ports = Pref.range("UDP ports", "4991",
    "UDP ports carrying VRT packets", 65535)
local registered_ports = "4991"
function vrt.prefs_changed()
    local udp = DissectorTable.get("udp.port")
    udp:remove(registered_ports, vrt)
    registered_ports = tostring(vrt.prefs.ports)
    udp:add(registered_ports, vrt)
end

-- sequence tracking: first-pass state and per-frame verdicts
local seq_last, seq_gap_frames
function vrt.init()
    seq_last = {}
    seq_gap_frames = {}
end

-- 64-bit two's complement with the radix point right of bit 20
-- (section 9.5.1). tonumber() is exact up to 2^53, i.e. frequencies up
-- to ~8.5 THz at radix-20 - far beyond anything VRT carries.
local function radix20(range)
    return range:int64():tonumber() / 1048576.0
end

-- CIF0 field walk table (section 9.1): MSB-first order of the enabled fields.
-- {bit, words (0 = variable), handler}
local CIF0_FIELDS = {
    {30, 1, function(t, r) t:add(f.ref_point, r) end},
    {29, 2, function(t, r) t:add(f.bandwidth, r, radix20(r)) end},
    {28, 2, function(t, r) t:add(f.if_freq, r, radix20(r)) end},
    {27, 2, function(t, r) t:add(f.rf_freq, r, radix20(r)) end},
    {26, 2, function(t, r) t:add(f.rf_offset, r, radix20(r)) end},
    {25, 2, function(t, r) t:add(f.if_band_off, r, radix20(r)) end},
    {24, 1, function(t, r)
        t:add(f.ref_level, r(2, 2), r(2, 2):int() / 128.0) end},
    {23, 1, function(t, r)
        t:add(f.gain2, r(0, 2), r(0, 2):int() / 128.0)
        t:add(f.gain1, r(2, 2), r(2, 2):int() / 128.0) end},
    {22, 1, function(t, r) t:add(f.overrange, r) end},
    {21, 2, function(t, r) t:add(f.sample_rate, r, radix20(r)) end},
    {20, 2, function(t, r) t:add(f.ts_adjust, r) end},
    {19, 1, function(t, r) t:add(f.ts_calib, r) end},
    {18, 1, function(t, r)
        t:add(f.temperature, r(2, 2), r(2, 2):int() / 64.0) end},
    {17, 2, function(t, r) t:add(f.device_id, r) end},
    {16, 1, function(t, r) t:add(f.state_event, r) end},
    {15, 2, function(t, r) t:add(f.data_format, r) end},
    {14, 11, function(t, r) t:add(f.cif_raw, r):append_text(" (Formatted GPS)") end},
    {13, 11, function(t, r) t:add(f.cif_raw, r):append_text(" (Formatted INS)") end},
    {12, 13, function(t, r) t:add(f.cif_raw, r):append_text(" (ECEF Ephemeris)") end},
    {11, 13, function(t, r) t:add(f.cif_raw, r):append_text(" (Relative Ephemeris)") end},
    {10, 1, function(t, r) t:add(f.cif_raw, r):append_text(" (Ephemeris Ref ID)") end},
    {9, 0, nil},    -- GPS ASCII: variable size
    {8, 0, nil},    -- Context Association Lists: variable size
}

-- Decode the context section of a context packet: CIF0 (+CIF1) and every
-- enabled field. Returns nothing; adds to the tree.
local function decode_context(tvb, tree, p, pay_end)
    if pay_end - p < 4 then return end
    local cif0r = tvb(p, 4)
    local cif0 = cif0r:uint()
    tree:add(f.cif0, cif0r)
    p = p + 4

    local cif1 = nil
    if cif0 % 4 >= 2 then                      -- bit 1: CIF1 enable
        cif1 = tvb(p, 4)
        tree:add(f.cif1, cif1)
        p = p + 4
    end

    for _, e in ipairs(CIF0_FIELDS) do
        local bit_i, words, fn = e[1], e[2], e[3]
        if math.floor(cif0 / 2 ^ bit_i) % 2 == 1 then
            if words == 0 then
                tree:add_proto_expert_info(ex_cif)
                if pay_end > p then
                    tree:add(f.cif_raw, tvb(p, pay_end - p))
                end
                return
            end
            if p + words * 4 > pay_end then return end
            fn(tree, tvb(p, words * 4))
            p = p + words * 4
        end
    end

    if cif1 then
        local c1 = cif1:uint()
        local handled = 0
        if math.floor(c1 / 8) % 2 == 1 then    -- bit 3: V49 spec version
            tree:add(f.v49_ver, tvb(p, 4)); p = p + 4
            handled = handled + 8
        end
        if math.floor(c1 / 4) % 2 == 1 then    -- bit 2: year/day/revision
            tree:add(f.build_ydr, tvb(p, 4)); p = p + 4
            handled = handled + 4
        end
        -- any other enabled CIF1 field has no size table here: stop the
        -- detailed decode honestly rather than misalign what follows
        if c1 - handled ~= 0 then
            tree:add_proto_expert_info(ex_cif)
            if pay_end > p then
                tree:add(f.cif_raw, tvb(p, pay_end - p))
            end
        end
    end
end

-- signal-data trailer (section 5.1.6): show each indicator whose enable bit
-- is set, plus the associated-context count when its E bit is on
local function decode_trailer(tree, r)
    local w = r:uint()
    local sub = tree:add(f.trailer, r)
    local loss = false
    for _, e in ipairs(TRAILER_BITS) do
        local en_bit, ind_bit, name = e[1], e[2], e[3]
        if math.floor(w / 2 ^ en_bit) % 2 == 1 then
            local v = math.floor(w / 2 ^ ind_bit) % 2
            sub:add(f.trl_flag, r, string.format("%s = %d", name, v))
            if name == "Sample Loss" and v == 1 then
                loss = true
            end
        end
    end
    if math.floor(w / 128) % 2 == 1 then       -- bit 7: count enable
        sub:add(f.trl_ecount, r, w % 128)
    end
    if loss then
        tree:add_proto_expert_info(ex_loss)
    end
end

-- command packet preamble (section 8.2): CAM, Message ID, optional
-- Controllee/Controller IDs (32-bit form), then the CIF control section
local function decode_command(tvb, tree, p, pay_end, ind)
    tree:add(f.cmd_ack, ind % 8 >= 4):set_generated()
    tree:add(f.cmd_cancel, ind % 2 == 1):set_generated()
    if pay_end - p < 8 then return end
    local camr = tvb(p, 4)
    local cam = camr:uint()
    local ct = tree:add(f.cam, camr)
    ct:add(f.cam_ce_en, camr)
    ct:add(f.cam_cr_en, camr)
    ct:add(f.cam_partial, camr)
    ct:add(f.cam_warn, camr)
    ct:add(f.cam_err, camr)
    ct:add(f.cam_action, camr)
    ct:add(f.cam_nack, camr)
    p = p + 4
    tree:add(f.msg_id, tvb(p, 4)); p = p + 4
    if math.floor(cam / 2 ^ 31) % 2 == 1 then       -- controllee, 32-bit ID
        if math.floor(cam / 2 ^ 30) % 2 == 1 then return end
        if pay_end - p < 4 then return end
        tree:add(f.controllee, tvb(p, 4)); p = p + 4
    end
    if math.floor(cam / 2 ^ 29) % 2 == 1 then       -- controller, 32-bit ID
        if math.floor(cam / 2 ^ 28) % 2 == 1 then return end
        if pay_end - p < 4 then return end
        tree:add(f.controller, tvb(p, 4)); p = p + 4
    end
    decode_context(tvb, tree, p, pay_end)
end

local function dissect_one(tvb, pinfo, root, off, remaining)
    local hdr    = tvb(off, 4)
    local ptype  = hdr:bitfield(0, 4)
    local has_c  = hdr:bitfield(4, 1) == 1
    local ind    = hdr:bitfield(5, 3)
    local tsi    = hdr:bitfield(8, 2)
    local tsf    = hdr:bitfield(10, 2)
    local seq    = hdr:bitfield(12, 4)
    local size_w = hdr:bitfield(16, 16)
    local is_data = ptype <= 3
    local is_ctx  = ptype == 4 or ptype == 5
    local has_sid = (ptype ~= 0) and (ptype ~= 2)
    local has_trl = is_data and hdr:bitfield(5, 1) == 1     -- bit 26

    local nbytes = size_w * 4
    local tree = root:add(vrt, tvb(off, math.min(nbytes, remaining)),
        string.format("VITA 49.2, %s, seq %d, %d words",
                      PACKET_TYPES[ptype] or "?", seq, size_w))

    tree:add(f.ptype, hdr, ptype)
    tree:add(f.cid, hdr, has_c)
    tree:add(f.ind, hdr, ind)
    if is_data then tree:add(f.trailer_p, hdr, has_trl) end
    tree:add(f.tsi, hdr, tsi)
    tree:add(f.tsf, hdr, tsf)
    tree:add(f.seq, hdr, seq)
    tree:add(f.size, hdr, size_w)

    if nbytes > remaining or size_w == 0 then
        tree:add_proto_expert_info(ex_size)
        return remaining        -- consume the rest, stop walking
    end

    local p = off + 4
    local sid = nil
    if has_sid then
        sid = tvb(p, 4):uint()
        tree:add(f.sid, tvb(p, 4)); p = p + 4
    end

    local difi_key = nil
    local icl, pcl = nil, nil
    if has_c then
        local oui = tvb(p, 4):bitfield(8, 24)
        tree:add(f.oui, tvb(p + 1, 3))
        icl = tvb(p + 4, 2):uint()
        pcl = tvb(p + 6, 2):uint()
        tree:add(f.iclass, tvb(p + 4, 2))
        tree:add(f.pclass, tvb(p + 6, 2))
        if oui == DIFI_OUI then
            difi_key = DIFI_CLASSES[icl .. ":" .. pcl] or "DIFI (unknown class)"
            tree:add(f.difi, difi_key):set_generated()
        end
        p = p + 8
    end

    if tsi ~= 0 then
        tree:add(f.tsint, tvb(p, 4))
        if tsi == 1 then                            -- UTC epoch seconds
            tree:add(f.ts_utc, tvb(p, 4), format_date(tvb(p, 4):uint())
                ):set_generated()
        end
        p = p + 4
    end
    if tsf ~= 0 then
        tree:add(f.tsfrac, tvb(p, 8)); p = p + 8
    end

    local tail = has_trl and 4 or 0
    local pay_bytes = off + nbytes - p - tail
    if pay_bytes > 0 then
        tree:add(f.payload, tvb(p, pay_bytes))
        tree:add(f.paywords, pay_bytes / 4):set_generated()
        if is_ctx then
            decode_context(tvb, tree, p, p + pay_bytes)
        elseif ptype == 6 or ptype == 7 then
            decode_command(tvb, tree, p, p + pay_bytes, ind)
        end
    end
    if has_trl then
        decode_trailer(tree, tvb(off + nbytes - 4, 4))
    end

    -- sequence continuity per (type, stream ID, class): the packet count
    -- runs independently per stream AND packet class (section 5.1.1.7)
    local key = ptype .. ":" .. tostring(sid or "-") .. ":"
        .. tostring(icl or "-") .. ":" .. tostring(pcl or "-")
    if not pinfo.visited then
        local last = seq_last[key]
        if last ~= nil and seq ~= (last + 1) % 16 then
            seq_gap_frames[pinfo.number] = true
        end
        seq_last[key] = seq
    end
    if seq_gap_frames[pinfo.number] then
        tree:add_proto_expert_info(ex_seq)
    end

    -- info column
    local info = string.format("%s seq=%d",
        difi_key or PACKET_TYPES[ptype] or "VRT", seq)
    if sid then info = info .. string.format(" SID=0x%X", sid) end
    if pinfo.cols.info then
        pinfo.cols.info:append(" | " .. info)
    end
    return nbytes
end

function vrt.dissector(tvb, pinfo, root)
    pinfo.cols.protocol = "VITA-49.2"
    pinfo.cols.info = ""
    local off = 0
    while tvb:len() - off >= 4 do
        local used = dissect_one(tvb, pinfo, root, off, tvb:len() - off)
        off = off + used
    end
    return off
end

DissectorTable.get("udp.port"):add(4991, vrt)

-- heuristic: accept a UDP payload iff walking it as VRT packets by their
-- Packet Size fields consumes the datagram exactly
local function vrt_heuristic(tvb, pinfo, root)
    local len = tvb:len()
    local off = 0
    local n = 0
    while off + 4 <= len do
        local size_w = tvb(off, 4):bitfield(16, 16)
        if size_w == 0 then return false end
        off = off + size_w * 4
        n = n + 1
        if n > 64 then return false end
    end
    if off ~= len or n == 0 then return false end
    vrt.dissector(tvb, pinfo, root)
    return true
end
vrt:register_heuristic("udp", vrt_heuristic)

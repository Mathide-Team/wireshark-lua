-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/pdgendt/wireshark-smp-mcumgr (smp_mcumgr.lua),
-- commit 2981ee6471a984198c7ade1ab32de75f6977c773 du 08/09/2026.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- smp_mcumgr.lua
-- Wireshark dissector for SMP (Simple Management Protocol) / MCUmgr over UDP
-- Default port: 1337
--
-- SMP Header (8 bytes, Big Endian):
--   Byte 0:     OP      (3 bits) | Version (2 bits) | Reserved (3 bits)
--   Byte 1:     Flags
--   Bytes 2-3:  Data Length (uint16, big-endian)
--   Bytes 4-5:  Group ID   (uint16, big-endian)
--   Byte 6:     Sequence Number
--   Byte 7:     Command ID
--
-- Payload: CBOR-encoded data (variable length, may be absent)
--
-- References:
--   https://docs.zephyrproject.org/latest/services/device_mgmt/smp_protocol.html
--   https://github.com/zephyrproject-rtos/mcumgr/blob/master/protocol.md

-- ─── Protocol declaration ────────────────────────────────────────────────────

local smp_proto = Proto("smp_mcumgr", "SMP MCUmgr Protocol")

-- ─── Expert info ─────────────────────────────────────────────────────────────

local e_len_mismatch = ProtoExpert.new(
    "smp_mcumgr.len_mismatch.expert",
    "Header data length does not match the actual payload",
    expert.group.MALFORMED, expert.severity.WARN)
local e_cbor_failed = ProtoExpert.new(
    "smp_mcumgr.cbor_failed.expert", "CBOR decode failed",
    expert.group.UNDECODED, expert.severity.WARN)
smp_proto.experts = { e_len_mismatch, e_cbor_failed }

-- ─── Field definitions ───────────────────────────────────────────────────────

local f_op       = ProtoField.uint8 ("smp_mcumgr.op",       "Operation Code",    base.DEC)
local f_version  = ProtoField.uint8 ("smp_mcumgr.version",  "SMP Version",       base.DEC)
local f_reserved = ProtoField.uint8 ("smp_mcumgr.reserved", "Reserved",          base.HEX)
local f_flags    = ProtoField.uint8 ("smp_mcumgr.flags",    "Flags",             base.HEX)
local f_len      = ProtoField.uint16("smp_mcumgr.len",      "Data Length",       base.DEC)
local f_group    = ProtoField.uint16("smp_mcumgr.group",    "Group ID",          base.DEC)
local f_seq      = ProtoField.uint8 ("smp_mcumgr.seq",      "Sequence Number",   base.DEC)
local f_id       = ProtoField.uint8 ("smp_mcumgr.id",       "Command ID",        base.DEC)
local f_payload  = ProtoField.bytes ("smp_mcumgr.payload",  "CBOR Payload",      base.SPACE)

local f_response_in = ProtoField.framenum(
    "smp_mcumgr.response_in", "Response in", base.NONE, frametype.RESPONSE)
local f_request_in  = ProtoField.framenum(
    "smp_mcumgr.request_in", "Request in", base.NONE, frametype.REQUEST)

smp_proto.fields = { f_op, f_version, f_reserved, f_flags, f_len, f_group,
                     f_seq, f_id, f_payload, f_response_in, f_request_in }

-- ─── Request/response correlation ────────────────────────────────────────────
-- An exchange is identified by endpoint pair + group + command + sequence
-- number; requests have even op codes, responses odd ones.

local pending_requests = {} -- endpoint/group/cmd/seq -> request frame
local exchange_response = {} -- request frame -> response frame
local exchange_request = {}  -- response frame -> request frame

function smp_proto.init()
    pending_requests = {}
    exchange_response = {}
    exchange_request = {}
end

-- ─── Value string tables ─────────────────────────────────────────────────────

local op_names = {
    [0] = "Read Request",
    [1] = "Read Response",
    [2] = "Write Request",
    [3] = "Write Response",
    [4] = "Read Request (v2)",
    [5] = "Read Response (v2)",
    [6] = "Write Request (v2)",
    [7] = "Write Response (v2)",
}

local group_names = {
    [0]   = "OS Management",
    [1]   = "Image Management",
    [2]   = "Statistics Management",
    [3]   = "Settings (Config) Management",
    [4]   = "Log Management (deprecated)",
    [5]   = "Crash Management",
    [6]   = "Split Image Management",
    [7]   = "Run Test Management",
    [8]   = "File Management",
    [9]   = "Shell Management",
    [10]  = "Enumeration Management",
    [63]  = "Zephyr Management",
    [64]  = "Peruser Group Base",
}

-- Command IDs per group (group_id -> { cmd_id -> name })
local cmd_names = {
    [0] = {    -- OS Management
        [0] = "Echo",
        [1] = "Console Echo Control",
        [2] = "Task Statistics",
        [3] = "Memory Pool Statistics",
        [4] = "Date/Time",
        [5] = "Reset",
        [6] = "MCUmgr Parameters",
        [7] = "Application Info",
        [8] = "Boot Mode",
    },
    [1] = {    -- Image Management
        [0] = "Image State",
        [1] = "Image Upload",
        [2] = "Image File",
        [3] = "Core List",
        [4] = "Core Load",
        [5] = "Image Erase",
        [6] = "Image Slot Info",
        [7] = "Image Erase State",
    },
    [2] = {    -- Statistics Management
        [0] = "Statistics Group List",
        [1] = "Statistics Group",
    },
    [3] = {    -- Settings (Config) Management
        [0] = "Read Setting",
        [1] = "Write Setting",
        [2] = "Delete Setting",
        [3] = "Commit Settings",
        [4] = "Load Settings",
        [5] = "Save Settings",
    },
    [8] = {    -- File Management
        [0] = "File Download / Upload",
        [1] = "File Status",
        [2] = "File Hash / Checksum",
        [3] = "Supported File Hash / Checksum Types",
        [4] = "File Close",
    },
    [9] = {    -- Shell Management
        [0] = "Execute Command",
        [1] = "Control",
    },
    [10] = {   -- Enumeration Management
        [0] = "Count Groups",
        [1] = "List Groups",
        [2] = "List Commands",
        [3] = "List Details",
    },
    [63] = {   -- Zephyr Management
        [0] = "Erase Storage",
    },
}

-- ─── Helper: lookup with fallback ────────────────────────────────────────────

local function lookup(tbl, key, fmt)
    return tbl[key] or string.format(fmt or "Unknown (0x%02x)", key)
end

local function lookup_cmd(group_id, cmd_id)
    local g = cmd_names[group_id]
    if g then
        return g[cmd_id] or string.format("Unknown Command (%d)", cmd_id)
    end
    return string.format("Command %d", cmd_id)
end

-- ─── Dissector ───────────────────────────────────────────────────────────────

function smp_proto.dissector(buffer, pinfo, tree)
    local pkt_len = buffer:len()

    -- Need at least the 8-byte SMP header
    if pkt_len < 8 then
        return 0
    end

    pinfo.cols.protocol:set("SMP MCUmgr")

    -- Parse byte 0: Reserved (bits 7-5) | Version (bits 4-3) | OP (bits 2-0).
    -- bitfield() counts from the most significant bit; using it avoids the
    -- legacy `bit` library, kept only as a compatibility shim in Lua 5.4.
    local reserved = buffer(0, 1):bitfield(0, 3)   -- bits [7:5]
    local version  = buffer(0, 1):bitfield(3, 2)   -- bits [4:3]
    local op       = buffer(0, 1):bitfield(5, 3)   -- bits [2:0]

    local flags    = buffer(1, 1):uint()
    local data_len = buffer(2, 2):uint()
    local group_id = buffer(4, 2):uint()
    local seq      = buffer(6, 1):uint()
    local cmd_id   = buffer(7, 1):uint()

    -- Build a human-readable summary for the packet list column
    local op_str    = lookup(op_names,    op,       "Op(%d)")
    local group_str = lookup(group_names, group_id, "Group(%d)")
    local cmd_str   = lookup_cmd(group_id, cmd_id)

    pinfo.cols.info:set(
        string.format("[%s] %s / %s  seq=%d  len=%d",
                      op_str, group_str, cmd_str, seq, data_len)
    )

    -- Build the protocol tree
    local subtree = tree:add(smp_proto, buffer(0, pkt_len), "SMP MCUmgr Protocol")

    -- Correlate requests (even op) and responses (odd op) by endpoint
    -- pair + group + command + sequence number
    local is_response = (op % 2) == 1
    local exchange = string.format("%d/%d/%d", group_id, cmd_id, seq)
    if not pinfo.visited then
        if is_response then
            local key = tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
                .. ">" .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
                .. "|" .. exchange
            local request_frame = pending_requests[key]
            if request_frame then
                exchange_request[pinfo.number] = request_frame
                exchange_response[request_frame] = pinfo.number
                pending_requests[key] = nil
            end
        else
            local key = tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
                .. ">" .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
                .. "|" .. exchange
            pending_requests[key] = pinfo.number
        end
    end
    if exchange_response[pinfo.number] then
        subtree:add(f_response_in,
            exchange_response[pinfo.number]):set_generated()
    elseif exchange_request[pinfo.number] then
        subtree:add(f_request_in,
            exchange_request[pinfo.number]):set_generated()
    end

    -- Header subtree
    local hdr = subtree:add(buffer(0, 8), "SMP Header")

    -- Byte 0 sub-fields
    local b0_item = hdr:add(buffer(0, 1),
        string.format("Byte 0: OP=%d (%s), Version=%d, Reserved=0x%x",
                      op, op_str, version, reserved))
    b0_item:add(f_op,       buffer(0, 1)):set_text(
        string.format("Operation Code: %d (%s)", op, op_str))
    b0_item:add(f_version,  buffer(0, 1)):set_text(
        string.format("SMP Version: %d", version))
    b0_item:add(f_reserved, buffer(0, 1)):set_text(
        string.format("Reserved: 0x%x", reserved))

    hdr:add(f_flags,  buffer(1, 1)):set_text(
        string.format("Flags: 0x%02x", flags))
    hdr:add(f_len,    buffer(2, 2)):set_text(
        string.format("Data Length: %d bytes", data_len))
    hdr:add(f_group,  buffer(4, 2)):set_text(
        string.format("Group ID: %d (%s)", group_id, group_str))
    hdr:add(f_seq,    buffer(6, 1)):set_text(
        string.format("Sequence Number: %d", seq))
    hdr:add(f_id,     buffer(7, 1)):set_text(
        string.format("Command ID: %d (%s)", cmd_id, cmd_str))

    -- CBOR Payload (if present)
    local payload_len = pkt_len - 8
    if payload_len > 0 then
        local payload_buf = buffer(8, payload_len)
        local payload_item = subtree:add(f_payload, payload_buf)
        payload_item:set_text(
            string.format("CBOR Payload (%d bytes)", payload_len))

        -- Attempt to hand off to Wireshark's built-in CBOR dissector if
        -- available (Dissector.get raises when the name is unknown)
        local found, cbor_dissector = pcall(Dissector.get, "cbor")
        if found and cbor_dissector then
            local ok, err = pcall(function()
                cbor_dissector:call(payload_buf:tvb(), pinfo, subtree)
            end)
            if not ok then
                subtree:add_proto_expert_info(e_cbor_failed,
                    "CBOR decode failed: " .. tostring(err))
            end
        end
    end

    -- Expert info for unusual conditions
    if data_len ~= payload_len then
        subtree:add_proto_expert_info(e_len_mismatch,
            string.format(
                "Header Data Length (%d) does not match actual payload (%d)",
                data_len, payload_len))
    end

    return pkt_len
end

-- ─── Registration ────────────────────────────────────────────────────────────
-- The UDP port is a protocol preference (default 1337); the protocol is
-- also offered via Decode As for other ports.

local udp_table = DissectorTable.get("udp.port")

smp_proto.prefs.port = Pref.uint(
    "port", 1337, "UDP port carrying SMP/MCUmgr traffic")

local bound_port = nil
local function bind_port()
    if bound_port then
        udp_table:remove(bound_port, smp_proto)
    end
    bound_port = smp_proto.prefs.port
    if bound_port and bound_port > 0 then
        udp_table:add(bound_port, smp_proto)
    end
end
function smp_proto.prefs_changed()
    bind_port()
end
bind_port()
udp_table:add_for_decode_as(smp_proto)

print("[smp_mcumgr] SMP MCUmgr dissector loaded - port " .. tostring(bound_port))

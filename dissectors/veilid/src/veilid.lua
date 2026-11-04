-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Veilid protocol dissector for Wireshark.
--
-- This is the ONLY file that registers anything. Everything under veilid/ is
-- a plain module that defines and returns a table; Wireshark auto-loads those
-- files too (it scans plugin subdirectories recursively), so they must stay
-- inert until required from here. See CLAUDE.md.
--
-- Versioning rule: no file except veilid/versions.lua (and the registry
-- entries in envelope.lua / receipt.lua) may name a concrete version FourCC.
-- "ENV0"/"RCP0"/"VLD0" carry digits that veilid-core will increment.

-- Resolve sibling modules relative to this script. Wireshark exposes no
-- script-path global, so derive it from the debug info of this chunk.
local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("^(.*)[/\\][^/\\]*$") or "."
package.path = script_dir .. "/?.lua;" .. package.path

local util = require "veilid.util"
local versions = require "veilid.versions"
local fields = require "veilid.fields"
local assembly = require "veilid.assembly"
local transport = require "veilid.transport"
local nodeid = require "veilid.nodeid"
local stats = require "veilid.stats"
local secrets = require "veilid.secrets"
local decrypt = require "veilid.decrypt"
-- These two exist to populate the version registry; nothing references their
-- return values.
require "veilid.envelope" -- registers the ENV0 layout
require "veilid.receipt"  -- registers the RCP0 layout

--------------------------------------------------------------------------------
-- Protocol + fields
--------------------------------------------------------------------------------

local PROTO_FILTER_NAME = "veilid"

local veilid = Proto(PROTO_FILTER_NAME, "Veilid")

-- Zero-length UDP datagrams are Veilid NAT hole-punch probes, but Wireshark's
-- UDP dissector never calls a subdissector when the payload is empty, so a
-- port registration cannot see them. A narrowly-gated postdissector is the
-- only way to label them. It borrows the veilid.* field namespace and adds the
-- veilid protocol item itself, so `-Y veilid` and `-Y veilid.hole_punch` both
-- work on these frames.
local veilid_hp = Proto("veilid_holepunch", "Veilid Hole Punch")

-- Wireshark binds a dissector table entry to a Proto, not to a bare function,
-- so each transport needs its own Proto object. They all add items using the
-- veilid.* field namespace and insert the `veilid` protocol item, so a single
-- `-Y veilid` filter still matches every transport.
local veilid_tcp = Proto("veilid_tcp", "Veilid over TCP")
local veilid_ws = Proto("veilid_ws", "Veilid over WebSocket")

local f = fields.build()
veilid.fields = f
local e = fields.build_experts(PROTO_FILTER_NAME)
veilid.experts = e

--------------------------------------------------------------------------------
-- Preferences
--------------------------------------------------------------------------------

local DEFAULT_PORTS = "5150"

veilid.prefs.udp_ports = Pref.range("UDP ports", DEFAULT_PORTS,
  "UDP port range carrying Veilid traffic", 65535)
veilid.prefs.tcp_ports = Pref.range("TCP ports", DEFAULT_PORTS,
  "TCP port range carrying Veilid traffic (raw TCP and WebSocket)", 65535)
veilid.prefs.heuristics = Pref.bool("Heuristic detection", true,
  "Detect Veilid on ports outside the configured ranges. Heuristics only "
    .. "claim a packet containing a readable message header, then pin the "
    .. "conversation.")
veilid.prefs.network_key = Pref.string("Private network key (base64)", "",
  "Shared secret for a private Veilid network. veilid-core XOR-masks the "
    .. "nonce, sender ID and recipient ID with this key; leave empty for the "
    .. "public network.")
veilid.prefs.self_node_id = Pref.string("Local node ID", "",
  "Node ID of the capturing node, e.g. VLD0:<base64url>. Used to label "
    .. "traffic direction.")
veilid.prefs.secrets_file = Pref.string("Shared secrets file", "",
  "Path to a file of pre-derived shared secrets produced by "
    .. "tools/veilid-secrets.py. Enables decryption of envelope operations. "
    .. "Lines: <crypto_kind> <peer_node_id_base64url> <shared_secret_hex>")

--------------------------------------------------------------------------------
-- Dissector context
--------------------------------------------------------------------------------

-- Single table threaded through every module so they never reach for globals.
local ctx = {
  proto = veilid,
  fields = f,
  experts = e,
  network_key = nil,
  self_node_id = nil,
}

local registered_udp_ports = nil
local registered_tcp_ports = nil
local udp_port_ranges = {}

--- Re-read preferences into the context. Called at init so a preference change
--- takes effect on the next redissection.
local function refresh_prefs()
  udp_port_ranges = util.parse_ranges(veilid.prefs.udp_ports)

  local nk = veilid.prefs.network_key
  if nk and nk ~= "" then
    local bytes, err = util.base64url_decode(nk)
    if bytes then
      ctx.network_key = bytes
    else
      ctx.network_key = nil
      report_failure("Veilid: could not decode the private network key: " .. tostring(err))
    end
  else
    ctx.network_key = nil
  end

  local self_id = veilid.prefs.self_node_id
  ctx.self_node_id = (self_id ~= "" ) and self_id or nil

  local path = veilid.prefs.secrets_file
  local loaded, serr = secrets.load(path ~= "" and path or nil)
  if serr then
    report_failure("Veilid: shared secrets file: " .. serr)
  end
  ctx.secrets_loaded = loaded
end

--------------------------------------------------------------------------------
-- Message dispatch (transport-independent)
--------------------------------------------------------------------------------

--- Dissect one complete Veilid message.
--
-- Only bytes 0x00..0x04 are version-independent, so this function reads the
-- FourCC, resolves a layout from the registry, and delegates. It deliberately
-- distinguishes three outcomes: not-Veilid (return 0), known family with an
-- unknown version (dissect the header, note, consume), and fully known.
--
-- @param tvb tvb covering exactly one message
-- @param transport "UDP" | "TCP" | "WebSocket"
-- @return number bytes consumed (0 if this is not a Veilid message)
local function dissect_message(tvb, pinfo, tree, transport)
  local len = tvb:len()
  if len < versions.FOURCC_LEN then return 0 end

  local fourcc_range = tvb(0, versions.FOURCC_LEN)
  local info = versions.classify(fourcc_range:raw())
  if not info then return 0 end

  local display_fourcc = util.printable_fourcc(info.fourcc)

  local subtree = tree:add(veilid, tvb())
  subtree:set_text(("Veilid %s (%s)"):format(info.family_name, display_fourcc))
  subtree:add(f.version, fourcc_range, display_fourcc)
  subtree:add(f.family, fourcc_range, info.family):set_generated()
  if info.version_num then
    subtree:add(f.version_num, fourcc_range, info.version_num):set_generated()
  end
  if transport then
    subtree:add(f.transport, fourcc_range, transport):set_generated()
  end

  pinfo.cols.protocol = "Veilid"

  -- Known family, unknown version. Still Veilid; say so and move on rather
  -- than reporting malformed bytes we simply do not understand yet.
  if not info.layout then
    subtree:append_text(" [unsupported version]")
    subtree:add_proto_expert_info(e.unsupported_version,
      ("%s is a recognized Veilid %s family FourCC but this dissector has no "
        .. "layout for version %q"):format(display_fourcc,
        info.family, info.version_char))
    if len > versions.FOURCC_LEN then
      subtree:add(f.unsupported_body, tvb(versions.FOURCC_LEN))
    end
    pinfo.cols.info:set(("%s (unsupported version, %d bytes)"):format(display_fourcc, len))
    return len
  end

  local summary = info.layout.dissect(ctx, tvb, pinfo, subtree)
  if summary then
    summary.transport = transport

    -- Direction is only meaningful once we know which key is ours.
    local self_id = ctx.self_node_id
    if self_id then
      local direction
      if summary.sender == self_id then
        direction = "outbound"
      elseif summary.recipient == self_id then
        direction = "inbound"
      end
      if direction then
        subtree:add(f.direction, fourcc_range, direction):set_generated()
        summary.direction = direction
      end
    end

    -- Accumulate once per message, not once per redissection.
    if not pinfo.visited then
      nodeid.observe(pinfo, summary)
    end

    ctx.set_info_column(pinfo, summary)
  end
  return len
end

--- Compose the info column for a dissected message.
function ctx.set_info_column(pinfo, s)
  local parts = { s.version }
  if s.sender and s.recipient then
    parts[#parts + 1] = ("%s \u{2192} %s"):format(
      util.short_key(s.sender), util.short_key(s.recipient))
  elseif s.sender then
    -- Receipts name only a sender; they are addressed by the flow they
    -- arrive on.
    parts[#parts + 1] = ("from %s"):format(util.short_key(s.sender))
  end
  if s.body_len and s.body_len > 0 then
    parts[#parts + 1] = ("%d B ops"):format(s.body_len)
  end
  if s.extra_data_len and s.extra_data_len > 0 then
    parts[#parts + 1] = ("%d B extra"):format(s.extra_data_len)
  end
  pinfo.cols.info:set(table.concat(parts, "  "))
end

ctx.dissect_message = dissect_message

--------------------------------------------------------------------------------
-- UDP
--------------------------------------------------------------------------------

--- Dissect a Veilid UDP datagram.
-- @return number bytes consumed, 0 if this is not Veilid
local function dissect_udp(tvb, pinfo, tree)
  local len = tvb:len()

  -- Zero-length datagrams are hole-punch probes. veilid-core sends these
  -- deliberately and drops them silently on receipt, so they are valid
  -- protocol traffic, not truncated packets.
  -- Returning 0 here would tell Wireshark "not mine" and revert the columns,
  -- so signal a full consume by returning nothing.
  if len == 0 then
    pinfo.cols.protocol = "Veilid"
    pinfo.cols.info:set("NAT hole punch")
    local t = tree:add(veilid, tvb())
    t:set_text("Veilid NAT Hole Punch")
    t:add(f.hole_punch, tvb(0, 0), true):set_generated()
    return
  end

  local h = assembly.parse_header(tvb)
  if not h then return 0 end

  local payload = tvb(assembly.HEADER_LEN)

  -- Decide whether this is ours BEFORE touching the tree. Rejecting after
  -- adding items leaves a stray half-built framing subtree on packets that
  -- then fall through to another dissector.
  --
  -- Any fragment at offset 0 starts with the message FourCC, so it can be
  -- checked directly. Later fragments carry no magic and are claimed on the
  -- structural validity of the assembly header alone.
  if h.offset == 0 and payload:len() >= versions.FOURCC_LEN then
    if not versions.classify(payload(0, versions.FOURCC_LEN):raw()) then
      return 0
    end
  end

  if not pinfo.visited then assembly.count(h) end
  assembly.add_header_tree(ctx, tvb, tree, h)

  if h.complete then
    dissect_message(payload, pinfo, tree, "UDP")
    return len
  end

  -- Fragment: accumulate on the first pass only, then render from the cache so
  -- redissection is stable.
  pinfo.cols.protocol = "Veilid"

  local conflict = false
  if not pinfo.visited then
    _, conflict = assembly.accumulate(pinfo, h, payload:raw())
  end

  local result = assembly.result_for(pinfo.number)
  local frag = assembly.fragment_info(pinfo.number)

  if conflict then
    tree:add_proto_expert_info(e.fragment_conflict,
      ("two fragments at offset %d of sequence %d carry different bytes")
        :format(h.offset, h.seq))
  end

  if result then
    -- This frame carried the last missing bytes: reassemble and dissect.
    assembly.add_reassembly_tree(ctx, tree, result, tvb)
    local reassembled = ByteArray.new(result.data, true):tvb("Reassembled Veilid Message")
    dissect_message(reassembled, pinfo, tree, "UDP")
    pinfo.cols.info:prepend(("[%d frags] "):format(#result.frames))
    return len
  end

  local desc = ("Message fragment %d-%d of %d (seq %d)")
    :format(h.offset, h.offset + h.payload_len - 1, h.total, h.seq)
  if frag then
    tree:add(f.asm_reassembled_in, tvb(0, 0), frag.reassembled_in):set_generated()
    desc = desc .. (" [reassembled in frame %d]"):format(frag.reassembled_in)
  elseif pinfo.visited then
    -- Only meaningful on a redissection: during the initial forward pass the
    -- completing fragment simply has not been read yet, so "incomplete" would
    -- be a false alarm on every non-final fragment. By the time a frame is
    -- revisited the whole file has been indexed, and a still-missing
    -- reassembly is genuinely missing.
    tree:add_proto_expert_info(e.fragment_incomplete,
      ("no frame in this capture completes sequence %d"):format(h.seq))
    desc = desc .. " [never reassembled]"
  else
    desc = desc .. " [reassembly pending]"
  end
  pinfo.cols.info:set(desc)
  return len
end

veilid.dissector = function(tvb, pinfo, tree)
  return dissect_udp(tvb, pinfo, tree)
end

veilid_tcp.dissector = function(tvb, pinfo, tree)
  return transport.dissect_tcp(ctx, tvb, pinfo, tree)
end

veilid_ws.dissector = function(tvb, pinfo, tree)
  return transport.dissect_ws(ctx, tvb, pinfo, tree)
end

--------------------------------------------------------------------------------
-- Hole-punch postdissector
--------------------------------------------------------------------------------

local fe_udp_length = Field.new("udp.length")
local fe_udp_srcport = Field.new("udp.srcport")
local fe_udp_dstport = Field.new("udp.dstport")

-- A UDP header is 8 bytes, so udp.length == 8 means a zero-byte payload.
local UDP_HEADER_LEN = 8

function veilid_hp.dissector(tvb, pinfo, tree)
  local ulen = fe_udp_length()
  if not ulen or ulen.value ~= UDP_HEADER_LEN then return end

  local sp, dp = fe_udp_srcport(), fe_udp_dstport()
  local sport = sp and sp.value
  local dport = dp and dp.value
  if not (util.in_ranges(udp_port_ranges, sport) or util.in_ranges(udp_port_ranges, dport)) then
    return
  end

  pinfo.cols.protocol = "Veilid"
  pinfo.cols.info:set("NAT hole punch")
  local t = tree:add(veilid, tvb(0, 0))
  t:set_text("Veilid NAT Hole Punch")
  t:add(f.hole_punch, tvb(0, 0), true):set_generated()
end

--------------------------------------------------------------------------------
-- Registration
--------------------------------------------------------------------------------

function veilid.init()
  refresh_prefs()
  assembly.reset()
  nodeid.reset()
  decrypt.reset()
end

ctx.decrypt_body = decrypt.decrypt_body

--- Bind the configured port ranges, replacing any previous binding.
local function apply_port_prefs()
  local udp_table = DissectorTable.get("udp.port")
  if registered_udp_ports then
    udp_table:remove(registered_udp_ports, veilid)
  end
  registered_udp_ports = veilid.prefs.udp_ports
  udp_table:add(registered_udp_ports, veilid)

  local tcp_table = DissectorTable.get("tcp.port")
  local ws_table = DissectorTable.get("ws.port")
  if registered_tcp_ports then
    tcp_table:remove(registered_tcp_ports, veilid_tcp)
    ws_table:remove(registered_tcp_ports, veilid_ws)
  end
  registered_tcp_ports = veilid.prefs.tcp_ports
  tcp_table:add(registered_tcp_ports, veilid_tcp)
  -- ws.port is keyed on the underlying TCP port, so Veilid's WebSocket
  -- transport shares the TCP range.
  ws_table:add(registered_tcp_ports, veilid_ws)
end

function veilid.prefs_changed()
  refresh_prefs()
  apply_port_prefs()
end

--------------------------------------------------------------------------------
-- Heuristics
--------------------------------------------------------------------------------

-- Gated on the preference so a user seeing a false positive can switch them
-- off without losing port-based decoding.
veilid:register_heuristic("udp", function(tvb, pinfo, tree)
  if not veilid.prefs.heuristics then return false end
  return transport.heuristic_udp(ctx, veilid, tvb, pinfo, tree)
end)

veilid_tcp:register_heuristic("tcp", function(tvb, pinfo, tree)
  if not veilid.prefs.heuristics then return false end
  return transport.heuristic_tcp(ctx, veilid_tcp, tvb, pinfo, tree)
end)

veilid_ws:register_heuristic("ws", function(tvb, pinfo, tree)
  if not veilid.prefs.heuristics then return false end
  return transport.heuristic_ws(ctx, veilid_ws, tvb, pinfo, tree)
end)

-- Allow manual "Decode As ..." for captures on unusual ports.
DissectorTable.get("udp.port"):add_for_decode_as(veilid)
DissectorTable.get("tcp.port"):add_for_decode_as(veilid_tcp)

refresh_prefs()
apply_port_prefs()
register_postdissector(veilid_hp)
stats.register(ctx, nodeid, assembly)

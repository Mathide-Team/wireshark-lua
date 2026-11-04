-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/assembly.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Veilid UDP framing: the veilid-tools AssemblyBuffer header.
--
-- Every Veilid UDP datagram carries an 8-byte big-endian header before the
-- message. A datagram is a complete message iff offset == 0 and length equals
-- the payload size; otherwise it is one fragment of a larger message.
--
--   0x00  u8   version   (VERSION_1 = 1)
--   0x01  u8   reserved  (0)
--   0x02  u16  seq       per-peer message sequence
--   0x04  u16  offset    this fragment's offset into the message
--   0x06  u16  length    TOTAL assembled message length
--
-- Fragment payloads are 1272 bytes (1280 - 8). Zero-length datagrams are NAT
-- hole-punch probes, not errors.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local M = {}

M.HEADER_LEN = 8
M.VERSION_1 = 1
M.FRAGMENT_PAYLOAD_LEN = 1272

local OFF_VERSION = 0x00
local OFF_FLAGS = 0x01
local OFF_SEQ = 0x02
local OFF_OFFSET = 0x04
local OFF_TOTAL = 0x06

--- Parse and structurally validate the assembly header.
-- Pure: takes a tvb, touches no dissection state, so heuristics can call it
-- cheaply before deciding whether to claim a packet.
-- @return table|nil header, string|nil reason
function M.parse_header(tvb)
  local len = tvb:len()
  if len < M.HEADER_LEN then return nil, "shorter than the 8-byte assembly header" end

  local h = {
    version = tvb(OFF_VERSION, 1):uint(),
    flags = tvb(OFF_FLAGS, 1):uint(),
    seq = tvb(OFF_SEQ, 2):uint(),
    offset = tvb(OFF_OFFSET, 2):uint(),
    total = tvb(OFF_TOTAL, 2):uint(),
  }
  h.payload_len = len - M.HEADER_LEN

  if h.version ~= M.VERSION_1 then
    return nil, ("unsupported assembly version %d"):format(h.version)
  end
  if h.flags ~= 0 then
    return nil, ("reserved assembly byte is %#04x, expected 0"):format(h.flags)
  end
  if h.payload_len == 0 then
    return nil, "assembly header with no payload"
  end
  if h.offset + h.payload_len > h.total then
    return nil, ("fragment [%d,%d) overruns the declared total of %d")
      :format(h.offset, h.offset + h.payload_len, h.total)
  end

  h.complete = (h.offset == 0 and h.payload_len == h.total)
  return h
end

--- Add the assembly header to the tree.
function M.add_header_tree(ctx, tvb, tree, h)
  local f = ctx.fields
  local sub = tree:add(ctx.proto, tvb(0, M.HEADER_LEN))
  sub:set_text(("Veilid UDP Framing (seq %d, %s)"):format(
    h.seq,
    h.complete and "complete"
      or ("fragment %d-%d of %d"):format(h.offset, h.offset + h.payload_len - 1, h.total)))

  sub:add(f.asm_version, tvb(OFF_VERSION, 1))
  sub:add(f.asm_flags, tvb(OFF_FLAGS, 1))
  sub:add(f.asm_seq, tvb(OFF_SEQ, 2))
  sub:add(f.asm_offset, tvb(OFF_OFFSET, 2))
  sub:add(f.asm_total_len, tvb(OFF_TOTAL, 2))
  sub:add(f.asm_frag_len, tvb(OFF_OFFSET, 2), h.payload_len):set_generated()
  sub:add(f.asm_fragmented, tvb(0, M.HEADER_LEN), not h.complete):set_generated()

  return sub
end

--------------------------------------------------------------------------------
-- Reassembly
--------------------------------------------------------------------------------
--
-- Wireshark's Lua bindings expose no fragment-table API, so reassembly is done
-- by hand. Two rules keep this stable under Wireshark's non-linear access
-- patterns (clicking around, filtering, two-pass tshark):
--
--   1. Accumulate ONLY when pinfo.visited is false, so a frame is never
--      counted twice.
--   2. Cache the finished result keyed by the frame that completed it, so
--      every later redissection renders identically without re-accumulating.
--
-- All state is cleared from proto.init (i.e. on every reload/refilter).

-- key -> { total, chunks = {offset -> bytes}, order = {offsets}, frames = {} }
local pending = {}
-- completing frame number -> { data, frames, total }
local results = {}
-- any fragment frame number -> { reassembled_in, index, count }
local frag_index = {}

local counters

function M.reset()
  pending = {}
  results = {}
  frag_index = {}
  counters = {
    datagrams = 0, complete = 0, fragments = 0,
    reassembled = 0, conflicts = 0,
  }
end

M.reset()

--- Count a datagram. Call once per datagram, on the first pass only.
function M.count(h)
  counters.datagrams = counters.datagrams + 1
  if h.complete then
    counters.complete = counters.complete + 1
  else
    counters.fragments = counters.fragments + 1
  end
end

--- Snapshot for the stats tap. `incomplete` is derived at read time from
-- whatever is still sitting in the pending table.
function M.stats()
  local s = {}
  for k, v in pairs(counters) do s[k] = v end
  s.incomplete = M.pending_count()
  return s
end

local function flow_key(pinfo, seq)
  return ("%s:%d>%s:%d#%d"):format(
    tostring(pinfo.src), pinfo.src_port, tostring(pinfo.dst), pinfo.dst_port, seq)
end

--- Walk the collected chunks from offset 0 and return the assembled message,
-- or nil if there is a gap. Verifying contiguity explicitly is stricter than
-- summing lengths -- overlapping fragments could otherwise sum to `total`
-- while leaving a hole.
local function try_assemble(st)
  local parts, off = {}, 0
  while off < st.total do
    local chunk = st.chunks[off]
    if not chunk then return nil end
    parts[#parts + 1] = chunk
    off = off + #chunk
  end
  if off ~= st.total then return nil end
  return table.concat(parts)
end

--- Feed one fragment into the reassembler.
-- @return table|nil result { data, frames, total } when this frame completes a
--         message, plus a boolean indicating a conflicting overlap
function M.accumulate(pinfo, h, payload_bytes)
  local key = flow_key(pinfo, h.seq)
  local conflict = false

  local st = pending[key]
  -- A different total under the same key means the sequence number was reused
  -- for a new message; start over rather than blending two messages.
  if st and st.total ~= h.total then
    st = nil
  end
  if not st then
    st = { total = h.total, chunks = {}, frames = {} }
    pending[key] = st
  end

  local existing = st.chunks[h.offset]
  if existing then
    if existing ~= payload_bytes then
      counters.conflicts = counters.conflicts + 1
      -- Same offset, different bytes: treat as the start of a new message
      -- reusing this sequence number.
      conflict = true
      st = { total = h.total, chunks = {}, frames = {} }
      pending[key] = st
    end
  end

  if not st.chunks[h.offset] then
    st.chunks[h.offset] = payload_bytes
    st.frames[#st.frames + 1] = pinfo.number
  end

  local data = try_assemble(st)
  if not data then return nil, conflict end

  pending[key] = nil
  counters.reassembled = counters.reassembled + 1
  local result = { data = data, frames = st.frames, total = st.total }
  results[pinfo.number] = result
  for i, frame in ipairs(st.frames) do
    frag_index[frame] = {
      reassembled_in = pinfo.number,
      index = i,
      count = #st.frames,
    }
  end
  return result, conflict
end

--- Result cached for the frame that completed a message, if any.
function M.result_for(frame_number)
  return results[frame_number]
end

--- Position of a frame within its message, once known.
function M.fragment_info(frame_number)
  return frag_index[frame_number]
end

--- Add the "reassembled from" list to the completing frame's tree.
function M.add_reassembly_tree(ctx, tree, result, tvb)
  local f = ctx.fields
  local sub = tree:add(ctx.proto, tvb(0, 0))
  sub:set_text(("Reassembled Veilid Message (%d bytes from %d fragments)")
    :format(result.total, #result.frames))
  sub:set_generated()
  for _, frame in ipairs(result.frames) do
    sub:add(f.asm_fragment, tvb(0, 0), frame):set_generated()
  end
  sub:add(f.asm_fragment_count, tvb(0, 0), #result.frames):set_generated()
  sub:add(f.asm_reassembled_len, tvb(0, 0), result.total):set_generated()
  return sub
end

--- Number of messages still awaiting fragments (never completed in capture).
function M.pending_count()
  local n = 0
  for _ in pairs(pending) do n = n + 1 end
  return n
end

return M

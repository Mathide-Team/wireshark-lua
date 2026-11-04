-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/transport.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Stream and datagram transports: TCP framing, WebSocket, and the heuristics
-- that find Veilid on ports outside the configured range.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local versions = require "veilid.versions"
local assembly = require "veilid.assembly"

local M = {}

-- veilid-core network/native/protocol/tcp.rs:
--   let header = [b'V', b'L', len as u8, (len >> 8) as u8];
-- Not version-bearing -- this is a fixed frame magic, unlike the ENV/RCP/VLD
-- FourCCs -- so a literal is correct here.
M.FRAME_MAGIC = "VL"
M.FRAME_HEADER_LEN = 4

--------------------------------------------------------------------------------
-- TCP
--------------------------------------------------------------------------------

--- Dissect Veilid frames inside a TCP segment.
--
-- Handles both directions of the mismatch between TCP segments and Veilid
-- frames: several frames per segment, and frames split across segments. On a
-- short read it asks Wireshark for more data via desegment_offset/len rather
-- than guessing.
--
-- @return number bytes consumed; 0 rejects the segment so other dissectors run
function M.dissect_tcp(ctx, tvb, pinfo, tree)
  local len = tvb:len()
  local offset = 0
  local messages = 0
  local max_msg = versions.global_max_size()
  local min_msg = versions.global_min_size()

  while offset < len do
    local remaining = len - offset

    if remaining < M.FRAME_HEADER_LEN then
      pinfo.desegment_offset = offset
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      return len
    end

    if tvb(offset, 2):raw() ~= M.FRAME_MAGIC then
      -- Garbage where a frame header should be. If we have not decoded
      -- anything yet this is simply not a Veilid stream; hand it back.
      if messages == 0 then return 0 end
      break
    end

    local msg_len = tvb(offset + 2, 2):le_uint()
    if msg_len < min_msg or msg_len > max_msg then
      if messages == 0 then return 0 end
      break
    end

    if remaining - M.FRAME_HEADER_LEN < msg_len then
      pinfo.desegment_offset = offset
      pinfo.desegment_len = msg_len - (remaining - M.FRAME_HEADER_LEN)
      return len
    end

    -- Before claiming the stream, confirm the first framed payload really is
    -- a Veilid message. "VL" plus a plausible length is only 4 bytes of
    -- evidence and would false-positive on binary traffic.
    local body_off = offset + M.FRAME_HEADER_LEN
    if messages == 0 then
      if not versions.classify(tvb(body_off, versions.FOURCC_LEN):raw()) then
        return 0
      end
    end

    local framing = tree:add(ctx.proto, tvb(offset, M.FRAME_HEADER_LEN + msg_len))
    framing:set_text(("Veilid TCP Framing (%d bytes)"):format(msg_len))
    framing:add(ctx.fields.tcp_magic, tvb(offset, 2), M.FRAME_MAGIC)
    framing:add_le(ctx.fields.tcp_len, tvb(offset + 2, 2))

    ctx.dissect_message(tvb(body_off, msg_len), pinfo, tree, "TCP")
    messages = messages + 1
    offset = offset + M.FRAME_HEADER_LEN + msg_len
  end

  if messages > 1 then
    pinfo.cols.info:prepend(("[%d msgs] "):format(messages))
  end
  return offset
end

--------------------------------------------------------------------------------
-- WebSocket
--------------------------------------------------------------------------------

--- Dissect a Veilid message carried in a binary WebSocket frame.
-- WebSocket is already message-framed, so there is no length prefix and no
-- AssemblyBuffer -- the payload is exactly one message.
function M.dissect_ws(ctx, tvb, pinfo, tree)
  local len = tvb:len()
  if len < versions.FOURCC_LEN then return 0 end
  if not versions.classify(tvb(0, versions.FOURCC_LEN):raw()) then return 0 end
  ctx.dissect_message(tvb, pinfo, tree, "WebSocket")
  return len
end

--------------------------------------------------------------------------------
-- Heuristics
--------------------------------------------------------------------------------
--
-- Veilid peers do not all run on 5150 (this project's reference capture has a
-- peer on 54994), so port registration alone under-detects. Heuristics have to
-- be strict: they are offered every packet on the network, and a false claim
-- corrupts an unrelated protocol's dissection.
--
-- The rule used here is "claim only on positive identification, then pin the
-- conversation". A heuristic fires only for a packet that contains a readable
-- message FourCC; on success it sets pinfo.conversation so the remaining
-- packets of that flow -- including later fragments, which carry no magic of
-- their own -- are routed to us directly.

--- UDP heuristic.
function M.heuristic_udp(ctx, proto, tvb, pinfo, tree)
  local h = assembly.parse_header(tvb)
  if not h then return false end

  -- Only offset-0 datagrams expose a FourCC. Requiring one keeps the
  -- heuristic honest; later fragments arrive via the pinned conversation.
  if h.offset ~= 0 then return false end

  local payload = tvb(assembly.HEADER_LEN)
  if payload:len() < versions.FOURCC_LEN then return false end

  local info = versions.classify(payload(0, versions.FOURCC_LEN):raw())
  if not info then return false end

  pinfo.conversation = proto
  proto.dissector(tvb, pinfo, tree)
  return true
end

--- TCP heuristic.
function M.heuristic_tcp(ctx, proto, tvb, pinfo, tree)
  local len = tvb:len()
  if len < M.FRAME_HEADER_LEN + versions.FOURCC_LEN then return false end
  if tvb(0, 2):raw() ~= M.FRAME_MAGIC then return false end

  local msg_len = tvb(2, 2):le_uint()
  if msg_len < versions.global_min_size() or msg_len > versions.global_max_size() then
    return false
  end
  if not versions.classify(tvb(M.FRAME_HEADER_LEN, versions.FOURCC_LEN):raw()) then
    return false
  end

  pinfo.conversation = proto
  proto.dissector(tvb, pinfo, tree)
  return true
end

--- WebSocket heuristic. The websocket dissector hands us the unmasked payload.
function M.heuristic_ws(ctx, proto, tvb, pinfo, tree)
  if tvb:len() < versions.FOURCC_LEN then return false end
  if not versions.classify(tvb(0, versions.FOURCC_LEN):raw()) then return false end
  proto.dissector(tvb, pinfo, tree)
  return true
end

return M

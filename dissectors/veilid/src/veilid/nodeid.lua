-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/nodeid.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Node registry and per-peer accounting.
--
-- Builds a picture of which node IDs were seen, where, and how much traffic
-- each exchanged. Populated as a side effect of dissection and read back by
-- stats.lua for the Statistics > Veilid taps.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local M = {}

-- node id string -> record
local nodes = {}
-- how many messages we have accounted for, so a tap can report coverage
local totals = { messages = 0, bytes = 0 }

function M.reset()
  nodes = {}
  totals = { messages = 0, bytes = 0 }
end

local function record_for(id)
  local rec = nodes[id]
  if not rec then
    rec = {
      id = id,
      sent = 0, recv = 0,
      bytes_sent = 0, bytes_recv = 0,
      first_frame = nil, last_frame = nil,
      first_ts = nil, last_ts = nil,
      addresses = {}, address_list = {},
      transports = {}, transport_list = {},
      max_abs_skew = 0,
    }
    nodes[id] = rec
  end
  return rec
end

local function note_address(rec, addr)
  if addr and not rec.addresses[addr] then
    rec.addresses[addr] = true
    rec.address_list[#rec.address_list + 1] = addr
  end
end

local function note_transport(rec, transport)
  if transport and not rec.transports[transport] then
    rec.transports[transport] = true
    rec.transport_list[#rec.transport_list + 1] = transport
  end
end

--- Record one dissected message.
--
-- Only called when pinfo.visited is false, so counts do not inflate when
-- Wireshark redissects a frame.
function M.observe(pinfo, summary)
  local size = summary.size or 0
  totals.messages = totals.messages + 1
  totals.bytes = totals.bytes + size

  local src = tostring(pinfo.src)
  local dst = tostring(pinfo.dst)

  if summary.sender then
    local rec = record_for(summary.sender)
    rec.sent = rec.sent + 1
    rec.bytes_sent = rec.bytes_sent + size
    note_address(rec, src)
    note_transport(rec, summary.transport)
    if not rec.first_frame then
      rec.first_frame = pinfo.number
      rec.first_ts = pinfo.abs_ts
    end
    rec.last_frame = pinfo.number
    rec.last_ts = pinfo.abs_ts
    if summary.skew and math.abs(summary.skew) > rec.max_abs_skew then
      rec.max_abs_skew = math.abs(summary.skew)
    end
  end

  if summary.recipient then
    local rec = record_for(summary.recipient)
    rec.recv = rec.recv + 1
    rec.bytes_recv = rec.bytes_recv + size
    note_address(rec, dst)
    note_transport(rec, summary.transport)
    if not rec.first_frame then
      rec.first_frame = pinfo.number
      rec.first_ts = pinfo.abs_ts
    end
    rec.last_frame = pinfo.number
    rec.last_ts = pinfo.abs_ts
  end
end

--- All node records, busiest first.
function M.sorted_nodes()
  local list = {}
  for _, rec in pairs(nodes) do list[#list + 1] = rec end
  table.sort(list, function(a, b)
    local at, bt = a.sent + a.recv, b.sent + b.recv
    if at ~= bt then return at > bt end
    return a.id < b.id
  end)
  return list
end

function M.totals()
  return totals
end

--- Infer the capturing node: the ID that appears on both sides of the most
-- conversations is almost always the local node. Used only as a fallback when
-- the user has not set the local-node preference.
function M.infer_local_node()
  local best, best_score
  for _, rec in pairs(nodes) do
    -- A relay or peer is mostly one-directional; the local node both sends
    -- and receives across many peers.
    local score = math.min(rec.sent, rec.recv)
    if not best_score or score > best_score then
      best, best_score = rec, score
    end
  end
  return best and best.id or nil, best_score or 0
end

return M

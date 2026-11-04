-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/stats.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Statistics taps: Statistics > Veilid > ... in the GUI, and
-- `tshark -q -z veilid,peers` / `-z veilid,assembly` on the command line.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local util = require "veilid.util"

local M = {}

local function pad(s, n)
  s = tostring(s)
  if #s >= n then return s end
  return s .. string.rep(" ", n - #s)
end

local function lpad(s, n)
  s = tostring(s)
  if #s >= n then return s end
  return string.rep(" ", n - #s) .. s
end

--- Register both taps.
-- @param ctx dissector context
-- @param nodeid the node registry module
-- @param assembly the reassembly module
function M.register(ctx, nodeid, assembly)
  ------------------------------------------------------------------------------
  -- Peers
  ------------------------------------------------------------------------------
  local function peers_tap()
    local tap = Listener.new("frame")

    function tap.draw()
      local nodes = nodeid.sorted_nodes()
      local totals = nodeid.totals()

      local local_id = ctx.self_node_id
      local inferred = false
      if not local_id then
        local_id = nodeid.infer_local_node()
        inferred = true
      end

      print("")
      print("===================================================================================")
      print("Veilid Peers")
      print(("  %d messages, %d bytes, %d distinct node IDs")
        :format(totals.messages, totals.bytes, #nodes))
      if local_id then
        print(("  local node: %s%s"):format(local_id, inferred and "  (inferred)" or ""))
      end
      print("===================================================================================")
      print(("%s %s %s %s %s %s"):format(
        pad("Node", 48), lpad("Sent", 7), lpad("Recv", 7),
        lpad("Bytes", 11), pad("  Transports", 20), "Addresses"))
      print(string.rep("-", 98))

      for _, rec in ipairs(nodes) do
        local label = rec.id
        if local_id and rec.id == local_id then label = label .. " *" end
        local addrs = table.concat(rec.address_list, ",")
        if #addrs > 40 then addrs = addrs:sub(1, 37) .. "..." end
        print(("%s %s %s %s %s %s"):format(
          pad(util.short_key(label, 12), 48),
          lpad(rec.sent, 7),
          lpad(rec.recv, 7),
          lpad(rec.bytes_sent + rec.bytes_recv, 11),
          pad("  " .. table.concat(rec.transport_list, ","), 20),
          addrs))
      end
      print(string.rep("-", 98))
      print("  * = local node")
      print("")
    end

    function tap.reset() end
  end

  register_stat_cmd_arg("veilid,peers", peers_tap)

  ------------------------------------------------------------------------------
  -- Assembly / reassembly health
  ------------------------------------------------------------------------------
  local function assembly_tap()
    local tap = Listener.new("frame")

    function tap.draw()
      local s = assembly.stats()
      print("")
      print("===================================================================")
      print("Veilid UDP Reassembly")
      print("===================================================================")
      print(("  datagrams seen           : %d"):format(s.datagrams))
      print(("  complete in one datagram : %d"):format(s.complete))
      print(("  fragment datagrams       : %d"):format(s.fragments))
      print(("  messages reassembled     : %d"):format(s.reassembled))
      print(("  fragments per message    : %.2f"):format(
        s.reassembled > 0 and (s.fragments / s.reassembled) or 0))
      print(("  overlap conflicts        : %d"):format(s.conflicts))
      print(("  never completed          : %d  <-- nonzero means lost fragments")
        :format(s.incomplete))
      print("")
    end

    function tap.reset() end
  end

  register_stat_cmd_arg("veilid,assembly", assembly_tap)
end

return M

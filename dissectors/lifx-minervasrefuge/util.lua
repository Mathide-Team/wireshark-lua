-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/util.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
function u16Percent(value)
   return " (" .. (value:le_uint()*100)/0xFFFF .. "%)"
end

function BuildProtoFieldGroup(t)
   for _, pf in ipairs(t) do
      pf[1] = t.key .. "." .. pf[1]

      local newPF = ProtoField[pf.fn](table.unpack(pf))
      t.mod[t.prefix .. pf.id] = newPF

      table.insert(t.mod.packetProtoFields, newPF)
   end
end

function le(tree, pf, buffer)
   return tree:add_le(pf, buffer)
end

DEC = base.DEC
SPACE = base.SPACE
UNICODE = base.UNICODE
NONE = base.NONE

N_TF = {[0]="False", [1]="True"}

function LDMOD(pktypes)
   return {
      dissectorLookups = {},
      packetProtoFields = {},
      lifxPacketTypes = pktypes
   }
end

function addDissector(id, m, fn)
   m.dissectorLookups[id] = fn
end

IGNORE_MARKER = "IGNORE"

function ignore(id, m)
   m.dissectorLookups[id] = IGNORE_MARKER
end

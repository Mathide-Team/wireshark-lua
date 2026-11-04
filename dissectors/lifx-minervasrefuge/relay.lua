-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/relay.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local m = {}
m.packetProtoFields = {}

m.lifxPacketTypes = {
   -- Relay
   [818] = "StateRPower",

   -- Relay [get]
   [816] = "GetRPower",

   -- Relay [set]
   [817] = "SetRPower"
}

local function dissector_name(tree, buffer, pinfo)
end

m.dissectorLookups = {
}

return m

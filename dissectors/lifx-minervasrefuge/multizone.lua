-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/multizone.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local m = LDMOD {
   -- MultiZone
   [503] = "StateZone",
   [506] = "StateMultiZone",
   [509] = "StateMultiZoneEffect",
   [512] = "StateExtendedColorZones",

   -- MultiZone [get]
   [502] = "GetColorZones",
   [507] = "GetMultiZoneEffect",
   [511] = "GetExtendedColorZones",

   -- MultiZone [set]
   [501] = "SetColorZones",
   [508] = "SetMultiZoneEffect",
   [510] = "SetExtendedColorZones"
}

local function dissector_name(tree, buffer, pinfo)
end

m.dissectorLookups = {
}

return m

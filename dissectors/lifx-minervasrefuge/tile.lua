-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/tile.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local m = LDMOD {
   -- Tile
   [702] = "StateDeviceChain",
   [711] = "State64",
   [720] = "StateTileEffect",

   -- Tile [get]
   [701] = "GetDeviceChain",
   [707] = "Get64",
   [718] = "GetTileEffect",

   -- Tile [set]
   [703] = "SetUserPosition",
   [715] = "Set64",
   [719] = "SetTileEffect"
}

local function dissector_name(tree, buffer, pinfo)
end

return m

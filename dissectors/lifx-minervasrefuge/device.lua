-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/device.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local lifxProducts = require("products")
require("util")

local m = LDMOD {
   [3]   = "StateService",
   [15]  = "StateHostFirmware",
   [17]  = "StateWifiInfo",
   [19]  = "StateWifiFirmware",
   [22]  = "StatePower",
   [25]  = "StateLabel",
   [33]  = "StateVersion",
   [35]  = "StateInfo",
   [50]  = "StateLocation",
   [53]  = "StateGroup",
   [59]  = "EchoResponse",
   [223] = "StateUnhandled",

   -- Device [get]
   [14] = "GetHostFirmware",
   [16] = "GetWifiInfo",
   [18] = "GetWifiFirmware",
   [20] = "GetPower",
   [23] = "GetLabel",
   [32] = "GetVersion",
   [34] = "GetInfo",
   [48] = "GetLocation",
   [51] = "GetGroup",
   [58] = "EchoRequest",

   -- Device [set]
   [21] = "SetPower",
   [24] = "SetLabel",
   [38] = "SetReboot",
   [49] = "SetLocation",
   [52] = "SetGroup"
}

-- StateVersion
BuildProtoFieldGroup {
   mod=m, prefix = "sv_", key="lifx.StateVersion", group="pfs_stateversion",

   {id="vendor"    , fn="uint32" , "vendor"    , "Vendor"    , DEC} ,
   {id="product"   , fn="uint32" , "product"   , "Product"   , DEC} ,
   {id="reserved1" , fn="bytes"  , "reserved1" , "Reserved1" , SPACE}
}



addDissector(33, m, function (t, b, pinfo)
   le(t, m.sv_vendor, b(0, 4))
   local field = le(t, m.sv_product, b(4, 4))
   local vendor = b(0, 4):le_uint()
   local product = lifxProducts[b(4, 4):le_uint()]
   if vendor == 1 and product then
      field:append_text(" (" .. product .. ")")
   end
   le(t, m.sv_reserved1, b(8, 4))
end)


-- GET
ignore(32, m) -- GetVersion

             
ignore(45, m)

return m

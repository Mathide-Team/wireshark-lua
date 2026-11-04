-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/service.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
require("util")

local m = LDMOD {
-- Discovery [get]
   [2] = "GetService",
   [3] = "StateService"
}

ignore(2, m)

-- StateService
BuildProtoFieldGroup {
   mod=m, prefix = "ss_", key="lifx.StateService",
   
   {id="service" , fn="uint8"  , "service" , "Service" , nil , {"UDP" , "RESERVED1" , "RESERVED2" , "RESERVED3" , "RESERVED4"}} ,
   {id="port"    , fn="uint32" , "port"    , "Port"    , DEC}
}

addDissector(3, m, function (t, b, pinfo) -- StateService
   le(t, m.ss_service, b(0, 1))
   le(t, m.ss_port   , b(1, 4))
end)

return m

-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/dottedmag/wireshark-zwave (zwave-app-noop.lua),
-- commit 557c8578df4d6e70233ab39fd5d01ef39903f7e8 du 31/10/2020.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local class_id = 0x00
local name = "No Operation"

-- Request

local req = Proto("zwave_req_app_noop", name.." request")

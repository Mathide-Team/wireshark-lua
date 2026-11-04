-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/ElectronicCats/CatSniffer-Tools (Legacy/pycatsniffer_bv3/dissectors/catsniffer-register.lua),
-- commit 8a34319dd50c560f15aeada3bfdacc2a3f838dab du 22/10/2026.
-- Licence amont : GPL-3.0-only (LICENSE amont) — voir README.md.
--
-- CatSniffer BLE Dissector
-- Electronic Cats - PwnLab
--
-------------------------------------------------------------------------------
-------------------------   Register All Dissectors   -------------------------
-------------------------------------------------------------------------------
-- The format of the CatSniffer Radio Packet is shown below.
--  ----------------------------------------------------------------------------------------------------------------------
--  | Version | Length | Interface Type | Interface ID | Protocol | PHY | Frequency | Channel | RSSI | Status | Payload  |
--  | 1B      | 2B     | 1B             | 2B           | 1B       | 1B  | 4B        | 2B      | 1B   | 1B     | Variable |
--  ----------------------------------------------------------------------------------------------------------------------
-- The format of the BLE meta header is shown below.
--
-- The variable length payload is forwarded to the Wireshark BLE dissector (btle).
--  -----------------------------------------------------
--  | Connection Event Counter | Info | Payload         |
--  | 2B                       | 1B   | Variable Length |
--  -----------------------------------------------------
require("catsniffer-blepi")
require("catsniffer-rpi")


DTL0_LINKLAYER = 147

local catsniffer_blepi_p = build_catsniffer_blepi_p()
local catsniffer_rpi_p = build_catsniffer_rpi_p()

-- For User DLT to controll the information of all the CatSniffer packets
local user_dtls = DissectorTable.get("dtls.port")
user_dtls:add(DTL0_LINKLAYER, catsniffer_rpi_p)

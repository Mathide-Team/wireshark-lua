-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/o-gs/dji-firmware-tools (comm_dissector/wireshark/init.lua),
-- commit 1db36ddf45d8018ea849f0c03c5e45d2f3068844 du 25/10/2026 (dernière modification du fichier :
-- commit 886155087c08b571b79e57b9f6b096f4e72ac886 du 26/04/2025).
-- Licence amont : GPL-3.0, LICENSE du dépôt — voir README.md et LICENSE.
disable_lua = false

-- Change dji_script_path to point to the directory where you have copied
-- the Lua scripts. Do not place them in the Wireshark Lua directory.
-- Please see the README file for more information.
-- This path should be an absolute path and end with a "/"
--
-- Linux/MacOS example:
--   local dji_script_path = "/path/to/scripts/"
-- Windows example:
--   local dji_script_path = "C:\\path\\to\\scripts\\"

local dji_script_path = ""

-- If you have not changed the line above, Lua will look for the scripts
-- in the current working directory and probably not find them.

dofile(dji_script_path .. 'dji-dumlv1-proto.lua')

dofile(dji_script_path .. 'dji-p3-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-p3-batt-proto.lua')
dofile(dji_script_path .. 'dji-p3.lua')

dofile(dji_script_path .. 'dji-mavic-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-mavic.lua')

dofile(dji_script_path .. 'dji-spark-flyrec-proto.lua')
dofile(dji_script_path .. 'dji-spark.lua')

dofile(dji_script_path .. 'dji-write-kml.lua')

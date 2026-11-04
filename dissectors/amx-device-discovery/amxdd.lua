-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/hisasan/amxdd-dissector (amxdd.lua),
-- commit df867fd0311b35e331d0be75e532b2c43a7fb7fb du 06/02/2020.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- AMX Device Discovery protocol dissector for Wireshark
-- Version 0.1.0
-- Author H.Doi

amxdd = Proto("AMXDD","AMX Device Discovery")

function amxdd.dissector(buffer, pinfo, tree)
    local datalen = buffer:len();
	if buffer(0, 5):string() ~= "AMXB<" or buffer(datalen - 1, 1):uint() ~= 0x0d then
		return
	end

    pinfo.cols.protocol = amxdd.name
	pinfo.cols.info     = "AMX Beacon"

    local subtree = tree:add(amxdd, buffer(), "AMX Beacon")
    local start   = 0
    local equal   = 0

    for offset = 4, datalen - 1 do
		local chr = buffer(offset, 1):string()
        if chr == "<" then
            start = offset
        elseif chr == "=" then
            equal = offset
        elseif chr == ">" then
			if 0 < start and start < equal then
				local name  = buffer(start + 1, equal - start - 1):string()
				local value = buffer(equal + 1, offset - equal - 1):string()
				if name:sub(1,1) == "-" then
					name = "Device" .. name
				end
	            subtree:add(buffer(start, offset - start + 1), name .. ":", value)
				pinfo.cols.info:append(" " .. value)
			end
			start = 0
			equal = 0
        end
    end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(9131, amxdd)

-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/o-gs/dji-firmware-tools (comm_dissector/wireshark/dji-spark.lua),
-- commit 1db36ddf45d8018ea849f0c03c5e45d2f3068844 du 25/10/2026 (dernière modification du fichier :
-- commit 1865b36e0bc9c1f10ab6fff64554f332acb5e5ec du 24/12/2018).
-- Licence amont : GPL-3.0, LICENSE du dépôt — voir README.md et LICENSE.
-- Create the aggeregate dissector
DJI_SPARK_PROTO = Proto ("dji_spark", "DJI_SPARK", "Dji Spark protocols aggregate")

local f = DJI_SPARK_PROTO.fields

-- [0]  Start of Pkt, always 0x55
f.delimiter = ProtoField.uint8 ("dji_spark.delimiter", "Delimiter", base.HEX)

-- The protocol dissector itself
function DJI_SPARK_PROTO.dissector (buffer, pinfo, tree)

    local subtree = tree:add (DJI_SPARK_PROTO, buffer())

    -- The Pkt start byte determines the pkt type
    local offset = 0

    local pkt_type = buffer(offset,1):uint()
    subtree:add (f.delimiter, buffer(offset, 1))
    offset = offset + 1

    if pkt_type == 0x55 then
        local pkt_protover = buffer(offset,2):le_uint()
        pkt_protover = bit32.rshift(bit32.band(pkt_protover, 0xFC00), 10)
        if pkt_protover == 0 then
            dji_spark_flyrec_main_dissector(buffer, pinfo, subtree)
        else
            dji_dumlv1_main_dissector(buffer, pinfo, subtree)
        end
    end
    
end

-- SPDX-License-Identifier: NASA-1.3
-- Importé de https://github.com/IRT-Saint-Exupery/CSS-Simulator (CSS_Attacks/Dissectors/Dissecteurs_CCSDS/sdls_trailer.lua),
-- commit 82457a85ee4c27605836d8e973d19c68b953a8e2 du 15/09/2026 (dernière modification du fichier :
-- commit 348b2cb29ef4e537b4a97b1ad49db269576a5f77 du 25/02/2026).
-- Licence amont : NASA Open Source Agreement 1.3 (LICENSE.txt amont) — voir README.md et LICENSE.txt.
-- © Copyright European Space Agency, 2023
-- This file is subject to the terms and conditions defined in file 'LICENSE.md',
-- which is part of this source code package. No part of the package,
-- including this file, may be copied, modified, propagated, or distributed except
-- according to the terms contained in the file ‘LICENSE.md’.

local sdls_trailer = Proto("sdls_trailer", "Space Data Link Security trailer")

-- Preferences
sdls_trailer.prefs.mac_length = Pref.uint("SDLS MAC Length", 16, "Message Authentication Code length")
local prefs = sdls_trailer.prefs
local config = prefs

-- Fields
local f = sdls_trailer.fields
f.mac = ProtoField.bytes("sdls.mac", "Message Authentication Code")

function sdls_trailer.dissector(buffer, pinfo, tree)
    local subtree = tree:add(sdls_trailer, buffer(), "Space Data Link Security trailer")
    local offset = 0

    subtree:add(f.mac, buffer(offset, config.mac_length))
    offset = offset + config.mac_length
end

function sdls_trailer.prefs_changed()
    SDLS_trailer_set_config(nil)
end

function SDLS_trailer_get_length(config)
    if config ~= nil then
        return config.mac_length
    end
    return prefs.mac_length
end

function SDLS_trailer_set_config(c)
    if c ~= nil then
        config = c
    else
        config = prefs
    end
end


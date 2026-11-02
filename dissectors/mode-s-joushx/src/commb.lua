-- SPDX-License-Identifier: GPL-2.0-only
-- Importé de https://github.com/joushx/mode-s-dissector (commb.lua),
-- commit 6543ebf2b97f50d0ade998a99f630afae56ad873 du 25/05/2016 (dernière modification du fichier :
-- commit f32ea2d8480da7da5ddbc397cfc8ee42d25da1f1 du 24/05/2016).
-- Licence amont : GPL-2.0, LICENSE du dépôt — voir README.md et LICENSE.
commb_proto = Proto("commb","Comm-B")

local f = commb_proto.fields

function commb_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "Comm-B"
    pinfo.cols.info = ""

    local commb = tree:add(commb_proto, buffer(0, buffer:len()), "Comm-B")
end

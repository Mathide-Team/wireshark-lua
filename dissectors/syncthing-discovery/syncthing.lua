-- SPDX-License-Identifier: GPL-2.0-only
-- Importé de https://github.com/tmo1/wireshark-syncthing-dissector (syncthing.lua),
-- commit 746aed2826c10012af59e774251a5c14a5a0a006 du 27/02/2022.
-- Licence amont : GPL-2.0-only (gpl-2.0.txt amont) — voir README.md.
-- Wireshark dissector for Syncthing protocols
-- Currently, only Announcement packets (Local Discovery Protocol v4) are supported
-- https://docs.syncthing.net/specs/localdisco-v4.html

-- Based on:
-- https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
-- https://wiki.wireshark.org/Lua/Dissectors
-- https://ask.wireshark.org/question/25070/lua-how-to-get-a-field-from-a-decoded-protobuf-to-decode-the-next-protobuf/

syncthing_announcement_protocol = Proto("Syncthing", "Syncthing Announcement")
syncthing_announcement_protocol.fields = {}
magic = ProtoField.int32("syncthing.magic", "Magic", base.DEC)
syncthing_announcement_protocol.fields = {magic}

function syncthing_announcement_protocol.dissector(tvb, pinfo, tree)
	length = tvb:len()
	if length == 0 or tvb(0, 4):uint() ~= 782752011 then return end
	local subtree = tree:add(syncthing_announcement_protocol, tvb(), "Syncthing Announcement")
	subtree:add(magic, tvb(0, 4))
	local protobuf_dissector = Dissector.get("protobuf")
	pinfo.private["pb_msg_type"] = "message,syncthing.Announce"
	pcall(Dissector.call, protobuf_dissector, tvb(4, length - 4):tvb(), pinfo, subtree)
	pinfo.cols.protocol = syncthing_announcement_protocol.name
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(21027, syncthing_announcement_protocol)

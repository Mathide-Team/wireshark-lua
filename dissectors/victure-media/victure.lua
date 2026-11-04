-- SPDX-License-Identifier: GPL-3.0-or-later
-- Importé de https://github.com/TKems/Victure-Camera-Vulnerabilities (victure.lua),
-- commit 952d589dc7906d7d849751b2457015c8d93bfc2b du 05/09/2024.
-- Licence amont : GPL-3.0-or-later (LICENSE amont) — voir README.md.
--[[Victure Camera Vulnerabilties
Copyright (C) 2024  Trevor Kems

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.]]--

victure_protocol = Proto("Victure-Media",  "Victure Media Protocol")

message_size = ProtoField.uint32("victure.message_size", "messageSize", base.DEC)
sync_one = ProtoField.uint8("victure.sync_one", "syncOne", base.HEX)
sync_two = ProtoField.uint8("victure.sync_two", "syncTwo", base.HEX)
media_type = ProtoField.uint8("victure.media_type", "mediaType", base.DEC)
eck_byte = ProtoField.uint8("victure.eck_byte", "eckByte", base.HEX)
seqNum = ProtoField.uint16("victure.seqNum", "seqNum", base.HEX)
data_length = ProtoField.uint16("victure.dataLength", "dataLength", base.HEX)
timestamp = ProtoField.uint32("victure.timestamp", "timestamp", base.HEX)
media_data = ProtoField.bytes("victure.mediaData", "mediaData", base.NONE)

victure_protocol.fields = {message_size, sync_one, sync_two, media_type, eck_byte, seqNum, data_length, timestamp, media_data}

function victure_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = victure_protocol.name

  local subtree = tree:add(victure_protocol, buffer(), "Victure Protocol Data")
  subtree:add(message_size, buffer(0,4))
  subtree:add(sync_one, buffer(4,1))
  subtree:add(sync_two, buffer(5,1))

  local media_type_num = buffer(6,1):uint()
  local media_type_name = get_media_type_name(media_type_num)

  subtree:add(media_type, buffer(6,1)):append_text(" (" .. media_type_name .. ")")
  subtree:add(eck_byte, buffer(7,1))
  subtree:add(seqNum, buffer(8,2))
  subtree:add(data_length, buffer(10,2))
  subtree:add(timestamp, buffer(12,4))
  subtree:add(media_data, buffer(16,length-16))

end

function get_media_type_name(media_type)
    local mediaType_name = "Unknown"
  
        if media_type == 5 then mediaType_name = "MEDIATYPE_VIDEO_H265"
    elseif media_type == 2 then mediaType_name = "MEDIATYPE_AUDIO_ALAW"
    elseif media_type == 60 then mediaType_name = "MEDIATYPE_AUDIO_MAX"
    elseif media_type == 61 then mediaType_name = "ERROR_EOL"
    elseif media_type == 62 then mediaType_name = "ERROR_BAD" end
  
    return mediaType_name
  end



local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(16116, victure_protocol)

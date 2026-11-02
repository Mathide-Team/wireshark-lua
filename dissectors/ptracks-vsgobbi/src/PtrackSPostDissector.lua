-- SPDX-License-Identifier: GPL-2.0-or-later
-- Importé de https://github.com/vsgobbi/PTracksV0.3 (PtrackSPostDissector.lua),
-- commit 25db0d65ba41973820cda5e91dcbc3b02f903b5c du 08/01/2019 (dernière modification du fichier :
-- commit 25db0d65ba41973820cda5e91dcbc3b02f903b5c du 08/01/2019).
-- Licence amont : « GPL licensed », sans version (en-tête du fichier) — voir README.md.
-- PtrackSPostDissector.lua
-- Created by Vitor Sgobbi, 2015, GPL licensed, Version 0.3
-- Brazilian Air Traffic Control Institute
-- e-mail: vitorvgsms@icea.gov.br
-- There is a "how to" created on this project directory...
-- How to extract the payload bytes of an UDP packet???	

print("\n\nStarting to analyse PtrackS UDP data...\n")
-- declared "fake" protocol as trivial_proto
trivial_proto = Proto("PtrackS","PtrackS Protocol")

-- declare some Fields to be read:
ip_src_f = Field.new("ip.src")
ip_dst_f = Field.new("ip.dst")
udp_src_f = Field.new ("udp.srcport")
udp_dst_f = Field.new ("udp.dstport")


-- create the fields for "ptracks protocol"
src_F = ProtoField.string("ptracks.src","Source")
dst_F = ProtoField.string("ptracks.dst","Destination")
conv_F = ProtoField.string("ptracks.conv","Conversation","A Conversation")
data_F = ProtoField.string("ptracks.data","Data set  ------------------------------------------")

-- create the string to see some of the message (protocol.fieldToString, Name of field, Type)
messageSimID = ProtoField.string("ptracks.simID","Simulator ID","Text") -- simulator ID 
messageMsgID = ProtoField.string("ptracks.messageID", "Message ID", "Text") --Message ID
messageCallSign = ProtoField.string("ptracks.callsign", "Aircraft Call Sign", "Text") -- Aircraft register
messageAircType = ProtoField.string("ptracks.ackind", "Aircraft type", "Text")
messageTime = ProtoField.string("ptracks.time", "Time", "Text") --  In seconds.miliseconds
messageStatus = ProtoField.string("ptracks.status", "Status", "Text")
messageLong = ProtoField.string("ptracks.long", "Longitude", "Text")
messageLat = ProtoField.string("ptracks.lat", "Latitude", "Text")
messageHeading = ProtoField.string("ptracks.heading", "Heading", "Text") -- Heading
messageAlt = ProtoField.string("ptracks.alt", "Altitude", "Text")
messageSpeed = ProtoField.string("ptracks.speed", "Speed", "Text")

-- add the field to the protocol
trivial_proto.fields = {src_F, dst_F, conv_F, data_F, messageSimID, messageMsgID, messageCallSign, messageAircType, messageTime, messageStatus, messageLong, messageLat, messageHeading, messageAlt, messageSpeed}
-- create a function to "postdissect" each frame
function trivial_proto.dissector(buffer,pinfo,tree)
-- obtain the current values the protocol fields
--local tcp_src = tcp_src_f()
--local tcp_dst = tcp_dst_f()
local udp_src = udp_src_f()
local udp_dst = udp_dst_f()
local ip_src = ip_src_f()
local ip_dst = ip_dst_f()


-- do dissection for udp
if udp_src then
	  --local subtree = tree:add(trivial_proto,"PtrackS Protocol")
	  local subtree = tree:add(trivial_proto,buffer())		
          local src = tostring(ip_src) .. ":" .. tostring(udp_src)
          local dst = tostring(ip_dst) .. ":" .. tostring(udp_dst)
          local conv = src  .. " -> " .. dst

          subtree:add(src_F,src)
          subtree:add(dst_F,dst)
          subtree:add(conv_F,conv)
	  subtree:add(data_F)
-- Now the boring part to separate correctly the fields
	  --subtree = tree:add(trivial_proto,buffer())
	  messageType = buffer(0,3):le_uint()
	  messageTypeString0 = "Identification of simulation type"
	  messageType = buffer(4,3):string()	  
	  messageTypeString1 = "Identification of message type"	  
	  messageType2 = buffer(8,7):string()
	  messageTypeString2 = "Aircraft register"
	  messageType3 = buffer(16,4):string()
	  messageTypeString3 = "Aircraft type"
	  messageType4 = buffer(21,8):string()
	  messageTypeString4 = "t1 Time in Seconds (sec.millisec)"   	
	  messageType5 = buffer(35,2):string()
	  messageTypeString5 = "Status, VN: Flying Normally"
	  messageType6 = buffer(38,8):string()
	  messageTypeString6 = "Longitude"
	  messageType7 = buffer(53,8):string()
	  messageTypeString7 = "Latitude"
	  messageType8 = buffer(68,8):string()
	  messageTypeString8 = "Heading (Prow in Degrees)"
	  messageType9 = buffer(83,5):string()
	  messageTypeString9 = "Altitude (Meters)"
	  messageType10 = buffer(89,6):string()
	  messageTypeString10 = "Speed (Meters/Second)"
	
-- create fields to separate and format data: 
	  subtree:add_le(messageSimID,buffer(0,3)):append_text(" (".. messageTypeString0 ..")")
	  subtree:add_le(messageMsgID,buffer(4,3)):append_text(" (".. messageTypeString1 ..")")
	  subtree:add_le(messageCallSign,buffer(8,7)):append_text(" (".. messageTypeString2 ..")")
	  subtree:add_le(messageAircType,buffer(16,4)):append_text(" (".. messageTypeString3 ..")")
	  subtree:add_le(messageTime,buffer(21,8)):append_text(" (" .. messageTypeString4 ..")")
	  subtree:add_le(messageStatus,buffer(35,2)):append_text(" (" .. messageTypeString5 ..")")
	  subtree:add_le(messageLong,buffer(38,8)):append_text(" (" .. messageTypeString6 ..")")
	  subtree:add_le(messageLat,buffer(53,8)):append_text(" (" .. messageTypeString7 ..")")
	  subtree:add_le(messageHeading,buffer(68,8)):append_text(" (" .. messageTypeString8 ..")")
	  subtree:add_le(messageAlt,buffer(83,5)):append_text(" (" .. messageTypeString9 ..")")
	  subtree:add_le(messageSpeed,buffer(89,6)):append_text(" (" .. messageTypeString10 ..")")   
       end
   end

-- register udp 1970 port to get only ptracks packets
udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(1970,trivial_proto)

--function to count number of packets
do
    packets = 0;
    local function init_listener()
        local tap = Listener.new("frame","udp.port==1970")
--"frame","ip.addr == 231.12.2.4/8"
        function tap.reset()
            packets = 0;
        end
        function tap.packet(pinfo,tvb,ip)
            packets = packets + 1
        end
        function tap.draw()
            print("UDP packets from PtrackS =",packets)
        end
    end
    init_listener()
end

--*This will register the trivial_proto (duplicated)
--register_postdissector(trivial_proto)


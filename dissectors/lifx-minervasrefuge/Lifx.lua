-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/Lifx.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
local dissectorHndls = {
   require("service"),
   require("device"),
   require("light"),
   require("multizone"),
   require("relay"),
   require("tile")
}

dissectors = {}

lifxPacketTypes = {
   -- Core
   [45]  = "Acknowledgement"
}

lifx_protocol = Proto("LIFX", "LIFX LAN")
lifx_protocol.fields = {}


-- load dissectorLookups
-- load packetProtoFields
-- load lifx_packet_types

for _,dhndl in ipairs(dissectorHndls) do
   if dhndl["lifxPacketTypes"] then
      for k,v in pairs(dhndl.lifxPacketTypes) do
         lifxPacketTypes[k] = v
      end
   end
   
   if dhndl["packetProtoFields"] then
      for _, pf in ipairs(dhndl.packetProtoFields) do
         table.insert(lifx_protocol.fields, pf)
      end
   end
   
   if dhndl["dissectorLookups"] then
      for k,v in pairs(dhndl.dissectorLookups) do
         dissectors[k] = v
      end
   end
end

-- Frame Header
size        = ProtoField.uint16("lifx.size"       , "PacketSize"  , base.DEC)
protocol    = ProtoField.uint16("lifx.protocol"   , "Protocol"    , base.DEC , nil          , 0xFFF0)
addressable = ProtoField.bool  ("lifx.addressable", "Addressable" , 16       , {"No", "Yes"}, 0x0008)
tagged      = ProtoField.bool  ("lifx.tagged"     , "Tagged"      , 16       , {"No", "Yes"}, 0x0004) 
origin      = ProtoField.uint8 ("lifx.origin"     , "Origin"      , base.HEX , nil          , 0x0003)
source      = ProtoField.uint32("lifx.source"     , "Source"      , base.HEX)

pf_header = {size, protocol, addressable, tagged, origin, source}

-- Frame Address
target         = ProtoField.ether ("lifx.target"       , "Target")
target_devices = ProtoField.uint16("lifx.target_device", "Target_device", base.HEX)
reserved1      = ProtoField.bytes ("lifx.reserved1"    , "Reserved1"    , base.SPACE)
res_required   = ProtoField.bool  ("lifx.res_required" , "Res Required" , 8       , {"No", "Yes"}, 0x80)
ack_required   = ProtoField.bool  ("lifx.ack_required" , "Ack Required" , 8       , {"No", "Yes"}, 0x40) 
reserved2      = ProtoField.uint8 ("lifx.reserved2"    , "Reserved2"    , base.HEX, nil                      , 0x3F)
sequence       = ProtoField.uint8 ("lifx.sequence"     , "Sequence"     , base.DEC)

pf_address = {target, target_devices, reserved1, res_required, ack_required, reserved2, sequence}

-- Protocol Header
reserved3 = ProtoField.uint64("lifx.reserved3", "Reserved3")
ptype     = ProtoField.uint16("lifx.type"     , "Type"     , nil, lifxPacketTypes)
reserved4 = ProtoField.uint16("lifx.reserved4", "Reserved4")

pf_protocol = {reserved3, ptype, reserved4}

for _, pfs in ipairs({pf_header, pf_address, pf_protocol}) do
   for _, pf in ipairs(pfs) do
      table.insert(lifx_protocol.fields, pf)
   end
end


function lifx_protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end
   
   pinfo.cols.protocol = lifx_protocol.name
   
   local subtree = tree:add(lifx_protocol, buffer(), "LIFX")
   local thead = subtree:add(lifx_protocol, buffer(), "Header")

   if length < 4 then return end

   thead:add_le(size,        buffer(0,2))
   local data = buffer(2,4)
   thead:add_le(protocol,    data)
   thead:add_le(addressable, data)
   thead:add_le(tagged,      data)
   thead:add_le(origin,      data)
   thead:add_le(source,      buffer(4, 4))

   if length < 23 then return end

   local taddress = subtree:add(lifx_protocol, buffer(), "Address")

   taddress:add_le(target        , buffer(8 , 6)) 
   taddress:add_le(target_devices, buffer(14, 2))
   taddress:add_le(reserved1     , buffer(16, 6)) -- 6 bytes
   local data = buffer(22,1)
   taddress:add_le(res_required  , data) -- bool
   taddress:add_le(ack_required  , data) -- bool
   taddress:add_le(reserved2     , data) -- 6 bits
   taddress:add_le(sequence      , buffer(23, 1)) -- 1 byte

   if length < 34 then return end

   local tproto = subtree:add(lifx_protocol, buffer(), "Protocol")

   tproto:add_le(reserved3, buffer(24, 8)) -- 8 bytes
   tproto:add_le(ptype,     buffer(32, 2)) -- u16
   tproto:add_le(reserved4, buffer(34, 2)) -- 2 bytes

   local comsID = buffer(32, 2):le_uint()
   local comsType = lifxPacketTypes[comsID]
   if comsType then
      pinfo.cols["info"] = comsType
   end

   local case = dissectors[comsID]

   if case ~= IGNORE_MARKER then
      local payloadBuffer = buffer(36, length-36)
      local ttype = subtree:add(lifx_protocol, payloadBuffer, comsType)

      if case then
         case(ttype, payloadBuffer, pinfo)
      end     
   end
   
end

DissectorTable.get("udp.port"):add(56700, lifx_protocol)

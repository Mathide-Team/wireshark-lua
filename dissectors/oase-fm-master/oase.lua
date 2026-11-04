-- SPDX-License-Identifier: BSD-2-Clause
-- Importé de https://github.com/wwwenca/oase-wireshark (oase.lua),
-- commit 3f06e536b9c84a07b54d48f03f021476adf8b5e6 du 04/04/2022.
-- Licence amont : BSD-2-Clause (LICENSE amont) — voir README.md.
local proto_oase = Proto.new("oase", "Oase Protocol")

local field_direction = ProtoField.uint8("oase.direction", "Direction", base.HEX)
local field_command = ProtoField.uint8("oase.command", "Command", base.HEX)
local field_raw = ProtoField.bytes("oase.raw", "Raw Data", base.HEX)
local field_len = ProtoField.uint16("oase.len", "Data Length", base.DEC)
local field_seq = ProtoField.uint16("oase.sequence", "Sequence", base.DEC)

generated_command_name = ProtoField.string("oase.command_name", "Command Name")
generated_details = ProtoField.string("oase.details", "Command Details")

proto_oase.fields = {
  field_direction, 
  field_command, 
  generated_command_name,
  field_raw,
  field_len,
  field_seq
}

function proto_oase.dissector(buffer, pinfo, tree)
    if buffer(0,4):bytes():tohex() ~= "5C234F41" then return end
    pinfo.cols.protocol = "Oase"
    local payload_tree = tree:add(proto_oase, buffer() )
    local data_len = buffer(4,2):le_uint()
    local seq = buffer(9,1):le_uint()
    local dir = buffer(10,1)
    payload_tree:add(field_direction, dir)
    local command_buffer = buffer(11,1)
    payload_tree:add(field_command, command_buffer)
    payload_tree:add(field_len, data_len)
    payload_tree:add(field_seq, seq)

    local data_start = 16
    local data_buffer = buffer(data_start, data_len)
    payload_tree:add(field_raw, data_buffer)
    

    local command_table = {}
    command_table[0xc4] = command_c4
    command_table[0xc5] = command_c5

    local command_code = command_buffer:uint()
    local command_string = "<unknown>"
    local command_function = command_table[command_code]
    if command_function ~= nil then 
      command_string = command_function(data_buffer, payload_tree, dir)
    end
    payload_tree:add(generated_command_name, command_string):set_generated()        
end

function command_c4(buffer, payload_tree, dir)
  if dir:uint() == 0x00 then 
    local control = buffer(11,1):uint()
    local intensity = buffer(12,1):uint()
    payload_tree:add(generated_details, "Control: " .. control .. "; Intensity: " .. intensity):set_generated()
  else
    local status = buffer(0,1):uint()
    payload_tree:add(generated_details, "Status: " .. status):set_generated()
  end
  return "Control"
end

function command_c5(buffer, payload_tree, dir)
  if dir:uint() == 0x00 then 
  else
    local control1 = buffer(11,1):uint()
    local control2 = buffer(12,1):uint()
    local control3 = buffer(13,1):uint()
    local control4 = buffer(14,1):uint()
    local control5 = buffer(15,1):uint()
    payload_tree:add(generated_details, "Control1: " .. control1 .. "; Control2: " .. control2 .. "; Control3: " .. control3 .. "; Control4: " .. control4 .. "; Control5: " .. control5):set_generated()
  end
  return "Control Status"
end

udp_table = DissectorTable.get("udp.port"):add(5959, proto_oase)

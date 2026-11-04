-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/amasiukevich/TINs (src/wireshark/tin-aaa.lua),
-- commit d80a64891ecd0cf64d5d04f715e2dfc00dae908d du 10/06/2021.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- created by Joanna Sokołowska on 16.05.2021


-- tutorial: https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html



local math = require("math")

-- definitions concerning message type
local packet_type_mask = 0xC0
local msg_data = 2
local msg_ack = 1
local msg_error = 3
local counter_mask = 0x3F80;
local session_mask = 0x007F;

-- definitions of error codes
local e_unknown = 0;
local e_wrong_type = 1;
local e_wrong_count = 2;
local e_wrong_session = 3;

aaa_protocol = Proto("AAA", "AAA Protocol")

packet_type = ProtoField.uint8( "type", "packet type",nil, base.dec, packet_type_mask)
number = ProtoField.uint16("num", "packet number",nil,  base.dec, counter_mask)
session_id = ProtoField.uint16("session", "session id", nil, base.dec, session_mask)


aaa_protocol.fields = {packet_type, number, session_id}

-- sourrce: https://stackoverflow.com/questions/32387117/bitwise-and-in-lua
local function bitwise_and(a, b)
    local result = 0
    local bitval = 1
    while a>0 and b >0 do
        if a%2 == 1 and b%2==1 then
            result = result + bitval
        end
        bitval = bitval * 2 -- left shift
        a = math.floor(a/2)
        b = math.floor(b/2)
    end
    return result
end

local function get_msg_type(code)
    code = math.floor(code / (2^6))    -- shift right by 6 so that you get int representation of codes (lua 5.2 does not support bitwise operations :C)
    local msg_type = "UNKNOWN"
    if code == msg_error then msg_type = "ERROR"
    elseif code == msg_data then msg_type = "DATA"
    elseif code == msg_ack then msg_type = "ACK" end
    return msg_type
end

local function get_error_codes(num)
    num = bitwise_and(num, counter_mask)
    num = math.floor(num/2^7)
    local err_code = "E_UNKNOWN"
    if num == e_wrong_type then err_code= "E_WRONG_PACKET_TYPE"
    elseif num == e_wrong_session then err_code = "E_WRONG_SESSION"
    elseif num == e_wrong_count then err_code = "E_WRONG_COUNT"
    end
    return err_code
end

function aaa_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if(length == 0) then return end

    pinfo.cols.protocol = aaa_protocol.name
    local subtree = tree:add(aaa_protocol, buffer(), "AAA protocol data")
    local type = buffer(0,1):bytes():get_index(0)
    local typename = get_msg_type(type)
    subtree:add(packet_type, buffer(0,1)):append_text(" [" .. typename .. "] ")

    local counter = buffer(0,1):bytes():get_index(0)
    subtree:add(session_id, buffer(0,2)):append_text("[session_id]")
    if(typename == "ERROR") then
        local error_code = get_error_codes(counter)
        subtree:add(number, buffer(0,2)):append_text(" [" .. error_code .. "]" )
    else
        subtree:add(number, buffer(0,2)):append_text(" [nr] ")

    end
    if (typename ~= "ACK" and length > 2) then
        subtree:add(buffer(2, length-2), buffer(2, length-2):string()):append_text(" [payload] ")
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(3000, aaa_protocol)

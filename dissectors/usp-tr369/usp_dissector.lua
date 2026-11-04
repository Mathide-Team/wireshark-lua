-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/NSIDE-ATTACK-LOGIC/USP-Wireshark-Dissector (usp_dissector.lua),
-- commit ba1e91336388d6d447e80682d0df74585eb146a9 du 03/07/2026.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- USP (TR-369) Wireshark Dissector
-- Parses USP Records and USP Messages carried over MQTT.
-- Based on usp_record.proto and usp_msg.proto (Broadband Forum TR-369).
--
-- Author:  Benedikt Strobl <bstrobl@nsideattacklogic.de>
-- License: MIT
--
-- Install: copy to ~/.local/lib/wireshark/plugins/ (Linux) or
--          %APPDATA%\Wireshark\plugins\ (Windows)
-- Then reload plugins: Analyze → Reload Lua Plugins (Ctrl+Shift+L)

local usp_record_proto = Proto("usp_record", "USP Record (TR-369)")
local usp_msg_proto    = Proto("usp_msg",    "USP Message (TR-369)")

-----------------------------------------------------------------------
-- ProtoField declarations – usp_record
-----------------------------------------------------------------------
local rf = {}
rf.version           = ProtoField.string ("usp_record.version",           "Version")
rf.to_id             = ProtoField.string ("usp_record.to_id",             "To ID")
rf.from_id           = ProtoField.string ("usp_record.from_id",           "From ID")
rf.payload_security  = ProtoField.uint32 ("usp_record.payload_security",  "Payload Security",
                           base.DEC, {[0]="PLAINTEXT",[1]="TLS12"})
rf.mac_signature     = ProtoField.bytes  ("usp_record.mac_signature",     "MAC Signature")
rf.sender_cert       = ProtoField.bytes  ("usp_record.sender_cert",       "Sender Certificate")
rf.record_type       = ProtoField.string ("usp_record.record_type",       "Record Type")
-- NoSessionContext
rf.nsc_payload       = ProtoField.bytes  ("usp_record.nsc.payload",       "NSC Payload (raw)")
-- SessionContext
rf.sc_session_id     = ProtoField.uint64 ("usp_record.sc.session_id",     "Session ID")
rf.sc_sequence_id    = ProtoField.uint64 ("usp_record.sc.sequence_id",    "Sequence ID")
rf.sc_expected_id    = ProtoField.uint64 ("usp_record.sc.expected_id",    "Expected ID")
rf.sc_retransmit_id  = ProtoField.uint64 ("usp_record.sc.retransmit_id",  "Retransmit ID")
local sar_vals = {[0]="NONE",[1]="BEGIN",[2]="INPROCESS",[3]="COMPLETE"}
rf.sc_payload_sar    = ProtoField.uint32 ("usp_record.sc.payload_sar",    "Payload SAR State",    base.DEC, sar_vals)
rf.sc_payloadrec_sar = ProtoField.uint32 ("usp_record.sc.payloadrec_sar", "PayloadRec SAR State", base.DEC, sar_vals)
rf.sc_payload        = ProtoField.bytes  ("usp_record.sc.payload",        "SC Payload (raw)")
-- MQTTConnect
rf.mqtt_version      = ProtoField.string ("usp_record.mqtt.version",      "MQTT Version")
rf.mqtt_topic        = ProtoField.string ("usp_record.mqtt.topic",        "Subscribed Topic")
-- WebSocketConnect
rf.ws_topic          = ProtoField.string ("usp_record.ws.topic",          "Subscribed Topic")
-- STOMPConnect
rf.stomp_dest        = ProtoField.string ("usp_record.stomp.dest",        "Subscribed Destination")
rf.stomp_version     = ProtoField.string ("usp_record.stomp.version",     "STOMP Version")
-- Disconnect
rf.disc_reason_code  = ProtoField.uint32 ("usp_record.disc.reason_code",  "Reason Code")
rf.disc_reason       = ProtoField.string ("usp_record.disc.reason",       "Reason")

usp_record_proto.fields = {
    rf.version, rf.to_id, rf.from_id, rf.payload_security,
    rf.mac_signature, rf.sender_cert, rf.record_type,
    rf.nsc_payload,
    rf.sc_session_id, rf.sc_sequence_id, rf.sc_expected_id,
    rf.sc_retransmit_id, rf.sc_payload_sar, rf.sc_payloadrec_sar, rf.sc_payload,
    rf.mqtt_version, rf.mqtt_topic,
    rf.ws_topic,
    rf.stomp_dest, rf.stomp_version,
    rf.disc_reason_code, rf.disc_reason,
}

-----------------------------------------------------------------------
-- ProtoField declarations – usp_msg
-----------------------------------------------------------------------
local mf = {}
local MSG_TYPES = {
    [0]="ERROR",              [1]="GET",                [2]="GET_RESP",
    [3]="NOTIFY",             [4]="SET",                [5]="SET_RESP",
    [6]="OPERATE",            [7]="OPERATE_RESP",       [8]="ADD",
    [9]="ADD_RESP",           [10]="DELETE",            [11]="DELETE_RESP",
    [12]="GET_SUPPORTED_DM",  [13]="GET_SUPPORTED_DM_RESP",
    [14]="GET_INSTANCES",     [15]="GET_INSTANCES_RESP",
    [16]="NOTIFY_RESP",       [17]="GET_SUPPORTED_PROTO",
    [18]="GET_SUPPORTED_PROTO_RESP",
    [19]="REGISTER",          [20]="REGISTER_RESP",
    [21]="DEREGISTER",        [22]="DEREGISTER_RESP",
}
mf.msg_id            = ProtoField.string ("usp_msg.msg_id",           "Message ID")
mf.msg_type          = ProtoField.uint32 ("usp_msg.msg_type",         "Message Type", base.DEC, MSG_TYPES)
mf.body_type         = ProtoField.string ("usp_msg.body_type",        "Body Type")
mf.notif_type        = ProtoField.string ("usp_msg.notif_type",       "Notification Type")
mf.param_path        = ProtoField.string ("usp_msg.param_path",       "Param Path")
mf.obj_path          = ProtoField.string ("usp_msg.obj_path",         "Object Path")
mf.param_value       = ProtoField.string ("usp_msg.param_value",      "Param Value")
mf.param_key         = ProtoField.string ("usp_msg.param_key",        "Param Key")
mf.command           = ProtoField.string ("usp_msg.command",          "Command")
mf.command_key       = ProtoField.string ("usp_msg.command_key",      "Command Key")
mf.send_resp         = ProtoField.bool   ("usp_msg.send_resp",        "Send Response")
mf.allow_partial     = ProtoField.bool   ("usp_msg.allow_partial",    "Allow Partial")
mf.max_depth         = ProtoField.uint32 ("usp_msg.max_depth",        "Max Depth")
mf.sub_id            = ProtoField.string ("usp_msg.sub_id",           "Subscription ID")
mf.err_code          = ProtoField.uint32 ("usp_msg.err_code",         "Error Code")
mf.err_msg           = ProtoField.string ("usp_msg.err_msg",          "Error Message")
mf.first_level       = ProtoField.bool   ("usp_msg.first_level",      "First Level Only")
mf.ret_cmds          = ProtoField.bool   ("usp_msg.ret_cmds",         "Return Commands")
mf.ret_events        = ProtoField.bool   ("usp_msg.ret_events",       "Return Events")
mf.ret_params        = ProtoField.bool   ("usp_msg.ret_params",       "Return Params")
mf.proto_vers        = ProtoField.string ("usp_msg.proto_vers",       "Protocol Versions")
mf.oui               = ProtoField.string ("usp_msg.oui",              "OUI")
mf.product_class     = ProtoField.string ("usp_msg.product_class",    "Product Class")
mf.serial_num        = ProtoField.string ("usp_msg.serial_num",       "Serial Number")
mf.requested_path    = ProtoField.string ("usp_msg.requested_path",   "Requested Path")
mf.resolved_path     = ProtoField.string ("usp_msg.resolved_path",    "Resolved Path")
mf.affected_path     = ProtoField.string ("usp_msg.affected_path",    "Affected Path")
mf.instantiated_path = ProtoField.string ("usp_msg.instantiated_path","Instantiated Path")
mf.registered_path   = ProtoField.string ("usp_msg.registered_path",  "Registered Path")
mf.result_param      = ProtoField.string ("usp_msg.result_param",     "Result Param")
mf.output_arg        = ProtoField.string ("usp_msg.output_arg",       "Output Arg")
mf.unique_key        = ProtoField.string ("usp_msg.unique_key",       "Unique Key")

usp_msg_proto.fields = {
    mf.msg_id, mf.msg_type, mf.body_type, mf.notif_type,
    mf.param_path, mf.obj_path, mf.param_value, mf.param_key,
    mf.command, mf.command_key, mf.send_resp, mf.allow_partial,
    mf.max_depth, mf.sub_id, mf.err_code, mf.err_msg,
    mf.first_level, mf.ret_cmds, mf.ret_events, mf.ret_params,
    mf.proto_vers, mf.oui, mf.product_class, mf.serial_num,
    mf.requested_path, mf.resolved_path, mf.affected_path,
    mf.instantiated_path, mf.registered_path,
    mf.result_param, mf.output_arg, mf.unique_key,
}

-----------------------------------------------------------------------
-- Protobuf binary parser (pure Lua, string-based, 1-indexed)
-----------------------------------------------------------------------

-- Decodes a varint from string s starting at pos.
-- Uses float arithmetic (mult*128) to handle > 32-bit values up to 2^53.
-- Returns: value (number), new_pos  or  nil, pos on error.
local function decode_varint(s, pos)
    local result = 0
    local mult   = 1
    local len    = #s
    while pos <= len do
        local b = string.byte(s, pos)
        pos = pos + 1
        result = result + bit.band(b, 0x7F) * mult
        mult   = mult * 128
        if bit.band(b, 0x80) == 0 then
            return result, pos
        end
        if mult > 2^63 then break end
    end
    return nil, pos
end

-- Reads one tag+value from string s at pos.
-- Returns: field_number, wire_type, value, new_pos  or  nil on error.
--   wire 0 → value is number (varint)
--   wire 1 → value is 0 (64-bit, skipped)
--   wire 2 → value is string (length-delimited bytes)
--   wire 5 → value is number (fixed32, little-endian)
local function read_field(s, pos)
    if pos > #s then return nil end
    local tag, npos = decode_varint(s, pos)
    if tag == nil then return nil end
    local wt   = bit.band(tag, 0x7)
    local fnum = bit.rshift(tag, 3)
    if fnum < 0 then fnum = fnum + 2^29 end

    if wt == 0 then
        local v, np = decode_varint(s, npos)
        return fnum, 0, v, np
    elseif wt == 1 then
        if npos + 7 > #s then return nil end
        return fnum, 1, 0, npos + 8
    elseif wt == 2 then
        local llen, np = decode_varint(s, npos)
        if llen == nil or np + llen - 1 > #s then return nil end
        local sub = s:sub(np, np + llen - 1)
        return fnum, 2, sub, np + llen
    elseif wt == 5 then
        if npos + 3 > #s then return nil end
        local b0 = string.byte(s, npos)
        local b1 = string.byte(s, npos+1)
        local b2 = string.byte(s, npos+2)
        local b3 = string.byte(s, npos+3)
        local v  = b0 + b1*256 + b2*65536 + b3*16777216
        return fnum, 5, v, npos + 4
    else
        return nil
    end
end

-- Calls fn(field_number, wire_type, value) for every field in protobuf string s.
local function iter_fields(s, fn)
    local pos = 1
    while pos <= #s do
        local fnum, wt, val, np = read_field(s, pos)
        if fnum == nil then break end
        fn(fnum, wt, val)
        pos = np
    end
end

-- Decodes a map<string,string> entry (wire-type-2 blob) into "key = value".
local function decode_map_entry(s)
    local k, v = "", ""
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then k = val
        elseif fn == 2 and wt == 2 then v = val
        end
    end)
    return k .. " = " .. v
end

-----------------------------------------------------------------------
-- USP Message sub-dissectors (one per request/response type)
-----------------------------------------------------------------------

local function diss_get(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.param_path, val)
        elseif fn == 2 and wt == 0 then t:add(mf.max_depth, val)
        end
    end)
end

local function diss_get_supported_dm(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.obj_path,    val)
        elseif fn == 2 and wt == 0 then t:add(mf.first_level, val ~= 0)
        elseif fn == 3 and wt == 0 then t:add(mf.ret_cmds,   val ~= 0)
        elseif fn == 4 and wt == 0 then t:add(mf.ret_events, val ~= 0)
        elseif fn == 5 and wt == 0 then t:add(mf.ret_params, val ~= 0)
        end
    end)
end

local function diss_get_instances(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.obj_path,    val)
        elseif fn == 2 and wt == 0 then t:add(mf.first_level, val ~= 0)
        end
    end)
end

local function diss_set(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 0 then
            t:add(mf.allow_partial, val ~= 0)
        elseif fn == 2 and wt == 2 then
            local ot = t:add(usp_msg_proto, "UpdateObject")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then ot:add(mf.obj_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    local ps = ot:add(usp_msg_proto, "ParamSetting")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then ps:add(mf.param_key,   val3)
                        elseif fn3 == 2 and wt3 == 2 then ps:add(mf.param_value, val3)
                        elseif fn3 == 3 and wt3 == 0 then ps:add(mf.send_resp,   val3 ~= 0)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_add(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 0 then
            t:add(mf.allow_partial, val ~= 0)
        elseif fn == 2 and wt == 2 then
            local ot = t:add(usp_msg_proto, "CreateObject")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then ot:add(mf.obj_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    local ps = ot:add(usp_msg_proto, "ParamSetting")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then ps:add(mf.param_key,   val3)
                        elseif fn3 == 2 and wt3 == 2 then ps:add(mf.param_value, val3)
                        elseif fn3 == 3 and wt3 == 0 then ps:add(mf.send_resp,   val3 ~= 0)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_delete(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 0 then t:add(mf.allow_partial, val ~= 0)
        elseif fn == 2 and wt == 2 then t:add(mf.obj_path, val)
        end
    end)
end

local function diss_operate(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.command,     val)
        elseif fn == 2 and wt == 2 then t:add(mf.command_key, val)
        elseif fn == 3 and wt == 0 then t:add(mf.send_resp,   val ~= 0)
        elseif fn == 4 and wt == 2 then
            local at = t:add(usp_msg_proto, "InputArg")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then at:add(mf.param_key,   val2)
                elseif fn2 == 2 and wt2 == 2 then at:add(mf.param_value, val2)
                end
            end)
        end
    end)
end

local function diss_notify(s, t)
    local ntype, ndata = nil, nil
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.sub_id,    val)
        elseif fn == 2 and wt == 0 then t:add(mf.send_resp, val ~= 0)
        elseif fn == 3 and wt == 2 then ntype = "Event";             ndata = val
        elseif fn == 4 and wt == 2 then ntype = "ValueChange";       ndata = val
        elseif fn == 5 and wt == 2 then ntype = "ObjectCreation";    ndata = val
        elseif fn == 6 and wt == 2 then ntype = "ObjectDeletion";    ndata = val
        elseif fn == 7 and wt == 2 then ntype = "OperationComplete"; ndata = val
        elseif fn == 8 and wt == 2 then ntype = "OnBoardRequest";    ndata = val
        end
    end)
    if not ntype then return end
    t:add(mf.notif_type, ntype)
    local nt = t:add(usp_msg_proto, ntype)
    if ntype == "ValueChange" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.param_path,  val)
            elseif fn == 2 and wt == 2 then nt:add(mf.param_value, val)
            end
        end)
    elseif ntype == "ObjectCreation" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.obj_path, val)
            elseif fn == 2 and wt == 2 then nt:add(mf.unique_key, decode_map_entry(val))
            end
        end)
    elseif ntype == "ObjectDeletion" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.obj_path, val) end
        end)
    elseif ntype == "Event" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.obj_path,   val)
            elseif fn == 2 and wt == 2 then nt:add(mf.param_key, val)
            elseif fn == 3 and wt == 2 then
                local ep = nt:add(usp_msg_proto, "EventParam")
                iter_fields(val, function(fn2, wt2, val2)
                    if fn2 == 1 and wt2 == 2 then ep:add(mf.param_key,   val2)
                    elseif fn2 == 2 and wt2 == 2 then ep:add(mf.param_value, val2)
                    end
                end)
            end
        end)
    elseif ntype == "OperationComplete" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.command,     val)
            elseif fn == 2 and wt == 2 then nt:add(mf.command_key, val)
            elseif fn == 3 and wt == 2 then nt:add(mf.obj_path,    val)
            elseif fn == 4 and wt == 2 then
                iter_fields(val, function(fn2, wt2, val2)
                    if fn2 == 1 and wt2 == 2 then nt:add(mf.output_arg, decode_map_entry(val2)) end
                end)
            elseif fn == 5 and wt == 2 then
                local cf = nt:add(usp_msg_proto, "CommandFailure")
                iter_fields(val, function(fn2, wt2, val2)
                    if fn2 == 1 and wt2 == 5 then cf:add(mf.err_code, val2)
                    elseif fn2 == 2 and wt2 == 2 then cf:add(mf.err_msg,  val2)
                    end
                end)
            end
        end)
    elseif ntype == "OnBoardRequest" then
        iter_fields(ndata, function(fn, wt, val)
            if fn == 1 and wt == 2 then nt:add(mf.oui,           val)
            elseif fn == 2 and wt == 2 then nt:add(mf.product_class, val)
            elseif fn == 3 and wt == 2 then nt:add(mf.serial_num,    val)
            elseif fn == 4 and wt == 2 then nt:add(mf.proto_vers,    val)
            end
        end)
    end
end

local function diss_get_supported_proto(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.proto_vers, val) end
    end)
end

local function diss_register(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 0 then t:add(mf.allow_partial, val ~= 0)
        elseif fn == 2 and wt == 2 then
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then t:add(mf.param_path, val2) end
            end)
        end
    end)
end

local function diss_deregister(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.param_path, val) end
    end)
end

-- Responses

local function diss_get_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local rr = t:add(usp_msg_proto, "RequestedPathResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then rr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 5 then rr:add(mf.err_code, val2)
                elseif fn2 == 3 and wt2 == 2 then rr:add(mf.err_msg,  val2)
                elseif fn2 == 4 and wt2 == 2 then
                    local rp = rr:add(usp_msg_proto, "ResolvedPathResult")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then rp:add(mf.resolved_path, val3)
                        elseif fn3 == 2 and wt3 == 2 then rp:add(mf.result_param, decode_map_entry(val3))
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_get_supported_dm_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local rr = t:add(usp_msg_proto, "RequestedObjectResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then rr:add(mf.obj_path,  val2)
                elseif fn2 == 2 and wt2 == 5 then rr:add(mf.err_code, val2)
                elseif fn2 == 3 and wt2 == 2 then rr:add(mf.err_msg,  val2)
                elseif fn2 == 5 and wt2 == 2 then
                    local so = rr:add(usp_msg_proto, "SupportedObject")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then so:add(mf.obj_path, val3) end
                    end)
                end
            end)
        end
    end)
end

local function diss_get_instances_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local rr = t:add(usp_msg_proto, "RequestedPathResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then rr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 5 then rr:add(mf.err_code, val2)
                elseif fn2 == 3 and wt2 == 2 then rr:add(mf.err_msg,  val2)
                elseif fn2 == 4 and wt2 == 2 then
                    local ci = rr:add(usp_msg_proto, "CurrInstance")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then ci:add(mf.instantiated_path, val3)
                        elseif fn3 == 2 and wt3 == 2 then ci:add(mf.unique_key, decode_map_entry(val3))
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_set_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local ur = t:add(usp_msg_proto, "UpdatedObjectResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then ur:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    local ok = ur:add(usp_msg_proto, "OperationSuccess")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then
                            local ir = ok:add(usp_msg_proto, "UpdatedInstanceResult")
                            iter_fields(val3, function(fn4, wt4, val4)
                                if fn4 == 1 and wt4 == 2 then ir:add(mf.affected_path, val4)
                                elseif fn4 == 3 and wt4 == 2 then ir:add(mf.result_param, decode_map_entry(val4))
                                end
                            end)
                        end
                    end)
                elseif fn2 == 3 and wt2 == 2 then
                    local nok = ur:add(usp_msg_proto, "OperationFailure")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then nok:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then nok:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_add_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local cr = t:add(usp_msg_proto, "CreatedObjectResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then cr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    local ok = cr:add(usp_msg_proto, "OperationSuccess")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then ok:add(mf.instantiated_path, val3)
                        elseif fn3 == 3 and wt3 == 2 then ok:add(mf.unique_key, decode_map_entry(val3))
                        end
                    end)
                elseif fn2 == 3 and wt2 == 2 then
                    local nok = cr:add(usp_msg_proto, "OperationFailure")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then nok:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then nok:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_delete_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local dr = t:add(usp_msg_proto, "DeletedObjectResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then dr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    local ok = dr:add(usp_msg_proto, "OperationSuccess")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then ok:add(mf.affected_path, val3) end
                    end)
                elseif fn2 == 3 and wt2 == 2 then
                    local nok = dr:add(usp_msg_proto, "OperationFailure")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then nok:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then nok:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_operate_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local or_ = t:add(usp_msg_proto, "OperationResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then or_:add(mf.command,    val2)
                elseif fn2 == 2 and wt2 == 2 then or_:add(mf.obj_path,   val2)
                elseif fn2 == 3 and wt2 == 2 then
                    local oa = or_:add(usp_msg_proto, "OutputArgs")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then oa:add(mf.output_arg, decode_map_entry(val3)) end
                    end)
                elseif fn2 == 4 and wt2 == 2 then
                    local cf = or_:add(usp_msg_proto, "CommandFailure")
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then cf:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then cf:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_notify_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.sub_id, val) end
    end)
end

local function diss_get_supported_proto_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then t:add(mf.proto_vers, val) end
    end)
end

local function diss_register_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local rpr = t:add(usp_msg_proto, "RegisteredPathResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then rpr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then rpr:add(mf.registered_path, val3) end
                    end)
                elseif fn2 == 3 and wt2 == 2 then
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then rpr:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then rpr:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_deregister_resp(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local dpr = t:add(usp_msg_proto, "DeregisteredPathResult")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then dpr:add(mf.requested_path, val2)
                elseif fn2 == 2 and wt2 == 2 then
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 2 then dpr:add(mf.registered_path, val3) end
                    end)
                elseif fn2 == 3 and wt2 == 2 then
                    iter_fields(val2, function(fn3, wt3, val3)
                        if fn3 == 1 and wt3 == 5 then dpr:add(mf.err_code, val3)
                        elseif fn3 == 2 and wt3 == 2 then dpr:add(mf.err_msg,  val3)
                        end
                    end)
                end
            end)
        end
    end)
end

local function diss_error(s, t)
    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 5 then t:add(mf.err_code, val)
        elseif fn == 2 and wt == 2 then t:add(mf.err_msg, val)
        elseif fn == 3 and wt == 2 then
            local pe = t:add(usp_msg_proto, "ParamError")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then pe:add(mf.param_path, val2)
                elseif fn2 == 2 and wt2 == 5 then pe:add(mf.err_code,  val2)
                elseif fn2 == 3 and wt2 == 2 then pe:add(mf.err_msg,   val2)
                end
            end)
        end
    end)
end

local REQ_DISSECTORS = {
    [1]  = {"Get",                  diss_get},
    [2]  = {"GetSupportedDM",       diss_get_supported_dm},
    [3]  = {"GetInstances",         diss_get_instances},
    [4]  = {"Set",                  diss_set},
    [5]  = {"Add",                  diss_add},
    [6]  = {"Delete",               diss_delete},
    [7]  = {"Operate",              diss_operate},
    [8]  = {"Notify",               diss_notify},
    [9]  = {"GetSupportedProtocol", diss_get_supported_proto},
    [10] = {"Register",             diss_register},
    [11] = {"Deregister",           diss_deregister},
}

local RESP_DISSECTORS = {
    [1]  = {"GetResp",                   diss_get_resp},
    [2]  = {"GetSupportedDMResp",        diss_get_supported_dm_resp},
    [3]  = {"GetInstancesResp",          diss_get_instances_resp},
    [4]  = {"SetResp",                   diss_set_resp},
    [5]  = {"AddResp",                   diss_add_resp},
    [6]  = {"DeleteResp",                diss_delete_resp},
    [7]  = {"OperateResp",               diss_operate_resp},
    [8]  = {"NotifyResp",                diss_notify_resp},
    [9]  = {"GetSupportedProtocolResp",  diss_get_supported_proto_resp},
    [10] = {"RegisterResp",              diss_register_resp},
    [11] = {"DeregisterResp",            diss_deregister_resp},
}

-----------------------------------------------------------------------
-- USP Msg top-level dissector (operates on a Lua string)
-----------------------------------------------------------------------

local function dissect_usp_msg(s, parent_tree)
    local mt = parent_tree:add(usp_msg_proto, "USP Message")
    local msg_type_val = nil

    iter_fields(s, function(fn, wt, val)
        if fn == 1 and wt == 2 then
            local ht = mt:add(usp_msg_proto, "Header")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then
                    ht:add(mf.msg_id, val2)
                elseif fn2 == 2 and wt2 == 0 then
                    msg_type_val = val2
                    ht:add(mf.msg_type, val2)
                end
            end)

        elseif fn == 2 and wt == 2 then
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then
                    local req_t = mt:add(usp_msg_proto, "Request")
                    mt:add(mf.body_type, "Request")
                    iter_fields(val2, function(fn3, wt3, val3)
                        local d = REQ_DISSECTORS[fn3]
                        if d and wt3 == 2 then
                            local sub = req_t:add(usp_msg_proto, d[1])
                            d[2](val3, sub)
                        end
                    end)

                elseif fn2 == 2 and wt2 == 2 then
                    local resp_t = mt:add(usp_msg_proto, "Response")
                    mt:add(mf.body_type, "Response")
                    iter_fields(val2, function(fn3, wt3, val3)
                        local d = RESP_DISSECTORS[fn3]
                        if d and wt3 == 2 then
                            local sub = resp_t:add(usp_msg_proto, d[1])
                            d[2](val3, sub)
                        end
                    end)

                elseif fn2 == 3 and wt2 == 2 then
                    local err_t = mt:add(usp_msg_proto, "Error")
                    mt:add(mf.body_type, "Error")
                    diss_error(val2, err_t)
                end
            end)
        end
    end)

    local label = MSG_TYPES[msg_type_val] or ("MsgType=" .. tostring(msg_type_val))
    mt:set_text("USP Message [" .. label .. "]")
    return label
end

-----------------------------------------------------------------------
-- USP Record dissector (entry point, called with a TvbRange)
-----------------------------------------------------------------------

function usp_record_proto.dissector(tvb, pinfo, tree)
    if tvb:len() == 0 then return 0 end

    -- Always receives a proper Tvb (callers must use ByteArray:tvb() to wrap foreign ranges).
    local raw = tvb:bytes():raw()
    pinfo.cols.protocol:set("USP")

    local rec_t = tree:add(usp_record_proto, tvb(), "USP Record (TR-369)")
    local rtype = "Unknown"
    local payload_str = nil

    iter_fields(raw, function(fn, wt, val)
        if fn == 1 and wt == 2 then rec_t:add(rf.version,         val)
        elseif fn == 2 and wt == 2 then rec_t:add(rf.to_id,       val)
        elseif fn == 3 and wt == 2 then rec_t:add(rf.from_id,     val)
        elseif fn == 4 and wt == 0 then rec_t:add(rf.payload_security, val)
        elseif fn == 5 and wt == 2 then rec_t:add(rf.mac_signature, val)
        elseif fn == 6 and wt == 2 then rec_t:add(rf.sender_cert, val)

        elseif fn == 7 and wt == 2 then
            rtype = "NoSessionContext"
            local st = rec_t:add(usp_record_proto, "NoSessionContextRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 2 and wt2 == 2 then
                    st:add(rf.nsc_payload, val2)
                    payload_str = val2
                end
            end)

        elseif fn == 8 and wt == 2 then
            rtype = "SessionContext"
            local st = rec_t:add(usp_record_proto, "SessionContextRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 0 then st:add(rf.sc_session_id,     val2)
                elseif fn2 == 2 and wt2 == 0 then st:add(rf.sc_sequence_id,  val2)
                elseif fn2 == 3 and wt2 == 0 then st:add(rf.sc_expected_id,  val2)
                elseif fn2 == 4 and wt2 == 0 then st:add(rf.sc_retransmit_id,val2)
                elseif fn2 == 5 and wt2 == 0 then st:add(rf.sc_payload_sar,  val2)
                elseif fn2 == 6 and wt2 == 0 then st:add(rf.sc_payloadrec_sar,val2)
                elseif fn2 == 7 and wt2 == 2 then
                    st:add(rf.sc_payload, val2)
                    payload_str = val2
                end
            end)

        elseif fn == 9 and wt == 2 then
            rtype = "WebSocketConnect"
            local st = rec_t:add(usp_record_proto, "WebSocketConnectRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then st:add(rf.ws_topic, val2) end
            end)

        elseif fn == 10 and wt == 2 then
            rtype = "MQTTConnect"
            local st = rec_t:add(usp_record_proto, "MQTTConnectRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then st:add(rf.mqtt_version, val2)
                elseif fn2 == 2 and wt2 == 2 then st:add(rf.mqtt_topic,   val2)
                end
            end)

        elseif fn == 11 and wt == 2 then
            rtype = "STOMPConnect"
            local st = rec_t:add(usp_record_proto, "STOMPConnectRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 2 then st:add(rf.stomp_dest,    val2)
                elseif fn2 == 2 and wt2 == 2 then st:add(rf.stomp_version, val2)
                end
            end)

        elseif fn == 12 and wt == 2 then
            rtype = "UDSConnect"
            rec_t:add(usp_record_proto, "UDSConnectRecord")

        elseif fn == 13 and wt == 2 then
            rtype = "Disconnect"
            local st = rec_t:add(usp_record_proto, "DisconnectRecord")
            iter_fields(val, function(fn2, wt2, val2)
                if fn2 == 1 and wt2 == 5 then st:add(rf.disc_reason_code, val2)
                elseif fn2 == 2 and wt2 == 2 then st:add(rf.disc_reason,      val2)
                end
            end)
        end
    end)

    rec_t:add(rf.record_type, rtype)
    local info = "USP [" .. rtype .. "]"

    if payload_str and #payload_str > 0 then
        local ok, label = pcall(dissect_usp_msg, payload_str, rec_t)
        if ok and label then
            info = "USP [" .. rtype .. "] " .. label
        end
    end

    rec_t:set_text("USP Record [" .. rtype .. "]")
    pinfo.cols.info:set(info)
    return tvb:len()
end

-----------------------------------------------------------------------
-- MQTT payload hookup via post-dissector
-- Field name is "mqtt.msg" (the PUBLISH payload field in Wireshark's MQTT dissector)
-----------------------------------------------------------------------

local f_mqtt_payload = Field.new("mqtt.msg")

local post_proto = Proto("usp_postdissector", "USP MQTT Hookup")
function post_proto.dissector(tvb, pinfo, tree)
    local fis = {f_mqtt_payload()}
    if #fis == 0 then return end

    -- Copy bytes into a fresh standalone Tvb.
    -- When MQTT runs over TLS the field range lives in the inner decrypted
    -- TVB; passing that range directly to tree:add() causes a cross-TVB
    -- error, so we must materialise it into its own Tvb first.
    local ba = fis[1].range:bytes()
    if ba:len() < 2 then return end

    -- Heuristic: first byte must be a valid protobuf tag (fields 1-16, wire 0 or 2).
    local b0  = ba:get_index(0)
    local wt  = bit.band(b0, 0x7)
    local fn0 = bit.rshift(b0, 3)
    if (wt ~= 0 and wt ~= 2) or fn0 < 1 or fn0 > 16 then return end

    local payload_tvb = ba:tvb("USP Record")
    pcall(function()
        usp_record_proto.dissector(payload_tvb, pinfo, tree)
    end)
end

register_postdissector(post_proto)
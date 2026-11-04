-- SPDX-License-Identifier: Apache-2.0
-- Importé de https://github.com/Marnm/iec61850-packets-dec-lua (iec61850_dissector.lua),
-- commit 0969d65fdc4cefa8670e3cbcc3e669f46777a330 du 27/08/2026.
-- Licence amont : Apache-2.0 (LICENSE amont) — voir README.md.
-- IEC 61850 MMS/GOOSE/SV Wireshark Lua Dissector Plugin
-- This plugin provides basic dissection support for IEC 61850 protocols
-- Place this file in: ~/.local/lib/wireshark/plugins/ (Linux) or 
-- C:\Program Files\Wireshark\plugins\ (Windows)

-- Protocol definitions
local iec61850_proto = Proto("IEC61850", "IEC 61850 Protocol Suite")

-- Common fields
local f_apdu_type = ProtoField.uint8("iec61850.apdu_type", "APDU Type", base.DEC)
local f_length = ProtoField.uint16("iec61850.length", "Length", base.DEC)
local f_invoke_id = ProtoField.uint32("iec61850.invoke_id", "Invoke ID", base.DEC)

-- MMS Fields
local f_mms_service = ProtoField.uint8("iec61850.mms.service", "MMS Service", base.HEX)
local f_mms_data = ProtoField.bytes("iec61850.mms.data", "MMS Data")

-- GOOSE Fields  
local f_goose_appid = ProtoField.uint16("iec61850.goose.appid", "APPID", base.HEX)
local f_goose_length = ProtoField.uint16("iec61850.goose.length", "Length", base.DEC)
local f_goose_reserved = ProtoField.uint16("iec61850.goose.reserved", "Reserved", base.DEC)
local f_goose_pcap = ProtoField.string("iec61850.goose.pcap", "Protocol APDU")
local f_goose_gocbref = ProtoField.string("iec61850.goose.gocbref", "GoCB Reference")
local f_goose_timeallowedtolive = ProtoField.uint32("iec61850.goose.tatl", "TimeAllowedToLive", base.DEC)
local f_goose_datset = ProtoField.string("iec61850.goose.dataset", "DataSet Reference")
local f_goose_statusnumber = ProtoField.uint32("iec61850.goose.stnum", "stNum", base.DEC)
local f_goose_sequence = ProtoField.uint32("iec61850.goose.sqnum", "sqNum", base.DEC)
local f_goose_test = ProtoField.bool("iec61850.goose.test", "Test", 8, nil, 0x80, nil)
local f_goose_confrev = ProtoField.uint32("iec61850.goose.confrev", "ConfRev", base.DEC)
local f_goose_ndat = ProtoField.uint8("iec61850.goose.ndat", "NumDatSetEntries", base.DEC)
local f_goose_data = ProtoField.bytes("iec61850.goose.data", "All Data")

-- SV (Sampled Values) Fields
local f_sv_appid = ProtoField.uint16("iec61850.sv.appid", "APPID", base.HEX)
local f_sv_length = ProtoField.uint16("iec61850.sv.length", "Length", base.DEC)
local f_sv_reserved = ProtoField.uint16("iec61850.sv.reserved", "Reserved", base.DEC)
local f_sv_pcap = ProtoField.string("iec61850.sv.pcap", "Protocol APDU")
local f_sv_svid = ProtoField.string("iec61850.sv.svid", "SvID")
local f_sv_smpcnt = ProtoField.uint32("iec61850.sv.smpcnt", "SmpCnt", base.DEC)
local f_sv_confrev = ProtoField.uint32("iec61850.sv.confrev", "ConfRev", base.DEC)
local f_sv_smpsynch = ProtoField.bool("iec61850.sv.smpsynch", "SmpSynch", 8, nil, 0x80, nil)
local f_sv_datset = ProtoField.string("iec61850.sv.dataset", "DataSet Reference")
local f_sv_data = ProtoField.bytes("iec61850.sv.data", "All Data")

-- Register all fields
iec61850_proto.fields = {
    f_apdu_type, f_length, f_invoke_id,
    f_mms_service, f_mms_data,
    f_goose_appid, f_goose_length, f_goose_reserved, f_goose_pcap,
    f_goose_gocbref, f_goose_timeallowedtolive, f_goose_datset,
    f_goose_statusnumber, f_goose_sequence, f_goose_test,
    f_goose_confrev, f_goose_ndat, f_goose_data,
    f_sv_appid, f_sv_length, f_sv_reserved, f_sv_pcap,
    f_sv_svid, f_sv_smpcnt, f_sv_confrev, f_sv_smpsynch,
    f_sv_datset, f_sv_data
}

-- ASN.1 BER tag constants
local BER_TAG_SEQUENCE = 0x30
local BER_TAG_APPLICATION_0 = 0xA0
local BER_TAG_APPLICATION_1 = 0xA1
local BER_TAG_APPLICATION_2 = 0xA2
local BER_TAG_APPLICATION_3 = 0xA3
local BER_TAG_BOOLEAN = 0x01
local BER_TAG_INTEGER = 0x02
local BER_TAG_BIT_STRING = 0x03
local BER_TAG_OCTET_STRING = 0x04
local BER_TAG_NULL = 0x05
local BER_TAG_OID = 0x06
local BER_TAG_UTF8_STRING = 0x0C
local BER_TAG_VISIBLE_STRING = 0x1A
local BER_TAG_UTC_TIME = 0x17
local BER_TAG_GENERALIZED_TIME = 0x18
local BER_TAG_CONTEXT_0 = 0x80
local BER_TAG_CONTEXT_1 = 0x81

-- MMS Service Types
local mms_services = {
    [0x01] = "Initiate",
    [0x02] = "Conclude",
    [0x03] = "Reject",
    [0x04] = "Cancel",
    [0x05] = "GetVariableAccessAttributes",
    [0x06] = "DefineNamedVariable",
    [0x07] = "DefineScatteredAccess",
    [0x08] = "GetVariableAccessAttributes",
    [0x09] = "Read",
    [0x0A] = "Write",
    [0x0B] = "GetNamedVariableArrayAttributes",
    [0x0C] = "DefineNamedVariableArray",
    [0x0D] = "DeleteVariableAccess",
    [0x0E] = "DefineDomain",
    [0x0F] = "GetDomainAttributes",
    [0x10] = "DownloadSegment",
    [0x11] = "UploadSegment",
    [0x12] = "RequestDomainDownload",
    [0x13] = "RequestDomainUpload",
    [0x14] = "LoadDomainContents",
    [0x15] = "StoreDomainContents",
    [0x16] = "DeleteDomain",
    [0x17] = "GetProgramInvocationAttributes",
    [0x18] = "StartProgramInvocation",
    [0x19] = "StopProgramInvocation",
    [0x1A] = "ResumeProgramInvocation",
    [0x1B] = "KillProgramInvocation",
    [0x1C] = "GetProgramExecutionArgs",
    [0x1D] = "DefineProgramInvocation",
    [0x1E] = "DeleteProgramInvocation",
    [0x1F] = "EventNotification",
    [0x20] = "AlarmAcknowledge",
    [0x21] = "JournalInitialize",
    [0x22] = "JournalRead",
    [0x23] = "JournalStatus"
}

-- Helper function to decode BER length
function decode_ber_length(buffer, offset)
    local first_byte = buffer(offset, 1):uint()
    if first_byte < 0x80 then
        return first_byte, 1
    elseif first_byte == 0x80 then
        return -1, 1 -- Indefinite length
    else
        local num_bytes = first_byte - 0x80
        if num_bytes > 4 then
            return -1, 1
        end
        local length = 0
        for i = 0, num_bytes - 1 do
            length = length * 256 + buffer(offset + 1 + i, 1):uint()
        end
        return length, num_bytes + 1
    end
end

-- Helper function to decode BER tag and length
function decode_ber_tag_length(buffer, offset)
    if offset >= buffer:len() then
        return nil, 0, 0
    end
    
    local tag = buffer(offset, 1):uint()
    local length, len_size = decode_ber_length(buffer, offset + 1)
    
    return tag, length, 1 + len_size
end

-- Decode ASN.1 BER encoded data recursively
function decode_asn1_ber(buffer, offset, tree, prefix)
    if offset >= buffer:len() then
        return offset
    end
    
    local tag, length, header_size = decode_ber_tag_length(buffer, offset)
    if not tag then
        return offset
    end
    
    if length == -1 then
        length = buffer:len() - offset - header_size
    end
    
    local tag_tree = tree:add(prefix .. string.format(" Tag: 0x%02X", tag), buffer(offset, header_size + length))
    
    -- Add specific interpretation based on tag type
    if tag == BER_TAG_BOOLEAN then
        local value = buffer(offset + header_size, length):uint()
        tag_tree:append_text(string.format(" (BOOLEAN): %s", value ~= 0 and "true" or "false"))
    elseif tag == BER_TAG_INTEGER then
        if length == 1 then
            local value = buffer(offset + header_size, length):uint()
            tag_tree:append_text(string.format(" (INTEGER): %d", value))
        elseif length == 2 then
            local value = buffer(offset + header_size, length):uint()
            tag_tree:append_text(string.format(" (INTEGER): %d", value))
        elseif length <= 4 then
            local value = buffer(offset + header_size, length):uint()
            tag_tree:append_text(string.format(" (INTEGER): %d", value))
        else
            tag_tree:append_text(" (INTEGER)")
        end
    elseif tag == BER_TAG_BIT_STRING then
        tag_tree:append_text(" (BIT STRING)")
    elseif tag == BER_TAG_OCTET_STRING then
        tag_tree:append_text(" (OCTET STRING)")
    elseif tag == BER_TAG_NULL then
        tag_tree:append_text(" (NULL)")
    elseif tag == BER_TAG_OID then
        tag_tree:append_text(" (OBJECT IDENTIFIER)")
    elseif tag == BER_TAG_UTF8_STRING or tag == BER_TAG_VISIBLE_STRING then
        local str_value = buffer(offset + header_size, length):string()
        tag_tree:append_text(string.format(" (STRING): '%s'", str_value))
    elseif tag == BER_TAG_SEQUENCE then
        tag_tree:append_text(" (SEQUENCE)")
        -- Recursively decode sequence contents
        local seq_offset = offset + header_size
        local seq_end = offset + header_size + length
        while seq_offset < seq_end do
            seq_offset = decode_asn1_ber(buffer, seq_offset, tag_tree, "  ")
        end
    elseif bit32.band(tag, 0xE0) == 0xA0 then -- Application class
        local app_num = bit32.band(tag, 0x1F)
        tag_tree:append_text(string.format(" (APPLICATION %d)", app_num))
        -- Recursively decode application contents
        local app_offset = offset + header_size
        local app_end = offset + header_size + length
        while app_offset < app_end do
            app_offset = decode_asn1_ber(buffer, app_offset, tag_tree, "  ")
        end
    else
        tag_tree:append_text(string.format(" (Tag: 0x%02X)", tag))
    end
    
    return offset + header_size + length
end

-- GOOSE dissector
function dissect_goose(buffer, pinfo, root)
    local goose_tree = root:add(iec61850_proto, buffer(), "GOOSE Packet")
    
    if buffer:len() < 4 then
        goose_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "GOOSE packet too short")
        return
    end
    
    local offset = 0
    
    -- APPID (2 bytes)
    local appid = buffer(offset, 2):uint()
    goose_tree:add(f_goose_appid, buffer(offset, 2)):append_text(string.format(" (0x%04X)", appid))
    offset = offset + 2
    
    -- Length (2 bytes)
    local length = buffer(offset, 2):uint()
    goose_tree:add(f_goose_length, buffer(offset, 2))
    offset = offset + 2
    
    -- Reserved (2 bytes)
    local reserved = buffer(offset, 2):uint()
    goose_tree:add(f_goose_reserved, buffer(offset, 2))
    offset = offset + 2
    
    -- Remaining is the Protocol APDU (ASN.1 BER encoded)
    if offset < buffer:len() then
        local pcap_buffer = buffer(offset, buffer:len() - offset)
        goose_tree:add(f_goose_pcap, pcap_buffer)
        
        -- Try to decode ASN.1 BER structure
        decode_asn1_ber(pcap_buffer, 0, goose_tree, "GOOSE APDU")
    end
    
    -- Set protocol info
    pinfo.cols.protocol:set("GOOSE")
    pinfo.cols.info:set(string.format("GOOSE AppID: 0x%04X", appid))
end

-- SV (Sampled Values) dissector
function dissect_sv(buffer, pinfo, root)
    local sv_tree = root:add(iec61850_proto, buffer(), "Sampled Values Packet")
    
    if buffer:len() < 4 then
        sv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "SV packet too short")
        return
    end
    
    local offset = 0
    
    -- APPID (2 bytes)
    local appid = buffer(offset, 2):uint()
    sv_tree:add(f_sv_appid, buffer(offset, 2)):append_text(string.format(" (0x%04X)", appid))
    offset = offset + 2
    
    -- Length (2 bytes)
    local length = buffer(offset, 2):uint()
    sv_tree:add(f_sv_length, buffer(offset, 2))
    offset = offset + 2
    
    -- Reserved (2 bytes)
    local reserved = buffer(offset, 2):uint()
    sv_tree:add(f_sv_reserved, buffer(offset, 2))
    offset = offset + 2
    
    -- Remaining is the Protocol APDU (ASN.1 BER encoded)
    if offset < buffer:len() then
        local pcap_buffer = buffer(offset, buffer:len() - offset)
        sv_tree:add(f_sv_pcap, pcap_buffer)
        
        -- Try to decode ASN.1 BER structure
        decode_asn1_ber(pcap_buffer, 0, sv_tree, "SV APDU")
    end
    
    -- Set protocol info
    pinfo.cols.protocol:set("SV")
    pinfo.cols.info:set(string.format("SV AppID: 0x%04X", appid))
end

-- MMS over TCP dissector
function dissect_mms(buffer, pinfo, root)
    local mms_tree = root:add(iec61850_proto, buffer(), "MMS Packet")
    
    if buffer:len() < 1 then
        mms_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "MMS packet too short")
        return
    end
    
    local offset = 0
    
    -- Try to decode as ASN.1 BER encoded MMS PDU
    decode_asn1_ber(buffer, 0, mms_tree, "MMS APDU")
    
    -- Set protocol info
    pinfo.cols.protocol:set("MMS")
    pinfo.cols.info:set("MMS Protocol Data Unit")
end

-- Main dissector function
function iec61850_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then
        return
    end
    
    local subtree = tree:add(iec61850_proto, buffer(), "IEC 61850 Protocol")
    
    -- Determine protocol type based on port or packet characteristics
    local src_port = pinfo.src_port
    local dst_port = pinfo.dest_port
    
    -- Check for GOOSE (typically Ethernet type 0x88B8, but we check packet structure)
    -- GOOSE packets usually start with APPID in range 0x0000-0x3FFF
    if buffer:len() >= 4 then
        local potential_appid = buffer(0, 2):uint()
        
        -- GOOSE identification: APPID typically in 0x0000-0x3FFF range
        -- and second length field matches remaining packet size
        if potential_appid <= 0x3FFF then
            local potential_length = buffer(2, 2):uint()
            if potential_length == buffer:len() - 4 then
                dissect_goose(buffer, pinfo, subtree)
                return
            end
        end
        
        -- SV identification: APPID typically in 0x4000-0x7FFF range
        if potential_appid >= 0x4000 and potential_appid <= 0x7FFF then
            local potential_length = buffer(2, 2):uint()
            if potential_length == buffer:len() - 4 then
                dissect_sv(buffer, pinfo, subtree)
                return
            end
        end
    end
    
    -- Check for MMS over TCP (ports 102 or common MMS ports)
    if src_port and dst_port then
        local port_num = math.min(src_port:value(), dst_port:value())
        if port_num == 102 or port_num == 1002 or port_num == 10002 then
            dissect_mms(buffer, pinfo, subtree)
            return
        end
    end
    
    -- Default: try to detect based on content
    -- If it looks like ASN.1 BER encoded data, treat as MMS
    if buffer:len() > 0 then
        local first_byte = buffer(0, 1):uint()
        if first_byte == BER_TAG_SEQUENCE or 
           first_byte == BER_TAG_APPLICATION_0 or 
           first_byte == BER_TAG_APPLICATION_1 then
            dissect_mms(buffer, pinfo, subtree)
            return
        end
    end
    
    -- Unknown IEC 61850 protocol
    subtree:add_expert_info(PI_UNDECODED, PI_WARN, "Unknown IEC 61850 protocol type")
    pinfo.cols.protocol:set("IEC61850")
    pinfo.cols.info:set("IEC 61850 (Unknown Type)")
end

-- Register dissector for Ethernet types
local ethernet_type_table = DissectorTable.get("ethertype")
if ethernet_type_table then
    -- GOOSE uses Ethernet type 0x88B8
    ethernet_type_table:add(0x88B8, iec61850_proto)
    -- SV uses Ethernet type 0x88BA  
    ethernet_type_table:add(0x88BA, iec61850_proto)
end

-- Register dissector for TCP ports
local tcp_port_table = DissectorTable.get("tcp.port")
if tcp_port_table then
    -- MMS typically uses port 102
    tcp_port_table:add(102, iec61850_proto)
    tcp_port_table:add(1002, iec61850_proto)
    tcp_port_table:add(10002, iec61850_proto)
end

-- Register dissector for UDP ports (some implementations may use UDP)
local udp_port_table = DissectorTable.get("udp.port")
if udp_port_table then
    udp_port_table:add(102, iec61850_proto)
end

-- Plugin information
set_plugin_info({
    name = "IEC 61850 Protocol Dissector",
    version = "1.0.0",
    author = "IEC 61850 Working Group",
    description = "Dissector for IEC 61850 GOOSE, SV, and MMS protocols",
    repository = "https://github.com/iec61850/wireshark-plugin"
})

-- Debug output when plugin loads (use print for Wireshark Lua)
-- debug("IEC 61850 plugin loaded successfully")

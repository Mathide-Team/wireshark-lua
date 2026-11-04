-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/bivex/Noise_IK_25519_ChaChaPoly_BLAKE2b (wireshark/noise_ik.lua),
-- commit 44cf04b0d7e9ada98f24f40304fea001e75c79be du 24/02/2026.
-- Licence amont : MIT — voir README.md.
-- noise_ik.lua - Wireshark dissector for Noise_IK_25519_ChaChaPoly_BLAKE2b
-- Place in: ~/.local/lib/wireshark/plugins/ (Linux)
--            ~/Library/Application Support/Wireshark/Plugins/ (macOS)
--            %APPDATA%\Wireshark\plugins\ (Windows)

-- Create the protocol
local noise_ik_proto = Proto("noise_ik", "Noise IK Protocol")

-- Protocol fields
local f_length = ProtoField.uint16("noise_ik.length", "Message Length", base.DEC)
local f_msg_type = ProtoField.uint8("noise_ik.msg_type", "Message Type", base.DEC)
local f_direction = ProtoField.string("noise_ik.direction", "Direction", base.ASCII)

-- Handshake fields
local f_e_pub = ProtoField.bytes("noise_ik.e_pub", "Ephemeral Public Key", base.SPACE)
local f_s_enc = ProtoField.bytes("noise_ik.s_enc", "Encrypted Static Key", base.SPACE)
local f_auth_tag = ProtoField.bytes("noise_ik.auth_tag", "Poly1305 Auth Tag", base.SPACE)

-- Transport fields
local f_encrypted = ProtoField.bytes("noise_ik.encrypted", "Encrypted Payload", base.SPACE)

noise_ik_proto.fields = {
    f_length, f_msg_type, f_direction,
    f_e_pub, f_s_enc, f_auth_tag, f_encrypted
}

-- Message structure constants
local EPHEMERAL_KEY_LEN = 32
local AUTH_TAG_LEN = 16

-- Desegment data to get complete messages
noise_ik_proto.dissector = function(buffer, pinfo, tree)
    local len = buffer:len()

    -- Need at least 2 bytes for length prefix
    if len < 2 then
        -- Ask for more data
        pinfo.desegment_offset = 0
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- Read length prefix (big-endian)
    local msg_len = buffer(0, 2):uint()

    -- Sanity check
    if msg_len < 32 or msg_len > 65535 then
        return 0
    end

    -- Check if we have the complete message
    local total_len = 2 + msg_len
    if len < total_len then
        -- Need more data - request desegmentation
        pinfo.desegment_offset = 0
        pinfo.desegment_len = total_len - len
        return
    end

    -- Determine message type
    local msg_type = 0
    local msg_type_name = "Unknown"
    local direction = pinfo.src_port > pinfo.dst_port and "C→S" or "S→C"

    if msg_len == 96 then
        msg_type = 1
        msg_type_name = "Handshake Init: e, s"
    elseif msg_len == 48 then
        msg_type = 2
        msg_type_name = "Handshake Response: e, ee, se"
    elseif msg_len == 45 then
        msg_type = 3
        msg_type_name = "Handshake Final: s, es + Data"
    elseif msg_len == 44 then
        msg_type = 4
        msg_type_name = "Transport Response"
    else
        msg_type = 5
        msg_type_name = "Transport Data"
    end

    -- Create tree
    local subtree = tree:add(noise_ik_proto, buffer(0, total_len),
        "Noise IK Protocol, " .. direction .. ", " .. msg_type_name)

    subtree:add(f_length, buffer(0, 2))
    subtree:add(f_msg_type, msg_type)
    subtree:add(f_direction, direction)

    -- Parse payload
    local payload = buffer(2, msg_len)
    local offset = 0

    if msg_type == 1 then
        -- Initiator: e (32) + encrypted s + auth tag
        if msg_len >= EPHEMERAL_KEY_LEN then
            subtree:add(f_e_pub, payload(0, EPHEMERAL_KEY_LEN))
            offset = EPHEMERAL_KEY_LEN
        end
        if msg_len >= offset + AUTH_TAG_LEN then
            subtree:add(f_auth_tag, payload(msg_len - AUTH_TAG_LEN, AUTH_TAG_LEN))
            subtree:add(f_s_enc, payload(offset, msg_len - offset - AUTH_TAG_LEN))
        end

    elseif msg_type == 2 then
        -- Responder: e (32) + auth tag
        if msg_len >= EPHEMERAL_KEY_LEN then
            subtree:add(f_e_pub, payload(0, EPHEMERAL_KEY_LEN))
        end
        if msg_len >= EPHEMERAL_KEY_LEN + AUTH_TAG_LEN then
            subtree:add(f_auth_tag, payload(EPHEMERAL_KEY_LEN, AUTH_TAG_LEN))
        end

    else
        -- Transport: encrypted data + auth tag
        if msg_len >= AUTH_TAG_LEN then
            subtree:add(f_auth_tag, payload(msg_len - AUTH_TAG_LEN, AUTH_TAG_LEN))
            subtree:add(f_encrypted, payload(0, msg_len - AUTH_TAG_LEN))
        end
    end

    pinfo.cols.protocol = "NOISE-IK"
    pinfo.cols.info = direction .. " " .. msg_type_name

    return total_len
end

-- Register as a data dissector for TCP
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(8000, noise_ik_proto)
tcp_dissector_table:add(7000, noise_ik_proto)

-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/z-jack/wireshark-lua-plugins (oicq_enhanced.lua),
-- commit 6b685ef6c4fb461997ac2b973b1ab665df1a8214 du 24/06/2018.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
do
    --[[

    Proto.new(name, desc)

        name: displayed in the column of “Protocol” in the packet list

        desc: displayed as the dissection tree root in the packet details

    --]]
    local PROTO_OICQ = Proto("QPlus", "OICQ Protocol(Enhanced) - IM software, popular in China")

    --[[

    ProtoField:

        to be used when adding items to the dissection tree

    --]]
    local hf_oicq_flg = ProtoField.uint8("OICQ.Flag", "Flag", base.HEX)

    local hf_oicq_version = ProtoField.uint16("OICQ.Version", "Version", base.HEX)

    local hf_oicq_command = ProtoField.string("OICQ.Command", "Command")

    local hf_oicq_seq = ProtoField.uint16("OICQ.Seq", "Sequence", base.DEC)

    local hf_oicq_qqid = ProtoField.uint32("OICQ.QID", "OICQ Number", base.DEC)

    local hf_oicq_eflg = ProtoField.uint8("OICQ.EFlag", "End Flag", base.HEX)

    -- define the fields table of this dissector(as a protoField array)

    PROTO_OICQ.fields = {hf_oicq_flg, hf_oicq_version, hf_oicq_command, hf_oicq_seq, hf_oicq_qqid, hf_oicq_eflg}

    --[[

    Data Section

    --]]
    local data_dis = Dissector.get("data")

    --[[

    OICQ Dissector Function

    --]]
    local function roh_dissector(buf, pkt, root)
        -- check buffer length

        local buf_len = buf:len()

        if buf_len < 12 then
            return false
        end

        -- check flag

        if buf(0, 1):uint() ~= 0x02 then
            return false
        end

        -- check end flag

        if buf(buf_len - 1, 1):uint() ~= 0x03 then
            return false
        end

        --[[

        packet list columns

        --]]
        pkt.cols.protocol = "OICQ"

        pkt.cols.info = "OICQ Protocol(Enhanced) - IM software, popular in China"

        --[[

        OICQ command list

        ]]
        local command_list = {}
        command_list[0x0001] = "Log out"
        command_list[0x0002] = "Heart Message"
        command_list[0x0004] = "Update User information"
        command_list[0x0005] = "Search user"
        command_list[0x0006] = "Get User informationBroadcast"
        command_list[0x0009] = "Add friend no auth"
        command_list[0x000a] = "Delete user"
        command_list[0x000b] = "Add friend by auth"
        command_list[0x000d] = "Set status"
        command_list[0x0012] = "Confirmation of receiving message from server"
        command_list[0x0016] = "Send message"
        command_list[0x0017] = "Receive message"
        command_list[0x0018] = "Retrieve information"
        command_list[0x001a] = "Reserved "
        command_list[0x001c] = "Delete Me"
        command_list[0x001d] = "Request KEY"
        command_list[0x0021] = "Cell Phone"
        command_list[0x0022] = "Log in"
        command_list[0x0026] = "Get friend list"
        command_list[0x0027] = "Get friend online"
        command_list[0x0029] = "Cell PHONE"
        command_list[0x0030] = "Operation on group"
        command_list[0x0031] = "Log in test"
        command_list[0x003c] = "Group name operation"
        command_list[0x003d] = "Upload group friend"
        command_list[0x003e] = "MEMO Operation"
        command_list[0x0058] = "Download group friend"
        command_list[0x005c] = "Get level"
        command_list[0x0062] = "Request login"
        command_list[0x0065] = "Request extra information"
        command_list[0x0067] = "Signature operation"
        command_list[0x0080] = "Receive system message"
        command_list[0x0081] = "Get status of friend"
        command_list[0x00b5] = "Get friend's status of group"

        --[[

        dissection tree in packet details

        --]]
        -- tree root

        local t = root:add(PROTO_OICQ, buf(0, buf_len))

        -- child items

        t:add(hf_oicq_flg, buf(0, 1))

        t:add(hf_oicq_version, buf(1, 2))

        local cmd = buf(3, 2):uint()

        if command_list[cmd] then
            t:add(hf_oicq_command, buf(3, 2), string.format("%s (%d)", command_list[cmd], cmd))
        else
            t:add(hf_oicq_command, buf(3, 2), string.format("Unknown (%d)", cmd))
        end

        t:add(hf_oicq_seq, buf(5, 2))

        t:add(hf_oicq_qqid, buf(7, 4))

        t:add(hf_oicq_eflg, buf(buf_len - 1, 1))

        if buf_len > 12 then
            local d = root:add(buf(11, buf_len - 12), "OICQ Data")
        end

        return true
    end

    --[[

    Dissect Process

    --]]
    function PROTO_OICQ.dissector(buf, pkt, root)
        if roh_dissector(buf, pkt, root) then
            -- valid ROH diagram
        else
            data_dis:call(buf, pkt, root)
        end
    end

    --[[

    Specify Protocol Port

    --]]
    local tcp_encap_table = DissectorTable.get("udp.port")

    tcp_encap_table:set(8000, PROTO_OICQ)
end

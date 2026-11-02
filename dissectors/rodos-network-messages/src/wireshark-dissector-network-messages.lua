-- SPDX-License-Identifier: Apache-2.0
-- Importé de https://github.com/fantana21/rodos (support/tools/wireshark-dissector-network-messages.lua),
-- commit 81072d9244e29aff24b7dd751f93a7989e0efbdf du 14/04/2026 (dernière modification du fichier :
-- commit ee10bc32f889d8e0f148c66bc12b3496cf526e17 du 02/04/2024).
-- Licence amont : Apache-2.0 (LICENCE.txt amont) — voir README.md et LICENSE.
-- Decoder for rodos NetwerkMessages sent over UDP
-- this is a yet unfinished debugging tool from Sebastian Kind, he is still working on it
-- 20.03.2024
-- usage:
-- sudo wireshark -X lua_script:'/path/to/this/script'
-- now you can filter by RODOS and see networkmessages within UDP packets

-- Define the Rodos protocol
rodos_protocol = Proto("Rodos", "Rodos Protocol")

-- Define the fields
receiver_node = ProtoField.int32("rodos.receiver_node", "Receiver Node")
receiver_nodes_bitmap = ProtoField.uint32("rodos.receiver_nodes_bitmap", "Receiver Nodes Bitmap")
max_steps_to_forward = ProtoField.int16("rodos.max_steps_to_forward", "Max Steps to Forward")
checksum = ProtoField.uint16("rodos.checksum", "Checksum")
message_type = ProtoField.uint16("rodos.message_type", "Message Type")
message_length = ProtoField.uint16("rodos.message_length", "Message Length")
sender_node = ProtoField.int32("rodos.sender_node", "Sender Node")
sent_time = ProtoField.int64("rodos.sent_time", "Sent Time")
sender_thread_id = ProtoField.uint32("rodos.sender_thread_id", "Sender Thread ID")
topic_id = ProtoField.uint32("rodos.topic_id", "Topic ID")

-- Add the fields to the protocol
rodos_protocol.fields = { receiver_node, receiver_nodes_bitmap, max_steps_to_forward, checksum, message_type, message_length, sender_node, sent_time, sender_thread_id, topic_id }

-- Define the dissector function
function rodos_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 36 then return end -- Minimum length check

    pinfo.cols.protocol = rodos_protocol.name

    local subtree = tree:add(rodos_protocol, buffer(), "Rodos Protocol Data")

    -- Add fields to the subtree
    subtree:add(receiver_node, buffer(0, 4))
    subtree:add(receiver_nodes_bitmap, buffer(4, 4))
    subtree:add(max_steps_to_forward, buffer(8, 2))
    subtree:add(checksum, buffer(10, 2))
    subtree:add(message_type, buffer(12, 2))
    subtree:add(message_length, buffer(14, 2))
    subtree:add(sender_node, buffer(16, 4))
    subtree:add(sent_time, buffer(20, 8))
    subtree:add(sender_thread_id, buffer(28, 4))
    subtree:add(topic_id, buffer(32, 4))
end

-- Register the dissector
udp_table = DissectorTable.get("udp.port"):add(50000, rodos_protocol)

-- SPDX-License-Identifier: Apache-2.0
-- Importé de https://github.com/rigazilla/hotrod-dissector (src/hotrod.lua),
-- commit 19c62707b03503efb34ba8b266c10c5d91ea63e1 du 08/05/2026.
-- Licence amont : Apache-2.0 (LICENSE amont) — voir README.md.
-- Wireshark Dissector for Infinispan Hot Rod Protocol 4.0+
-- Based on hotrod40.ksy schema and protocol documentation
--
-- Installation:
--   Linux/macOS: ~/.local/lib/wireshark/plugins/hotrod.lua
--   Windows: %APPDATA%\Wireshark\plugins\hotrod.lua
--   Then press Ctrl+Shift+L in Wireshark to reload
--
-- Protocol versions supported:
--   - 4.0 (0x28 = 40 decimal) - Infinispan 14.0+
--   - 4.1 (0x29 = 41 decimal) - Infinispan 15.1+
--
-- Assumptions:
--   - Client intelligence: 0x03 (HASH_DISTRIBUTION_AWARE)

-- ============================================================================
-- Protocol Declaration
-- ============================================================================

local hotrod_protocol = Proto("hotrod", "Infinispan Hot Rod Protocol")

-- ============================================================================
-- Helper Functions for Variable-Length Integer Encoding
-- ============================================================================

-- Read unsigned variable-length integer (1-5 bytes for vint)
-- Returns: value, bytes_read
function read_vint(tvb, offset)
    if offset >= tvb:len() then
        return nil, 0
    end

    local value = 0
    local shift = 0
    local bytes_read = 0

    while bytes_read < 5 do  -- max 5 bytes for vint
        if offset + bytes_read >= tvb:len() then
            return nil, 0
        end

        local b = tvb(offset + bytes_read, 1):uint()
        value = bit.bor(value, bit.lshift(bit.band(b, 0x7F), shift))
        bytes_read = bytes_read + 1
        shift = shift + 7

        -- Check continuation bit (high bit)
        if bit.band(b, 0x80) == 0 then
            break
        end
    end

    return value, bytes_read
end

-- Read unsigned variable-length long (1-9 bytes for vlong)
-- Returns: value, bytes_read
function read_vlong(tvb, offset)
    if offset >= tvb:len() then
        return nil, 0
    end

    local value = 0
    local shift = 0
    local bytes_read = 0

    while bytes_read < 9 do  -- max 9 bytes for vlong
        if offset + bytes_read >= tvb:len() then
            return nil, 0
        end

        local b = tvb(offset + bytes_read, 1):uint()
        value = value + bit.lshift(bit.band(b, 0x7F), shift)
        bytes_read = bytes_read + 1
        shift = shift + 7

        -- Check continuation bit (high bit)
        if bit.band(b, 0x80) == 0 then
            break
        end
    end

    return value, bytes_read
end

-- Read signed variable-length integer with ZigZag encoding
-- Returns: signed_value, bytes_read
function read_signed_vint(tvb, offset)
    local unsigned_value, bytes_read = read_vint(tvb, offset)
    if unsigned_value == nil then
        return nil, 0
    end

    -- ZigZag decode: (n >>> 1) ^ -(n & 1)
    local signed_value = bit.bxor(bit.rshift(unsigned_value, 1), -bit.band(unsigned_value, 1))

    return signed_value, bytes_read
end

-- Read length-prefixed bytes
-- Returns: tvb_range, total_bytes_read (including length prefix)
function read_lp_bytes(tvb, offset)
    local length, len_bytes = read_vint(tvb, offset)
    if length == nil then
        return nil, 0
    end

    if offset + len_bytes + length > tvb:len() then
        return nil, 0
    end

    local data_range = tvb(offset + len_bytes, length)
    return data_range, len_bytes + length
end

-- Read length-prefixed UTF-8 string
-- Returns: string_value, total_bytes_read
function read_lp_string(tvb, offset)
    local data_range, total_bytes = read_lp_bytes(tvb, offset)
    if data_range == nil then
        return nil, 0
    end

    local str = data_range:string()
    return str, total_bytes
end

-- Helper: Add lp_bytes to tree with length field displayed
-- Also adds string representation if string_field is provided
-- Returns: offset after data
function add_lp_bytes_with_length(tree, tvb, offset, bytes_field, string_field, length_field, label)
    local length, len_bytes = read_vint(tvb, offset)
    if length == nil then
        return offset
    end

    if offset + len_bytes + length > tvb:len() then
        return offset
    end

    -- Add length field
    local length_item = tree:add(length_field, tvb(offset, len_bytes))
    length_item:append_text(string.format(" (%d bytes)", length))

    -- Add data field as bytes (hex)
    tree:add(bytes_field, tvb(offset + len_bytes, length))

    -- Add data field as string (text) if string_field provided
    if string_field ~= nil then
        local str_data = tvb(offset + len_bytes, length):string()
        tree:add(string_field, tvb(offset + len_bytes, length), str_data)
    end

    return offset + len_bytes + length
end

-- Helper: Add lp_string to tree with length field displayed
-- Returns: offset after string
function add_lp_string_with_length(tree, tvb, offset, field, length_field, label)
    local length, len_bytes = read_vint(tvb, offset)
    if length == nil then
        return offset
    end

    if offset + len_bytes + length > tvb:len() then
        return offset
    end

    -- Add length field
    local length_item = tree:add(length_field, tvb(offset, len_bytes))
    length_item:append_text(string.format(" (%d bytes)", length))

    -- Add string field
    local str = tvb(offset + len_bytes, length):string()
    tree:add(field, tvb(offset + len_bytes, length), str)

    return offset + len_bytes + length
end

-- ============================================================================
-- Protocol Field Definitions
-- ============================================================================

-- Magic byte
local f_magic = ProtoField.uint8("hotrod.magic", "Magic Byte", base.HEX)

-- Header containers (for tree organization)
local f_req_header = ProtoField.none("hotrod.req.header", "Request Header")
local f_resp_header = ProtoField.none("hotrod.resp.header", "Response Header")

-- Request Header Fields
local f_req_message_id = ProtoField.uint64("hotrod.req.message_id", "Message ID", base.DEC)
local f_req_version = ProtoField.uint8("hotrod.req.version", "Protocol Version", base.DEC)
local f_req_opcode = ProtoField.uint8("hotrod.req.opcode", "Request Opcode", base.HEX)
local f_req_cache_name = ProtoField.string("hotrod.req.cache_name", "Cache Name")
local f_req_flags = ProtoField.uint64("hotrod.req.flags", "Flags", base.HEX)
local f_req_client_intelligence = ProtoField.uint8("hotrod.req.client_intelligence", "Client Intelligence", base.HEX)
local f_req_topology_id = ProtoField.uint64("hotrod.req.topology_id", "Topology ID", base.DEC)

-- Response Header Fields
local f_resp_message_id = ProtoField.uint64("hotrod.resp.message_id", "Message ID", base.DEC)
local f_resp_opcode = ProtoField.uint8("hotrod.resp.opcode", "Response Opcode", base.HEX)
local f_resp_status = ProtoField.uint8("hotrod.resp.status", "Status", base.HEX)
local f_resp_topology_marker = ProtoField.uint8("hotrod.resp.topology_marker", "Topology Change Marker", base.HEX)
local f_resp_in_frame = ProtoField.framenum("hotrod.resp.request_in", "Request in Frame", base.NONE)
local f_req_in_frame = ProtoField.framenum("hotrod.req.response_in", "Response in Frame", base.NONE)

-- Topology Change Fields
local f_topology_id = ProtoField.uint64("hotrod.topology.id", "Topology ID", base.DEC)
local f_topology_num_servers = ProtoField.uint64("hotrod.topology.num_servers", "Number of Servers", base.DEC)
local f_topology_server_host = ProtoField.string("hotrod.topology.server.host", "Server Host")
local f_topology_server_port = ProtoField.uint16("hotrod.topology.server.port", "Server Port", base.DEC)
local f_topology_hash_function = ProtoField.uint8("hotrod.topology.hash_function", "Hash Function Version", base.DEC)
local f_topology_num_segments = ProtoField.uint64("hotrod.topology.num_segments", "Number of Segments", base.DEC)
local f_topology_segment_owners = ProtoField.uint8("hotrod.topology.segment.num_owners", "Number of Owners", base.DEC)
local f_topology_owner_index = ProtoField.uint8("hotrod.topology.segment.owner", "Owner Index", base.DEC)

-- MediaType Fields (no f_media_type - we'll create the tree directly)
local f_media_type_indicator = ProtoField.uint8("hotrod.media_type.indicator", "Type Indicator", base.HEX)
local f_media_type_predefined_id = ProtoField.uint64("hotrod.media_type.predefined_id", "Predefined ID", base.DEC)
local f_media_type_custom = ProtoField.string("hotrod.media_type.custom", "Custom Type")
local f_media_type_param_count = ProtoField.uint64("hotrod.media_type.param_count", "Parameter Count", base.DEC)
local f_media_type_param_key = ProtoField.string("hotrod.media_type.param.key", "Parameter Key")
local f_media_type_param_value = ProtoField.string("hotrod.media_type.param.value", "Parameter Value")

-- Other Params Fields (Protocol 4.0+)
local f_other_param_count = ProtoField.uint64("hotrod.other_param_count", "Other Parameter Count", base.DEC)
local f_other_param_key = ProtoField.string("hotrod.other_param.key", "Parameter Key")
local f_other_param_value = ProtoField.bytes("hotrod.other_param.value", "Parameter Value")

-- Body Fields
local f_key = ProtoField.bytes("hotrod.key", "Key (hex)")
local f_key_string = ProtoField.string("hotrod.key.string", "Key (string)")
local f_key_length = ProtoField.uint64("hotrod.key.length", "Key Length", base.DEC)
local f_value = ProtoField.bytes("hotrod.value", "Value (hex)")
local f_value_string = ProtoField.string("hotrod.value.string", "Value (string)")
local f_value_length = ProtoField.uint64("hotrod.value.length", "Value Length", base.DEC)
local f_string_length = ProtoField.uint64("hotrod.string.length", "String Length", base.DEC)
local f_bytes_length = ProtoField.uint64("hotrod.bytes.length", "Bytes Length", base.DEC)
local f_time_units = ProtoField.uint8("hotrod.time_units", "Time Units", base.HEX)
local f_lifespan = ProtoField.uint64("hotrod.lifespan", "Lifespan", base.DEC)
local f_max_idle = ProtoField.uint64("hotrod.max_idle", "Max Idle", base.DEC)

-- Entry Metadata Fields (Protocol 4.0+)
local f_metadata_flag = ProtoField.uint8("hotrod.metadata.flag", "Metadata Flag", base.HEX)
local f_metadata_created = ProtoField.int64("hotrod.metadata.created", "Created", base.DEC)
local f_metadata_lifespan = ProtoField.uint64("hotrod.metadata.lifespan", "Lifespan", base.DEC)
local f_metadata_last_used = ProtoField.int64("hotrod.metadata.last_used", "Last Used", base.DEC)
local f_metadata_max_idle = ProtoField.uint64("hotrod.metadata.max_idle", "Max Idle", base.DEC)
local f_metadata_version = ProtoField.int64("hotrod.metadata.version", "Entry Version", base.DEC)

-- PING Response Fields
local f_ping_key_type = ProtoField.none("hotrod.ping.key_type", "Key Type")
local f_ping_value_type = ProtoField.none("hotrod.ping.value_type", "Value Type")
local f_ping_server_version = ProtoField.uint8("hotrod.ping.server_version", "Server Version", base.DEC)
local f_ping_op_count = ProtoField.uint64("hotrod.ping.op_count", "Supported Operation Count", base.DEC)
local f_ping_supported_op = ProtoField.uint16("hotrod.ping.supported_op", "Supported Opcode", base.HEX)

-- Bulk Operation Fields
local f_entry_count = ProtoField.uint64("hotrod.entry_count", "Entry Count", base.DEC)
local f_key_count = ProtoField.uint64("hotrod.key_count", "Key Count", base.DEC)
local f_bulk_more = ProtoField.uint8("hotrod.bulk.more", "More Entries", base.DEC)

-- Utility Operation Fields
local f_stat_count = ProtoField.uint64("hotrod.stats.count", "Stat Count", base.DEC)
local f_stat_name = ProtoField.string("hotrod.stats.name", "Stat Name")
local f_stat_value = ProtoField.string("hotrod.stats.value", "Stat Value")
local f_cache_size = ProtoField.uint64("hotrod.size", "Cache Size", base.DEC)

-- Iteration Operation Fields
local f_iteration_id = ProtoField.bytes("hotrod.iteration.id", "Iteration ID (hex)")
local f_iteration_id_string = ProtoField.string("hotrod.iteration.id.string", "Iteration ID (string)")
local f_iteration_id_length = ProtoField.uint64("hotrod.iteration.id.length", "Iteration ID Length", base.DEC)
local f_iteration_segments_size = ProtoField.int64("hotrod.iteration.segments_size", "Segments Size", base.DEC)
local f_iteration_segment_id = ProtoField.uint32("hotrod.iteration.segment_id", "Segment ID", base.DEC)
local f_iteration_filter_size = ProtoField.int64("hotrod.iteration.filter_size", "Filter Size", base.DEC)
local f_iteration_filter = ProtoField.string("hotrod.iteration.filter", "Filter Converter")
local f_iteration_param_count = ProtoField.uint8("hotrod.iteration.param_count", "Parameter Count", base.DEC)
local f_iteration_param = ProtoField.bytes("hotrod.iteration.param", "Parameter")
local f_iteration_batch_size = ProtoField.uint64("hotrod.iteration.batch_size", "Batch Size", base.DEC)
local f_iteration_metadata_flag = ProtoField.uint8("hotrod.iteration.metadata_flag", "Include Metadata", base.DEC)
local f_iteration_finished_segments_size = ProtoField.uint64("hotrod.iteration.finished_segments_size", "Finished Segments Size", base.DEC)
local f_iteration_finished_segment = ProtoField.uint32("hotrod.iteration.finished_segment", "Finished Segment", base.DEC)
local f_iteration_num_projections = ProtoField.uint64("hotrod.iteration.num_projections", "Number of Value Projections", base.DEC)
local f_iteration_metadata_present = ProtoField.uint8("hotrod.iteration.metadata_present", "Metadata Present", base.DEC)
local f_iteration_expiration_flag = ProtoField.uint8("hotrod.iteration.expiration_flag", "Expiration Flag", base.HEX)

-- Counter Operation Fields
local f_counter_name = ProtoField.string("hotrod.counter.name", "Counter Name")
local f_counter_name_length = ProtoField.uint64("hotrod.counter.name.length", "Counter Name Length", base.DEC)
local f_counter_config_flags = ProtoField.uint8("hotrod.counter.config.flags", "Configuration Flags", base.HEX)
local f_counter_concurrency = ProtoField.uint64("hotrod.counter.config.concurrency", "Concurrency Level", base.DEC)
local f_counter_lower_bound = ProtoField.int64("hotrod.counter.config.lower_bound", "Lower Bound", base.DEC)
local f_counter_upper_bound = ProtoField.int64("hotrod.counter.config.upper_bound", "Upper Bound", base.DEC)
local f_counter_initial_value = ProtoField.int64("hotrod.counter.config.initial_value", "Initial Value", base.DEC)
local f_counter_value = ProtoField.int64("hotrod.counter.value", "Counter Value", base.DEC)
local f_counter_delta = ProtoField.int64("hotrod.counter.delta", "Delta", base.DEC)
local f_counter_expect = ProtoField.int64("hotrod.counter.expect", "Expected Value", base.DEC)
local f_counter_update = ProtoField.int64("hotrod.counter.update", "Update Value", base.DEC)

-- Multimap Operation Fields
local f_multimap_support_duplicates = ProtoField.uint8("hotrod.multimap.support_duplicates", "Support Duplicates", base.DEC)
local f_multimap_value_count = ProtoField.uint64("hotrod.multimap.value_count", "Value Count", base.DEC)
local f_multimap_result = ProtoField.uint8("hotrod.multimap.result", "Result", base.DEC)

-- Stream Operation Fields
local f_stream_id = ProtoField.int32("hotrod.stream.id", "Stream ID", base.DEC)
local f_stream_batch_size = ProtoField.uint64("hotrod.stream.batch_size", "Batch Size", base.DEC)
local f_stream_complete = ProtoField.uint8("hotrod.stream.complete", "Complete", base.DEC)
local f_stream_condition_version = ProtoField.int64("hotrod.stream.condition_version", "Condition Version", base.DEC)
local f_stream_chunk = ProtoField.bytes("hotrod.stream.chunk", "Data Chunk")

-- Transaction Operation Fields
local f_tx_xid_format = ProtoField.uint64("hotrod.tx.xid.format_id", "XID Format ID", base.DEC)
local f_tx_xid_global_length = ProtoField.uint8("hotrod.tx.xid.global_length", "Global TX ID Length", base.DEC)
local f_tx_xid_global = ProtoField.bytes("hotrod.tx.xid.global", "Global TX ID")
local f_tx_xid_branch_length = ProtoField.uint8("hotrod.tx.xid.branch_length", "Branch Qualifier Length", base.DEC)
local f_tx_xid_branch = ProtoField.bytes("hotrod.tx.xid.branch", "Branch Qualifier")
local f_tx_one_phase = ProtoField.uint8("hotrod.tx.one_phase", "One Phase Commit", base.DEC)
local f_tx_recoverable = ProtoField.uint8("hotrod.tx.recoverable", "Recoverable", base.DEC)
local f_tx_timeout = ProtoField.int64("hotrod.tx.timeout", "Timeout", base.DEC)
local f_tx_num_keys = ProtoField.uint64("hotrod.tx.num_keys", "Number of Keys", base.DEC)
local f_tx_control_byte = ProtoField.uint8("hotrod.tx.control_byte", "Control Byte", base.HEX)
local f_tx_num_xids = ProtoField.uint64("hotrod.tx.num_xids", "Number of XIDs", base.DEC)

-- Event Fields
local f_event_listener_id = ProtoField.bytes("hotrod.event.listener_id", "Listener ID (hex)")
local f_event_listener_id_string = ProtoField.string("hotrod.event.listener_id.string", "Listener ID (string)")
local f_event_listener_id_length = ProtoField.uint64("hotrod.event.listener_id.length", "Listener ID Length", base.DEC)
local f_event_custom_marker = ProtoField.uint8("hotrod.event.custom_marker", "Custom Marker", base.DEC)
local f_event_command_retried = ProtoField.uint8("hotrod.event.command_retried", "Command Retried", base.DEC)
local f_event_custom_data = ProtoField.bytes("hotrod.event.custom_data", "Custom Data")

-- Error Response Fields
local f_error_message = ProtoField.string("hotrod.error.message", "Error Message")
local f_error_message_length = ProtoField.uint64("hotrod.error.message.length", "Error Message Length", base.DEC)

-- Query Operation Fields
local f_query_payload = ProtoField.bytes("hotrod.query.payload", "Query Payload (hex)")
local f_query_payload_length = ProtoField.uint64("hotrod.query.payload.length", "Query Payload Length", base.DEC)
local f_query_response_payload = ProtoField.bytes("hotrod.query.response_payload", "Response Payload (hex)")
local f_query_response_payload_length = ProtoField.uint64("hotrod.query.response_payload.length", "Response Payload Length", base.DEC)

-- Exec Operation Fields
local f_exec_script_name = ProtoField.string("hotrod.exec.script_name", "Script Name")
local f_exec_script_name_length = ProtoField.uint64("hotrod.exec.script_name.length", "Script Name Length", base.DEC)
local f_exec_param_count = ProtoField.uint64("hotrod.exec.param_count", "Parameter Count", base.DEC)
local f_exec_param_name = ProtoField.string("hotrod.exec.param.name", "Parameter Name")
local f_exec_param_name_length = ProtoField.uint64("hotrod.exec.param.name.length", "Parameter Name Length", base.DEC)
local f_exec_param_value = ProtoField.bytes("hotrod.exec.param.value", "Parameter Value (hex)")
local f_exec_param_value_string = ProtoField.string("hotrod.exec.param.value.string", "Parameter Value (string)")
local f_exec_param_value_length = ProtoField.uint64("hotrod.exec.param.value.length", "Parameter Value Length", base.DEC)
local f_exec_result = ProtoField.bytes("hotrod.exec.result", "Result (hex)")
local f_exec_result_string = ProtoField.string("hotrod.exec.result.string", "Result (string)")
local f_exec_result_length = ProtoField.uint64("hotrod.exec.result.length", "Result Length", base.DEC)

-- Authentication Operation Fields
local f_auth_mech_count = ProtoField.uint64("hotrod.auth.mech_count", "Mechanism Count", base.DEC)
local f_auth_mech = ProtoField.string("hotrod.auth.mechanism", "SASL Mechanism")
local f_auth_mech_length = ProtoField.uint64("hotrod.auth.mechanism.length", "Mechanism Length", base.DEC)
local f_auth_response_data = ProtoField.bytes("hotrod.auth.response_data", "Response Data (hex)")
local f_auth_response_data_string = ProtoField.string("hotrod.auth.response_data.string", "Response Data (string)")
local f_auth_response_data_length = ProtoField.uint64("hotrod.auth.response_data.length", "Response Data Length", base.DEC)
local f_auth_completed = ProtoField.uint8("hotrod.auth.completed", "Authentication Completed", base.DEC)
local f_auth_challenge_data = ProtoField.bytes("hotrod.auth.challenge_data", "Challenge Data (hex)")
local f_auth_challenge_data_string = ProtoField.string("hotrod.auth.challenge_data.string", "Challenge Data (string)")
local f_auth_challenge_data_length = ProtoField.uint64("hotrod.auth.challenge_data.length", "Challenge Data Length", base.DEC)

-- Transaction Operation Fields (additional)
local f_tx_xa_return_code = ProtoField.int32("hotrod.tx.xa_return_code", "XA Return Code", base.DEC)

-- Client Listener Operation Fields
local f_listener_id = ProtoField.bytes("hotrod.listener.id", "Listener ID (hex)")
local f_listener_id_string = ProtoField.string("hotrod.listener.id.string", "Listener ID (string)")
local f_listener_id_length = ProtoField.uint64("hotrod.listener.id.length", "Listener ID Length", base.DEC)
local f_listener_include_state = ProtoField.uint8("hotrod.listener.include_state", "Include State", base.DEC)
local f_listener_filter_factory = ProtoField.string("hotrod.listener.filter_factory", "Filter Factory Name")
local f_listener_filter_factory_length = ProtoField.uint64("hotrod.listener.filter_factory.length", "Filter Factory Name Length", base.DEC)
local f_listener_converter_factory = ProtoField.string("hotrod.listener.converter_factory", "Converter Factory Name")
local f_listener_converter_factory_length = ProtoField.uint64("hotrod.listener.converter_factory.length", "Converter Factory Name Length", base.DEC)
local f_listener_use_raw_data = ProtoField.uint8("hotrod.listener.use_raw_data", "Use Raw Data", base.DEC)
local f_listener_event_interests = ProtoField.uint64("hotrod.listener.event_interests", "Event Type Interests", base.HEX)
local f_listener_param_count = ProtoField.uint8("hotrod.listener.param_count", "Parameter Count", base.DEC)
local f_listener_param = ProtoField.bytes("hotrod.listener.param", "Parameter (hex)")
local f_listener_param_string = ProtoField.string("hotrod.listener.param.string", "Parameter (string)")
local f_listener_param_length = ProtoField.uint64("hotrod.listener.param.length", "Parameter Length", base.DEC)
local f_bloom_filter_bit_size = ProtoField.uint64("hotrod.bloom.bit_size", "Bloom Filter Bit Size", base.DEC)
local f_bloom_filter_bits = ProtoField.bytes("hotrod.bloom.bits", "Bloom Filter Bits (hex)")
local f_bloom_filter_bits_length = ProtoField.uint64("hotrod.bloom.bits.length", "Bloom Filter Bits Length", base.DEC)

-- Counter Names Response Fields
local f_counter_names_count = ProtoField.uint64("hotrod.counter.names.count", "Counter Names Count", base.DEC)

-- Register all fields
hotrod_protocol.fields = {
    f_magic,
    f_req_header, f_resp_header,
    f_req_message_id, f_req_version, f_req_opcode, f_req_cache_name,
    f_req_flags, f_req_client_intelligence, f_req_topology_id,
    f_media_type_indicator, f_media_type_predefined_id, f_media_type_custom,
    f_media_type_param_count, f_media_type_param_key, f_media_type_param_value,
    f_other_param_count, f_other_param_key, f_other_param_value,
    f_resp_message_id, f_resp_opcode, f_resp_status, f_resp_topology_marker,
    f_resp_in_frame, f_req_in_frame,
    f_topology_id, f_topology_num_servers, f_topology_server_host, f_topology_server_port,
    f_topology_hash_function, f_topology_num_segments, f_topology_segment_owners, f_topology_owner_index,
    f_key, f_key_string, f_key_length, f_value, f_value_string, f_value_length, f_string_length, f_bytes_length,
    f_time_units, f_lifespan, f_max_idle,
    f_metadata_flag, f_metadata_created, f_metadata_lifespan, f_metadata_last_used,
    f_metadata_max_idle, f_metadata_version,
    f_ping_key_type, f_ping_value_type, f_ping_server_version, f_ping_op_count, f_ping_supported_op,
    f_entry_count, f_key_count, f_bulk_more,
    f_stat_count, f_stat_name, f_stat_value, f_cache_size,
    f_iteration_id, f_iteration_id_string, f_iteration_id_length,
    f_iteration_segments_size, f_iteration_segment_id,
    f_iteration_filter_size, f_iteration_filter, f_iteration_param_count, f_iteration_param,
    f_iteration_batch_size, f_iteration_metadata_flag,
    f_iteration_finished_segments_size, f_iteration_finished_segment,
    f_iteration_num_projections, f_iteration_metadata_present, f_iteration_expiration_flag,
    f_counter_name, f_counter_name_length, f_counter_config_flags,
    f_counter_concurrency, f_counter_lower_bound, f_counter_upper_bound, f_counter_initial_value,
    f_counter_value, f_counter_delta, f_counter_expect, f_counter_update,
    f_multimap_support_duplicates, f_multimap_value_count, f_multimap_result,
    f_stream_id, f_stream_batch_size, f_stream_complete, f_stream_condition_version, f_stream_chunk,
    f_tx_xid_format, f_tx_xid_global_length, f_tx_xid_global, f_tx_xid_branch_length, f_tx_xid_branch,
    f_tx_one_phase, f_tx_recoverable, f_tx_timeout, f_tx_num_keys, f_tx_control_byte, f_tx_num_xids,
    f_event_listener_id, f_event_listener_id_string, f_event_listener_id_length,
    f_event_custom_marker, f_event_command_retried, f_event_custom_data,
    f_error_message, f_error_message_length,
    f_query_payload, f_query_payload_length, f_query_response_payload, f_query_response_payload_length,
    f_exec_script_name, f_exec_script_name_length, f_exec_param_count,
    f_exec_param_name, f_exec_param_name_length, f_exec_param_value, f_exec_param_value_string, f_exec_param_value_length,
    f_exec_result, f_exec_result_string, f_exec_result_length,
    f_auth_mech_count, f_auth_mech, f_auth_mech_length,
    f_auth_response_data, f_auth_response_data_string, f_auth_response_data_length,
    f_auth_completed, f_auth_challenge_data, f_auth_challenge_data_string, f_auth_challenge_data_length,
    f_tx_xa_return_code,
    f_listener_id, f_listener_id_string, f_listener_id_length,
    f_listener_include_state, f_listener_filter_factory, f_listener_filter_factory_length,
    f_listener_converter_factory, f_listener_converter_factory_length,
    f_listener_use_raw_data, f_listener_event_interests,
    f_listener_param_count, f_listener_param, f_listener_param_string, f_listener_param_length,
    f_bloom_filter_bit_size, f_bloom_filter_bits, f_bloom_filter_bits_length,
    f_counter_names_count
}

-- ============================================================================
-- Opcode Mappings (Protocol 4.0+)
-- ============================================================================

local request_opcodes = {
    [0x01] = "PUT",
    [0x03] = "GET",
    [0x05] = "PUT_IF_ABSENT",
    [0x07] = "REPLACE",
    [0x09] = "REPLACE_IF_UNMODIFIED",
    [0x0B] = "REMOVE",
    [0x0D] = "REMOVE_IF_UNMODIFIED",
    [0x0F] = "CONTAINS_KEY",
    [0x11] = "GET_WITH_VERSION",
    [0x13] = "CLEAR",
    [0x15] = "STATS",
    [0x17] = "PING",
    [0x19] = "BULK_GET",
    [0x1B] = "GET_WITH_METADATA",
    [0x1D] = "BULK_GET_KEYS",
    [0x1F] = "QUERY",
    [0x21] = "AUTH_MECH_LIST",
    [0x23] = "AUTH",
    [0x25] = "ADD_CLIENT_LISTENER",
    [0x27] = "REMOVE_CLIENT_LISTENER",
    [0x29] = "SIZE",
    [0x2B] = "EXEC",
    [0x2D] = "PUT_ALL",
    [0x2F] = "GET_ALL",
    [0x31] = "ITERATION_START",
    [0x33] = "ITERATION_NEXT",
    [0x35] = "ITERATION_END",
    [0x3D] = "COMMIT",
    [0x3F] = "ROLLBACK",
    [0x41] = "ADD_BLOOM_FILTER_LISTENER",
    [0x43] = "UPDATE_BLOOM_FILTER",
    [0x4B] = "COUNTER_CREATE",
    [0x4D] = "COUNTER_GET_CONFIGURATION",
    [0x4F] = "COUNTER_IS_DEFINED",
    [0x52] = "COUNTER_ADD_AND_GET",
    [0x54] = "COUNTER_RESET",
    [0x56] = "COUNTER_GET_VALUE",
    [0x58] = "COUNTER_CAS",
    [0x5A] = "COUNTER_ADD_LISTENER",
    [0x5C] = "COUNTER_REMOVE_LISTENER",
    [0x5E] = "COUNTER_REMOVE",
    [0x67] = "MULTIMAP_GET",
    [0x69] = "MULTIMAP_GET_WITH_METADATA",
    [0x6B] = "MULTIMAP_PUT",
    [0x6D] = "MULTIMAP_REMOVE_KEY",
    [0x6F] = "MULTIMAP_REMOVE_ENTRY",
    [0x71] = "MULTIMAP_SIZE",
    [0x73] = "MULTIMAP_CONTAINS_ENTRY",
    [0x75] = "MULTIMAP_CONTAINS_KEY",
    [0x77] = "MULTIMAP_CONTAINS_VALUE",
    [0x79] = "FORGET_TX",
    [0x7B] = "FETCH_IN_DOUBT_TX",
    [0x7D] = "PREPARE_V2",
    [0x7F] = "COUNTER_GET_AND_SET",
    [0xE5] = "GET_STREAM_END",
    [0xE7] = "GET_STREAM_NEXT",
    [0xE9] = "GET_STREAM_START",
    [0xEB] = "PUT_STREAM_END",
    [0xED] = "PUT_STREAM_NEXT",
    [0xEF] = "PUT_STREAM_START"
}

local response_opcodes = {
    [0x02] = "PUT",
    [0x04] = "GET",
    [0x06] = "PUT_IF_ABSENT",
    [0x08] = "REPLACE",
    [0x0A] = "REPLACE_IF_UNMODIFIED",
    [0x0C] = "REMOVE",
    [0x0E] = "REMOVE_IF_UNMODIFIED",
    [0x10] = "CONTAINS_KEY",
    [0x12] = "GET_WITH_VERSION",
    [0x14] = "CLEAR",
    [0x16] = "STATS",
    [0x18] = "PING",
    [0x1A] = "BULK_GET",
    [0x1C] = "GET_WITH_METADATA",
    [0x1E] = "BULK_GET_KEYS",
    [0x20] = "QUERY",
    [0x22] = "AUTH_MECH_LIST",
    [0x24] = "AUTH",
    [0x26] = "ADD_CLIENT_LISTENER",
    [0x28] = "REMOVE_CLIENT_LISTENER",
    [0x2A] = "SIZE",
    [0x2C] = "EXEC",
    [0x2E] = "PUT_ALL",
    [0x30] = "GET_ALL",
    [0x32] = "ITERATION_START",
    [0x34] = "ITERATION_NEXT",
    [0x36] = "ITERATION_END",
    [0x3E] = "COMMIT",
    [0x40] = "ROLLBACK",
    [0x42] = "ADD_BLOOM_FILTER_LISTENER",
    [0x44] = "UPDATE_BLOOM_FILTER",
    [0x4C] = "COUNTER_CREATE",
    [0x4E] = "COUNTER_GET_CONFIGURATION",
    [0x50] = "ERROR",
    [0x51] = "COUNTER_IS_DEFINED",
    [0x53] = "COUNTER_ADD_AND_GET",
    [0x55] = "COUNTER_RESET",
    [0x57] = "COUNTER_GET_VALUE",
    [0x59] = "COUNTER_CAS",
    [0x5B] = "COUNTER_ADD_LISTENER",
    [0x5D] = "COUNTER_REMOVE_LISTENER",
    [0x5F] = "COUNTER_REMOVE",
    [0x60] = "CACHE_ENTRY_CREATED_EVENT",
    [0x61] = "CACHE_ENTRY_MODIFIED_EVENT",
    [0x62] = "CACHE_ENTRY_REMOVED_EVENT",
    [0x63] = "CACHE_ENTRY_EXPIRED_EVENT",
    [0x65] = "COUNTER_GET_NAMES",
    [0x66] = "COUNTER_EVENT",
    [0x68] = "MULTIMAP_GET",
    [0x6A] = "MULTIMAP_GET_WITH_METADATA",
    [0x6C] = "MULTIMAP_PUT",
    [0x6E] = "MULTIMAP_REMOVE_KEY",
    [0x70] = "MULTIMAP_REMOVE_ENTRY",
    [0x72] = "MULTIMAP_SIZE",
    [0x74] = "MULTIMAP_CONTAINS_ENTRY",
    [0x76] = "MULTIMAP_CONTAINS_KEY",
    [0x78] = "MULTIMAP_CONTAINS_VALUE",
    [0x7A] = "FORGET_TX",
    [0x7C] = "FETCH_TX_RECOVERY",
    [0x7E] = "PREPARE_V2",
    [0x80] = "COUNTER_GET_AND_SET",
    [0xE4] = "GET_STREAM_END",
    [0xE6] = "GET_STREAM_NEXT",
    [0xE8] = "GET_STREAM_START",
    [0xEA] = "PUT_STREAM_END",
    [0xEC] = "PUT_STREAM_NEXT",
    [0xEE] = "PUT_STREAM_START"
}

local status_codes = {
    [0x00] = "Success",
    [0x01] = "Not Executed",
    [0x02] = "Key Does Not Exist",
    [0x03] = "Success With Previous",
    [0x04] = "Not Executed With Previous",
    [0x81] = "Invalid Magic or Message ID",
    [0x82] = "Unknown Command",
    [0x83] = "Unknown Version",
    [0x84] = "Parse Error",
    [0x85] = "Server Error",
    [0x86] = "Command Timed Out",
    [0x87] = "Node Suspected",
    [0x88] = "Illegal Lifecycle State"
}

local client_intelligence = {
    [0x01] = "Basic",
    [0x02] = "Topology Aware",
    [0x03] = "Hash Distribution Aware"
}

-- Predefined Media Type IDs (from MediaTypeIds.java)
local predefined_media_types = {
    [1] = "application/x-java-object",
    [2] = "application/json",
    [3] = "application/octet-stream",
    [4] = "application/pdf",
    [5] = "application/rtf",
    [6] = "application/zip",
    [7] = "image/gif",
    [8] = "image/jpeg",
    [9] = "image/png",
    [10] = "text/css",
    [11] = "text/csv",
    [12] = "application/x-protostream",
    [13] = "text/plain",
    [14] = "text/html",
    [15] = "application/x-jboss-marshalling",
    [17] = "application/unknown"
}

-- Media type kind names
local media_type_kind_names = {
    [0x00] = "None",
    [0x01] = "Predefined",
    [0x02] = "Custom"
}

-- ============================================================================
-- Conversation Tracking for Request-Response Correlation
-- ============================================================================

-- Table to track request-response pairs by frame number
-- request_to_response[frame_number] = response_frame
-- response_to_request[frame_number] = request_frame
local request_to_response = {}
local response_to_request = {}

-- Temporary table to track in-flight requests by message_id during first pass
-- pending_requests[message_id] = request_frame_number
local pending_requests = {}

-- Protocol initialization function - called when protocol is loaded/reset
function hotrod_protocol.init()
    -- Clear conversation tracking tables to prevent memory leaks on reload
    -- Must clear in-place since these are module-level locals
    for k in pairs(request_to_response) do
        request_to_response[k] = nil
    end
    for k in pairs(response_to_request) do
        response_to_request[k] = nil
    end
    for k in pairs(pending_requests) do
        pending_requests[k] = nil
    end
end

-- ============================================================================
-- Topology Change Parser (Intelligence 0x03)
-- ============================================================================

function parse_topology_change(tvb, offset, tree)
    local start_offset = offset

    local topo_tree = tree:add(hotrod_protocol, tvb(offset, 1)):set_text("Topology Change")

    -- Topology ID (vint)
    local topology_id, topo_id_len = read_vint(tvb, offset)
    if topology_id == nil then
        return nil, 0
    end
    local topo_id_item = topo_tree:add(f_topology_id, tvb(offset, topo_id_len))
    topo_id_item:append_text(string.format(" (%d)", topology_id))
    offset = offset + topo_id_len

    -- Number of servers (vint)
    local num_servers, num_servers_len = read_vint(tvb, offset)
    if num_servers == nil then
        return nil, 0
    end
    local num_servers_item = topo_tree:add(f_topology_num_servers, tvb(offset, num_servers_len))
    num_servers_item:append_text(string.format(" (%d)", num_servers))
    offset = offset + num_servers_len

    -- Server list
    for i = 1, num_servers do
        -- Server host (lp_string)
        local host, host_len = read_lp_string(tvb, offset)
        if host == nil then
            break
        end

        local server_item = topo_tree:add(tvb(offset, 1), string.format("Server %d", i - 1))
        server_item:add(f_topology_server_host, tvb(offset, host_len), host)
        offset = offset + host_len

        -- Server port (u2, big-endian)
        if offset + 2 > tvb:len() then
            break
        end
        local port = tvb(offset, 2):uint()
        server_item:add(f_topology_server_port, tvb(offset, 2), port)
        server_item:set_text(string.format("Server %d: %s:%d", i - 1, host, port))
        server_item:set_len(host_len + 2)
        offset = offset + 2
    end

    -- Hash function version (u1)
    if offset >= tvb:len() then
        topo_tree:set_len(offset - start_offset)
        return topo_tree, offset - start_offset
    end
    local hash_version = tvb(offset, 1):uint()
    local hash_names = {
        [0x01] = "MurmurHash2",
        [0x02] = "MurmurHash3",
        [0x03] = "MurmurHash3 with segments"
    }
    local hash_name = hash_names[hash_version] or "Unknown"
    topo_tree:add(f_topology_hash_function, tvb(offset, 1)):append_text(string.format(" (%s)", hash_name))
    offset = offset + 1

    -- Number of segments (vint)
    local num_segments, num_segments_len = read_vint(tvb, offset)
    if num_segments == nil then
        topo_tree:set_len(offset - start_offset)
        return topo_tree, offset - start_offset
    end
    local num_segments_item = topo_tree:add(f_topology_num_segments, tvb(offset, num_segments_len))
    num_segments_item:append_text(string.format(" (%d)", num_segments))
    offset = offset + num_segments_len

    -- Segments (showing only first few to avoid huge trees)
    local max_segments_to_show = 10
    for i = 1, math.min(num_segments, max_segments_to_show) do
        -- Number of owners for this segment (u1)
        if offset >= tvb:len() then
            break
        end
        local num_owners = tvb(offset, 1):uint()
        local segment_item = topo_tree:add(tvb(offset, 1), string.format("Segment %d", i - 1))
        segment_item:add(f_topology_segment_owners, tvb(offset, 1), num_owners)
        offset = offset + 1

        -- Owner indices (u1 each)
        for j = 1, num_owners do
            if offset >= tvb:len() then
                break
            end
            local owner_idx = tvb(offset, 1):uint()
            segment_item:add(f_topology_owner_index, tvb(offset, 1), owner_idx)
            offset = offset + 1
        end
        segment_item:set_len(1 + num_owners)
    end

    -- Skip remaining segments if there are more than max_segments_to_show
    if num_segments > max_segments_to_show then
        for i = max_segments_to_show + 1, num_segments do
            if offset >= tvb:len() then
                break
            end
            local num_owners = tvb(offset, 1):uint()
            offset = offset + 1 + num_owners
        end
        topo_tree:add(tvb(offset - 1, 1), string.format("... (%d more segments not shown)", num_segments - max_segments_to_show))
    end

    topo_tree:set_len(offset - start_offset)
    return topo_tree, offset - start_offset
end

-- ============================================================================
-- MediaType Parser (Protocol 2.8+)
-- ============================================================================

-- MediaType encoding:
--   0x00 = none (no media type)
--   0x01 = predefined (has predefined_id + optional params)
--   0x02 = custom (has custom_string + optional params)
function parse_media_type(tvb, offset, tree, label)
    local start_offset = offset

    if offset >= tvb:len() then
        return nil, 0
    end

    -- Create a simple text tree item (not using ProtoField.none)
    local media_tree = tree:add(hotrod_protocol, tvb(offset, 1)):set_text(label)

    -- Type indicator (u1)
    local type_indicator = tvb(offset, 1):uint()
    local type_name = media_type_kind_names[type_indicator]
    if type_name then
        media_tree:add(f_media_type_indicator, tvb(offset, 1)):append_text(" (" .. type_name .. ")")
    else
        media_tree:add(f_media_type_indicator, tvb(offset, 1))
    end
    offset = offset + 1

    -- If type is none (0x00), we're done
    if type_indicator == 0x00 then
        media_tree:set_len(offset - start_offset)
        return media_tree, offset - start_offset
    end

    -- Predefined type (0x01) - has predefined_id
    if type_indicator == 0x01 then
        local pred_id, pred_len = read_vint(tvb, offset)
        if pred_id == nil then
            return nil, 0
        end
        -- For vint, add bytes and append decoded text with media type name
        local pred_item = media_tree:add(f_media_type_predefined_id, tvb(offset, pred_len))
        local media_name = predefined_media_types[pred_id]
        if media_name then
            pred_item:append_text(" (" .. media_name .. ")")
        end
        offset = offset + pred_len

    -- Custom type (0x02) - has custom string
    elseif type_indicator == 0x02 then
        local custom_str, custom_len = read_lp_string(tvb, offset)
        if custom_str == nil then
            return nil, 0
        end
        media_tree:add(f_media_type_custom, tvb(offset, custom_len), custom_str)
        offset = offset + custom_len
    else
        -- Unknown type indicator
        media_tree:set_len(offset - start_offset)
        return media_tree, offset - start_offset
    end

    -- Both predefined and custom can have parameters
    if type_indicator == 0x01 or type_indicator == 0x02 then
        local param_count, param_count_len = read_vint(tvb, offset)
        if param_count == nil then
            return nil, 0
        end

        -- For vint, add bytes and append decoded text
        local param_count_item = media_tree:add(f_media_type_param_count, tvb(offset, param_count_len))
        param_count_item:append_text(string.format(" (%d)", param_count))
        offset = offset + param_count_len

        -- Read parameter key-value pairs
        for i = 1, param_count do
            -- Parameter key (lp_string)
            local param_key, key_len = read_lp_string(tvb, offset)
            if param_key == nil then
                break
            end

            local param_item = media_tree:add(tvb(offset, 1), string.format("Parameter %d", i - 1))
            param_item:add(f_media_type_param_key, tvb(offset, key_len), param_key)
            offset = offset + key_len

            -- Parameter value (lp_string)
            local param_value, value_len = read_lp_string(tvb, offset)
            if param_value == nil then
                break
            end
            param_item:add(f_media_type_param_value, tvb(offset, value_len), param_value)
            param_item:set_len(key_len + value_len)
            offset = offset + value_len
        end
    end

    media_tree:set_len(offset - start_offset)
    return media_tree, offset - start_offset
end

-- ============================================================================
-- Entry Metadata Parser (Protocol 4.0+)
-- ============================================================================

function parse_entry_metadata(tvb, offset, tree)
    local start_offset = offset

    if offset >= tvb:len() then
        return nil, 0
    end

    local metadata_tree = tree:add(hotrod_protocol, tvb(offset, 1)):set_text("Entry Metadata")

    -- Metadata flag (u1)
    local flag = tvb(offset, 1):uint()
    metadata_tree:add(f_metadata_flag, tvb(offset, 1))
    offset = offset + 1

    local infinite_lifespan = (bit.band(flag, 0x01) ~= 0)
    local infinite_maxidle = (bit.band(flag, 0x02) ~= 0)

    -- Created (s8) - only if not infinite lifespan
    if not infinite_lifespan then
        if offset + 8 > tvb:len() then
            return nil, 0
        end
        metadata_tree:add(f_metadata_created, tvb(offset, 8))
        offset = offset + 8

        -- Lifespan (vint)
        local lifespan, lifespan_len = read_vint(tvb, offset)
        if lifespan == nil then
            return nil, 0
        end
        local lifespan_item = metadata_tree:add(f_metadata_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Last Used (s8) - only if not infinite maxidle
    if not infinite_maxidle then
        if offset + 8 > tvb:len() then
            return nil, 0
        end
        metadata_tree:add(f_metadata_last_used, tvb(offset, 8))
        offset = offset + 8

        -- Max Idle (vint)
        local max_idle, max_idle_len = read_vint(tvb, offset)
        if max_idle == nil then
            return nil, 0
        end
        local max_idle_item = metadata_tree:add(f_metadata_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Entry Version (s8)
    if offset + 8 > tvb:len() then
        return nil, 0
    end
    metadata_tree:add(f_metadata_version, tvb(offset, 8))
    offset = offset + 8

    metadata_tree:set_len(offset - start_offset)
    return metadata_tree, offset - start_offset
end

-- ============================================================================
-- Operation Body Parsers
-- ============================================================================

-- GET Request (0x03)
function parse_get_request(tvb, offset, tree)
    return add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")
end

-- GET Response (0x04)
function parse_get_response(tvb, offset, tree, status)
    if status == 0x00 then  -- Success
        return add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
    end
    return offset
end

-- PUT Request (0x01)
function parse_put_request(tvb, offset, tree)
    -- Key (lp_bytes with length and string representation)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Time Units (u1)
    if offset >= tvb:len() then
        return offset
    end
    local time_units = tvb(offset, 1):uint()
    local lifespan_unit = bit.rshift(time_units, 4)
    local maxidle_unit = bit.band(time_units, 0x0F)

    local time_unit_names = {
        [0x00] = "SECONDS", [0x01] = "MILLISECONDS", [0x02] = "NANOSECONDS",
        [0x03] = "MICROSECONDS", [0x04] = "MINUTES", [0x05] = "HOURS",
        [0x06] = "DAYS", [0x07] = "DEFAULT", [0x08] = "INFINITE"
    }

    tree:add(f_time_units, tvb(offset, 1)):append_text(
        string.format(" (Lifespan: %s, MaxIdle: %s)",
            time_unit_names[lifespan_unit] or "UNKNOWN",
            time_unit_names[maxidle_unit] or "UNKNOWN"))
    offset = offset + 1

    -- Lifespan (vlong) - only if not DEFAULT or INFINITE
    if lifespan_unit < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan == nil then
            return offset
        end
        local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Max Idle (vlong) - only if not DEFAULT or INFINITE
    if maxidle_unit < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle == nil then
            return offset
        end
        local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Value (lp_bytes with length and string representation)
    return add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
end

-- PUT Response (0x02)
function parse_put_response(tvb, offset, tree, status, version)
    -- Only has body if status indicates previous value
    if status == 0x03 or status == 0x04 then  -- Success/Not Executed With Previous
        -- Protocol 4.0+ includes metadata
        if version >= 40 then
            local metadata, metadata_len = parse_entry_metadata(tvb, offset, tree)
            if metadata == nil then
                return offset
            end
            offset = offset + metadata_len
        end

        -- Value (lp_bytes with length and string representation)
        return add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
    end
    return offset
end

-- REMOVE Request (0x0B) - same as GET
function parse_remove_request(tvb, offset, tree)
    return add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")
end

-- REMOVE Response (0x0C) - same as PUT response (previous value with metadata in 4.0+)
function parse_remove_response(tvb, offset, tree, status, version)
    -- Only has body if status indicates previous value
    if status == 0x03 or status == 0x04 then  -- Success/Not Executed With Previous
        -- Protocol 4.0+ includes metadata
        if version >= 40 then
            local metadata, metadata_len = parse_entry_metadata(tvb, offset, tree)
            if metadata == nil then
                return offset
            end
            offset = offset + metadata_len
        end

        -- Value (lp_bytes with length and string representation)
        return add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
    end
    return offset
end

-- REPLACE Request (0x07) - same as PUT
function parse_replace_request(tvb, offset, tree)
    return parse_put_request(tvb, offset, tree)
end

-- REPLACE Response (0x08) - same as PUT response
function parse_replace_response(tvb, offset, tree, status, version)
    return parse_put_response(tvb, offset, tree, status, version)
end

-- PUT_IF_ABSENT Request (0x05) - same as PUT
function parse_put_if_absent_request(tvb, offset, tree)
    return parse_put_request(tvb, offset, tree)
end

-- PUT_IF_ABSENT Response (0x06) - same as PUT response
function parse_put_if_absent_response(tvb, offset, tree, status, version)
    return parse_put_response(tvb, offset, tree, status, version)
end

-- CONTAINS_KEY Request (0x0F) - same as GET
function parse_contains_key_request(tvb, offset, tree)
    return add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")
end

-- CONTAINS_KEY Response (0x10) - no body, status indicates if key exists
function parse_contains_key_response(tvb, offset, tree, status)
    -- No body - status tells us if key exists
    -- 0x00 = key exists, 0x02 = key does not exist
    return offset
end

-- GET_WITH_METADATA Request (0x1B) - same as GET
function parse_get_with_metadata_request(tvb, offset, tree)
    return add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")
end

-- GET_WITH_METADATA Response (0x1C) - always includes metadata
function parse_get_with_metadata_response(tvb, offset, tree, status)
    if status == 0x00 then  -- Success
        -- Parse metadata
        local metadata, metadata_len = parse_entry_metadata(tvb, offset, tree)
        if metadata == nil then
            return offset
        end
        offset = offset + metadata_len

        -- Value (lp_bytes with length and string representation)
        return add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
    end
    return offset
end

-- PUT_ALL Request (0x2D)
function parse_put_all_request(tvb, offset, tree)
    -- Time Units (u1)
    if offset >= tvb:len() then
        return offset
    end
    local time_units = tvb(offset, 1):uint()
    local lifespan_unit = bit.rshift(time_units, 4)
    local maxidle_unit = bit.band(time_units, 0x0F)

    local time_unit_names = {
        [0x00] = "SECONDS", [0x01] = "MILLISECONDS", [0x02] = "NANOSECONDS",
        [0x03] = "MICROSECONDS", [0x04] = "MINUTES", [0x05] = "HOURS",
        [0x06] = "DAYS", [0x07] = "DEFAULT", [0x08] = "INFINITE"
    }

    tree:add(f_time_units, tvb(offset, 1)):append_text(
        string.format(" (Lifespan: %s, MaxIdle: %s)",
            time_unit_names[lifespan_unit] or "UNKNOWN",
            time_unit_names[maxidle_unit] or "UNKNOWN"))
    offset = offset + 1

    -- Lifespan (vlong) - only if not DEFAULT or INFINITE
    if lifespan_unit < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan == nil then
            return offset
        end
        local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Max Idle (vlong) - only if not DEFAULT or INFINITE
    if maxidle_unit < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle == nil then
            return offset
        end
        local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Entry count (vint)
    local entry_count, count_len = read_vint(tvb, offset)
    if entry_count == nil then
        return offset
    end
    local count_item = tree:add(f_entry_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", entry_count))
    offset = offset + count_len

    -- Entries (key-value pairs)
    for i = 1, entry_count do
        local entry_item = tree:add(tvb(offset, 1), string.format("Entry %d", i - 1))

        -- Key
        local key_start = offset
        offset = add_lp_bytes_with_length(entry_item, tvb, offset, f_key, f_key_string, f_key_length, "Key")

        -- Value
        offset = add_lp_bytes_with_length(entry_item, tvb, offset, f_value, f_value_string, f_value_length, "Value")

        entry_item:set_len(offset - key_start)
    end

    return offset
end

-- PUT_ALL Response (0x2E) - no body, just status
function parse_put_all_response(tvb, offset, tree, status)
    -- No body - status tells success/failure
    return offset
end

-- GET_ALL Request (0x2F)
function parse_get_all_request(tvb, offset, tree)
    -- Key count (vint)
    local key_count, count_len = read_vint(tvb, offset)
    if key_count == nil then
        return offset
    end
    local count_item = tree:add(f_key_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", key_count))
    offset = offset + count_len

    -- Keys
    for i = 1, key_count do
        local key_item = tree:add(tvb(offset, 1), string.format("Key %d", i - 1))
        local key_start = offset
        offset = add_lp_bytes_with_length(key_item, tvb, offset, f_key, f_key_string, f_key_length, "Key")
        key_item:set_len(offset - key_start)
    end

    return offset
end

-- GET_ALL Response (0x30)
function parse_get_all_response(tvb, offset, tree, status)
    if status == 0x00 then  -- Success
        -- Entry count (vint)
        local entry_count, count_len = read_vint(tvb, offset)
        if entry_count == nil then
            return offset
        end
        local count_item = tree:add(f_entry_count, tvb(offset, count_len))
        count_item:append_text(string.format(" (%d)", entry_count))
        offset = offset + count_len

        -- Entries (key-value pairs)
        for i = 1, entry_count do
            local entry_item = tree:add(tvb(offset, 1), string.format("Entry %d", i - 1))

            -- Key
            local entry_start = offset
            offset = add_lp_bytes_with_length(entry_item, tvb, offset, f_key, f_key_string, f_key_length, "Key")

            -- Value
            offset = add_lp_bytes_with_length(entry_item, tvb, offset, f_value, f_value_string, f_value_length, "Value")

            entry_item:set_len(offset - entry_start)
        end
    end
    return offset
end

-- BULK_GET Request (0x19)
function parse_bulk_get_request(tvb, offset, tree)
    -- Entry count (vint) - 0 means return all entries
    local entry_count, count_len = read_vint(tvb, offset)
    if entry_count == nil then
        return offset
    end
    local count_item = tree:add(f_entry_count, tvb(offset, count_len))
    if entry_count == 0 then
        count_item:append_text(" (0 = return all entries)")
    else
        count_item:append_text(string.format(" (%d)", entry_count))
    end
    offset = offset + count_len

    return offset
end

-- BULK_GET Response (0x1A) - chunked format
function parse_bulk_get_response(tvb, offset, tree, status)
    if status == 0x00 then  -- Success
        local chunk_num = 0

        -- Read chunks until more == 0
        while offset < tvb:len() do
            local chunk_start = offset

            -- More marker (u1)
            local more = tvb(offset, 1):uint()
            local chunk_item = tree:add(tvb(offset, 1), string.format("Chunk %d", chunk_num))
            chunk_item:add(f_bulk_more, tvb(offset, 1)):append_text(
                more == 0 and " (last chunk)" or " (more chunks follow)")
            offset = offset + 1

            -- If more != 0, read the entry (lp_bytes for both key and value combined)
            if more ~= 0 then
                -- This is actually a single lp_bytes that contains the entry
                offset = add_lp_bytes_with_length(chunk_item, tvb, offset, f_value, f_value_string, f_value_length, "Entry Data")
            end

            chunk_item:set_len(offset - chunk_start)
            chunk_num = chunk_num + 1

            -- If more == 0, we're done
            if more == 0 then
                break
            end
        end
    end
    return offset
end

-- BULK_GET_KEYS Request (0x1D) - no body
function parse_bulk_get_keys_request(tvb, offset, tree)
    -- No body - retrieves all keys
    return offset
end

-- BULK_GET_KEYS Response (0x1E) - same chunked format as BULK_GET
function parse_bulk_get_keys_response(tvb, offset, tree, status)
    return parse_bulk_get_response(tvb, offset, tree, status)
end

-- PING Response (0x18) - Protocol 3.0+
function parse_ping_response(tvb, offset, tree)
    -- Key Media Type
    local key_media, key_media_len = parse_media_type(tvb, offset, tree, "Key Type")
    if key_media == nil then
        return offset
    end
    offset = offset + key_media_len

    -- Value Media Type
    local value_media, value_media_len = parse_media_type(tvb, offset, tree, "Value Type")
    if value_media == nil then
        return offset
    end
    offset = offset + value_media_len

    -- Server Version (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_ping_server_version, tvb(offset, 1)):append_text(
        string.format(" (Protocol %d.%d)",
            math.floor(tvb(offset, 1):uint() / 10),
            tvb(offset, 1):uint() % 10))
    offset = offset + 1

    -- Operation Count (vint)
    local op_count, op_count_len = read_vint(tvb, offset)
    if op_count == nil then
        return offset
    end
    local op_count_item = tree:add(f_ping_op_count, tvb(offset, op_count_len))
    op_count_item:append_text(string.format(" (%d)", op_count))
    offset = offset + op_count_len

    -- Supported Operations (u2 each)
    for i = 1, op_count do
        if offset + 2 > tvb:len() then
            break
        end
        local opcode = tvb(offset, 2):uint()
        local opcode_name = request_opcodes[opcode] or response_opcodes[opcode] or "UNKNOWN"
        tree:add(f_ping_supported_op, tvb(offset, 2)):append_text(
            string.format(" (%s)", opcode_name))
        offset = offset + 2
    end

    return offset
end

-- ============================================================================
-- Utility Operation Parsers (Batch 3)
-- ============================================================================

-- STATS Response (0x16) - No request body
function parse_stats_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Stat count (vint)
    local count, count_len = read_vint(tvb, offset)
    if count == nil then
        return offset
    end
    local count_item = tree:add(f_stat_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", count))
    offset = offset + count_len

    -- Array of name-value pairs (both are length-prefixed strings)
    for i = 1, count do
        -- Stat name (lp_string)
        local name, name_len = read_lp_string(tvb, offset)
        if name == nil then
            break
        end
        offset = add_lp_string_with_length(tree, tvb, offset, f_stat_name, f_string_length, "Stat Name")

        -- Stat value (lp_string)
        local value, value_len = read_lp_string(tvb, offset)
        if value == nil then
            break
        end
        offset = add_lp_string_with_length(tree, tvb, offset, f_stat_value, f_string_length, "Stat Value")
    end

    return offset
end

-- SIZE Response (0x2A) - No request body
function parse_size_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Cache size (vlong)
    local size, size_len = read_vlong(tvb, offset)
    if size == nil then
        return offset
    end
    local size_item = tree:add(f_cache_size, tvb(offset, size_len))
    size_item:append_text(string.format(" (%d)", size))
    offset = offset + size_len

    return offset
end

-- ============================================================================
-- Query Operation (0x1F request, 0x20 response)
-- ============================================================================

-- QUERY Request (0x1F)
function parse_query_request(tvb, offset, tree)
    -- Query payload (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_query_payload, nil,
        f_query_payload_length, "Query Payload")
    return offset
end

-- QUERY Response (0x20)
function parse_query_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Response payload (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_query_response_payload, nil,
        f_query_response_payload_length, "Response Payload")
    return offset
end

-- ============================================================================
-- Exec Operation (0x2B request, 0x2C response)
-- ============================================================================

-- EXEC Request (0x2B)
function parse_exec_request(tvb, offset, tree)
    -- Script name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_exec_script_name,
        f_exec_script_name_length, "Script Name")

    -- Parameter count (vint)
    local param_count, count_len = read_vint(tvb, offset)
    if param_count == nil then
        return offset
    end
    local count_item = tree:add(f_exec_param_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", param_count))
    offset = offset + count_len

    -- Parameters (array of name-value pairs)
    for i = 1, param_count do
        local param_tree = tree:add(tvb(offset, 0), string.format("Parameter %d", i))

        -- Parameter name (lp_string)
        local name_start = offset
        offset = add_lp_string_with_length(param_tree, tvb, offset, f_exec_param_name,
            f_exec_param_name_length, "Name")

        -- Parameter value (lp_bytes + string)
        local value_start = offset
        offset = add_lp_bytes_with_length(param_tree, tvb, offset, f_exec_param_value, f_exec_param_value_string,
            f_exec_param_value_length, "Value")

        -- Update param_tree length
        param_tree:set_len(offset - name_start)
    end

    return offset
end

-- EXEC Response (0x2C)
function parse_exec_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Result (lp_bytes + string)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_exec_result, f_exec_result_string,
        f_exec_result_length, "Result")
    return offset
end

-- ============================================================================
-- Error Response (0x50)
-- ============================================================================

-- ERROR Response (0x50)
-- Contains error message for all error status codes
function parse_error_response(tvb, offset, tree)
    -- Error message (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_error_message,
        f_error_message_length, "Error Message")
    return offset
end

-- ============================================================================
-- Conditional Operations
-- ============================================================================

-- REPLACE_IF_UNMODIFIED Request (0x09)
function parse_replace_if_unmodified_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string,
        f_key_length, "Key")

    -- Time units (u1)
    local time_units = tvb(offset, 1):uint()
    tree:add(f_time_units, tvb(offset, 1))
    offset = offset + 1

    -- Lifespan (vlong) - conditional
    local lifespan_unit = bit.band(time_units, 0x0F)
    if lifespan_unit < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan ~= nil then
            local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
            lifespan_item:append_text(string.format(" (%d)", lifespan))
            offset = offset + lifespan_len
        end
    end

    -- Max idle (vlong) - conditional
    local maxidle_unit = bit.rshift(bit.band(time_units, 0xF0), 4)
    if maxidle_unit < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle ~= nil then
            local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
            max_idle_item:append_text(string.format(" (%d)", max_idle))
            offset = offset + max_idle_len
        end
    end

    -- Entry version (s8)
    tree:add(f_metadata_version, tvb(offset, 8))
    offset = offset + 8

    -- Value (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string,
        f_value_length, "Value")

    return offset
end

-- REPLACE_IF_UNMODIFIED Response (0x0A)
-- Same as PUT response - returns previous value with metadata in protocol 4.0+
function parse_replace_if_unmodified_response(tvb, offset, tree, status, version)
    return parse_put_response(tvb, offset, tree, status, version)
end

-- REMOVE_IF_UNMODIFIED Request (0x0D)
function parse_remove_if_unmodified_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string,
        f_key_length, "Key")

    -- Entry version (s8)
    tree:add(f_metadata_version, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- REMOVE_IF_UNMODIFIED Response (0x0E)
-- Same as REMOVE response - returns previous value with metadata in protocol 4.0+
function parse_remove_if_unmodified_response(tvb, offset, tree, status, version)
    return parse_remove_response(tvb, offset, tree, status, version)
end

-- ============================================================================
-- Transaction Operations
-- ============================================================================

-- PREPARE Request (0x3B) - Old version, before PREPARE_V2
-- No body - just header
function parse_prepare_request(tvb, offset, tree)
    -- No body
    return offset
end

-- PREPARE Response (0x3C)
function parse_prepare_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- XA Return Code (s4)
    tree:add(f_tx_xa_return_code, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- COMMIT Request (0x3D)
function parse_commit_request(tvb, offset, tree)
    -- Transaction ID (XID)
    local xid_start = offset
    local xid_info, xid_len = parse_xid(tvb, offset, tree)
    if xid_info ~= nil then
        offset = offset + xid_len
    end
    return offset
end

-- COMMIT Response (0x3E)
function parse_commit_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- XA Return Code (s4)
    tree:add(f_tx_xa_return_code, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- ROLLBACK Request (0x3F)
function parse_rollback_request(tvb, offset, tree)
    -- Transaction ID (XID)
    local xid_start = offset
    local xid_info, xid_len = parse_xid(tvb, offset, tree)
    if xid_info ~= nil then
        offset = offset + xid_len
    end
    return offset
end

-- ROLLBACK Response (0x40)
function parse_rollback_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- XA Return Code (s4)
    tree:add(f_tx_xa_return_code, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- ============================================================================
-- Authentication Operations
-- ============================================================================

-- AUTH_MECH_LIST Request (0x21)
-- No body - just header
function parse_auth_mech_list_request(tvb, offset, tree)
    -- No body
    return offset
end

-- AUTH_MECH_LIST Response (0x22)
function parse_auth_mech_list_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Mechanism count (vint)
    local mech_count, count_len = read_vint(tvb, offset)
    if mech_count == nil then
        return offset
    end
    local count_item = tree:add(f_auth_mech_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", mech_count))
    offset = offset + count_len

    -- Mechanisms (array of lp_string)
    for i = 1, mech_count do
        offset = add_lp_string_with_length(tree, tvb, offset, f_auth_mech,
            f_auth_mech_length, string.format("Mechanism %d", i))
    end

    return offset
end

-- AUTH Request (0x23)
function parse_auth_request(tvb, offset, tree)
    -- Mechanism (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_auth_mech,
        f_auth_mech_length, "SASL Mechanism")

    -- Response data (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_auth_response_data, f_auth_response_data_string,
        f_auth_response_data_length, "Response Data")

    return offset
end

-- AUTH Response (0x24)
function parse_auth_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Completed (u1)
    tree:add(f_auth_completed, tvb(offset, 1))
    offset = offset + 1

    -- Challenge data (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_auth_challenge_data, f_auth_challenge_data_string,
        f_auth_challenge_data_length, "Challenge Data")

    return offset
end

-- ============================================================================
-- Client Listener Operations
-- ============================================================================

-- Helper: Parse listener factory params
function parse_listener_factory_params(tvb, offset, tree, label)
    if offset >= tvb:len() then
        return offset
    end

    -- Parameter count (u1)
    local param_count = tvb(offset, 1):uint()
    local count_item = tree:add(f_listener_param_count, tvb(offset, 1))
    count_item:append_text(string.format(" (%d)", param_count))
    offset = offset + 1

    -- Parameters (array of lp_bytes)
    for i = 1, param_count do
        offset = add_lp_bytes_with_length(tree, tvb, offset, f_listener_param, f_listener_param_string,
            f_listener_param_length, string.format("%s Parameter %d", label, i))
    end

    return offset
end

-- ADD_CLIENT_LISTENER Request (0x25)
function parse_add_client_listener_request(tvb, offset, tree)
    -- Listener ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_listener_id, f_listener_id_string,
        f_listener_id_length, "Listener ID")

    -- Include state (u1)
    tree:add(f_listener_include_state, tvb(offset, 1))
    offset = offset + 1

    -- Filter factory name (lp_string)
    local filter_name_offset = offset
    local filter_name, filter_name_len = read_lp_string(tvb, offset)
    offset = add_lp_string_with_length(tree, tvb, offset, f_listener_filter_factory,
        f_listener_filter_factory_length, "Filter Factory Name")

    -- Filter factory params (conditional - if name length > 0)
    if filter_name ~= nil and #filter_name > 0 then
        offset = parse_listener_factory_params(tvb, offset, tree, "Filter")
    end

    -- Converter factory name (lp_string)
    local converter_name_offset = offset
    local converter_name, converter_name_len = read_lp_string(tvb, offset)
    offset = add_lp_string_with_length(tree, tvb, offset, f_listener_converter_factory,
        f_listener_converter_factory_length, "Converter Factory Name")

    -- Converter factory params (conditional - if name length > 0)
    if converter_name ~= nil and #converter_name > 0 then
        offset = parse_listener_factory_params(tvb, offset, tree, "Converter")
    end

    -- Use raw data (u1)
    tree:add(f_listener_use_raw_data, tvb(offset, 1))
    offset = offset + 1

    -- Event type interests (vint) - bitmask
    local interests, interests_len = read_vint(tvb, offset)
    if interests ~= nil then
        local interests_item = tree:add(f_listener_event_interests, tvb(offset, interests_len))
        local event_types = {}
        if bit.band(interests, 0x01) ~= 0 then table.insert(event_types, "CREATED") end
        if bit.band(interests, 0x02) ~= 0 then table.insert(event_types, "MODIFIED") end
        if bit.band(interests, 0x04) ~= 0 then table.insert(event_types, "REMOVED") end
        if bit.band(interests, 0x08) ~= 0 then table.insert(event_types, "EXPIRED") end
        if #event_types > 0 then
            interests_item:append_text(string.format(" (%s)", table.concat(event_types, ", ")))
        end
        offset = offset + interests_len
    end

    return offset
end

-- ADD_CLIENT_LISTENER Response (0x26) - No body (status only)
function parse_add_client_listener_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- REMOVE_CLIENT_LISTENER Request (0x27)
function parse_remove_client_listener_request(tvb, offset, tree)
    -- Listener ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_listener_id, f_listener_id_string,
        f_listener_id_length, "Listener ID")
    return offset
end

-- REMOVE_CLIENT_LISTENER Response (0x28) - No body (status only)
function parse_remove_client_listener_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- ADD_BLOOM_FILTER_LISTENER Request (0x41)
function parse_add_bloom_filter_listener_request(tvb, offset, tree)
    -- Listener ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_listener_id, f_listener_id_string,
        f_listener_id_length, "Listener ID")

    -- Bloom filter bit size (vint)
    local bit_size, size_len = read_vint(tvb, offset)
    if bit_size ~= nil then
        local size_item = tree:add(f_bloom_filter_bit_size, tvb(offset, size_len))
        size_item:append_text(string.format(" (%d bits)", bit_size))
        offset = offset + size_len
    end

    return offset
end

-- ADD_BLOOM_FILTER_LISTENER Response (0x42) - No body (status only)
function parse_add_bloom_filter_listener_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- UPDATE_BLOOM_FILTER Request (0x43)
function parse_update_bloom_filter_request(tvb, offset, tree)
    -- Bloom filter bits (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_bloom_filter_bits, nil,
        f_bloom_filter_bits_length, "Bloom Filter Bits")
    return offset
end

-- UPDATE_BLOOM_FILTER Response (0x44) - No body (status only)
function parse_update_bloom_filter_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- ============================================================================
-- Status-Only Response Operations
-- ============================================================================

-- CLEAR Response (0x14) - No body
function parse_clear_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- ITERATION_END Response (0x36) - No body
function parse_iteration_end_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_CREATE Response (0x4C) - No body
function parse_counter_create_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_IS_DEFINED Response (0x51) - No body
function parse_counter_is_defined_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_RESET Response (0x55) - No body
function parse_counter_reset_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_ADD_LISTENER Response (0x5B) - No body
function parse_counter_add_listener_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_REMOVE_LISTENER Response (0x5D) - No body
function parse_counter_remove_listener_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_REMOVE Response (0x5F) - No body
function parse_counter_remove_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- MULTIMAP_PUT Response (0x6C) - No body
function parse_multimap_put_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- FORGET_TX Response (0x7A) - No body
function parse_forget_tx_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- COUNTER_GET_NAMES Response (0x65) - HAS BODY!
function parse_counter_get_names_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Counter count (vint)
    local count, count_len = read_vint(tvb, offset)
    if count == nil then
        return offset
    end
    local count_item = tree:add(f_counter_names_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", count))
    offset = offset + count_len

    -- Counter names (array of lp_string)
    for i = 1, count do
        offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name,
            f_counter_name_length, string.format("Counter Name %d", i))
    end

    return offset
end

-- ============================================================================
-- Stream Operations (Protocol 4.1) - Remaining
-- ============================================================================

-- GET_STREAM_END Response (0xE4) - No body
function parse_get_stream_end_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- GET_STREAM_NEXT Response (0xE6) - HAS BODY!
function parse_get_stream_next_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Stream ID (s4)
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    -- Complete flag (u1)
    tree:add(f_stream_complete, tvb(offset, 1))
    offset = offset + 1

    -- Value chunk (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string,
        f_value_length, "Value Chunk")

    return offset
end

-- PUT_STREAM_NEXT Response (0xEC) - No body
function parse_put_stream_next_response(tvb, offset, tree, status)
    -- No body - status in header
    return offset
end

-- PUT_STREAM_START Response (0xEE) - HAS BODY!
function parse_put_stream_start_response_ex(tvb, offset, tree, status)
    -- Note: there's already a parse_put_stream_start_response that we're using
    -- This is the correct implementation - it just returns stream_id
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Stream ID (s4)
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- CLEAR (0x13/0x14) - No body in request or response (status-only)
-- No parser needed - status is already shown in response header

-- ============================================================================
-- Iteration Operation Parsers (Batch 4)
-- ============================================================================

-- ITERATION_START Request (0x31)
function parse_iteration_start_request(tvb, offset, tree)
    -- Segments size (signed vint) - -1 means no segment filtering
    local segments_size, segments_size_len = read_signed_vint(tvb, offset)
    if segments_size == nil then
        return offset
    end
    local seg_size_item = tree:add(f_iteration_segments_size, tvb(offset, segments_size_len))
    seg_size_item:append_text(string.format(" (%d)", segments_size))
    offset = offset + segments_size_len

    -- Segments array (only if segments_size > 0)
    if segments_size > 0 then
        -- Each segment is a vint
        for i = 1, segments_size do
            local seg_id, seg_id_len = read_vint(tvb, offset)
            if seg_id == nil then
                break
            end
            local seg_item = tree:add(f_iteration_segment_id, tvb(offset, seg_id_len))
            seg_item:append_text(string.format(" (%d)", seg_id))
            offset = offset + seg_id_len
        end
    end

    -- Filter converter size (signed vint) - -1 means no filter
    local filter_size, filter_size_len = read_signed_vint(tvb, offset)
    if filter_size == nil then
        return offset
    end
    local filter_size_item = tree:add(f_iteration_filter_size, tvb(offset, filter_size_len))
    filter_size_item:append_text(string.format(" (%d)", filter_size))
    offset = offset + filter_size_len

    -- Filter converter (only if filter_size >= 0)
    if filter_size >= 0 then
        -- Filter string
        if offset + filter_size > tvb:len() then
            return offset
        end
        tree:add(f_iteration_filter, tvb(offset, filter_size))
        offset = offset + filter_size

        -- Parameter count (u1)
        if offset >= tvb:len() then
            return offset
        end
        local param_count = tvb(offset, 1):uint()
        tree:add(f_iteration_param_count, tvb(offset, 1))
        offset = offset + 1

        -- Parameters (array of lp_bytes)
        if param_count > 0 then
            for i = 1, param_count do
                offset = add_lp_bytes_with_length(tree, tvb, offset, f_iteration_param, nil, f_bytes_length, "Parameter")
                if offset == nil then
                    break
                end
            end
        end
    end

    -- Batch size (vint)
    local batch_size, batch_size_len = read_vint(tvb, offset)
    if batch_size == nil then
        return offset
    end
    local batch_item = tree:add(f_iteration_batch_size, tvb(offset, batch_size_len))
    batch_item:append_text(string.format(" (%d)", batch_size))
    offset = offset + batch_size_len

    -- Include metadata flag (u1)
    if offset >= tvb:len() then
        return offset
    end
    local metadata_flag = tvb(offset, 1):uint()
    tree:add(f_iteration_metadata_flag, tvb(offset, 1)):append_text(
        metadata_flag == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset
end

-- ITERATION_START Response (0x32)
function parse_iteration_start_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Iteration ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_iteration_id, f_iteration_id_string, f_iteration_id_length, "Iteration ID")

    return offset
end

-- ITERATION_NEXT Request (0x33)
function parse_iteration_next_request(tvb, offset, tree)
    -- Iteration ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_iteration_id, f_iteration_id_string, f_iteration_id_length, "Iteration ID")

    return offset
end

-- ITERATION_NEXT Response (0x34)
function parse_iteration_next_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Finished segments size (vint)
    local finished_size, finished_size_len = read_vint(tvb, offset)
    if finished_size == nil then
        return offset
    end
    local finished_size_item = tree:add(f_iteration_finished_segments_size, tvb(offset, finished_size_len))
    finished_size_item:append_text(string.format(" (%d)", finished_size))
    offset = offset + finished_size_len

    -- Finished segments (raw bytes)
    if finished_size > 0 then
        if offset + finished_size > tvb:len() then
            return offset
        end
        -- Parse as array of vints
        local seg_offset = offset
        local seg_end = offset + finished_size
        while seg_offset < seg_end do
            local seg_id, seg_len = read_vint(tvb, seg_offset)
            if seg_id == nil or seg_offset + seg_len > seg_end then
                break
            end
            local seg_item = tree:add(f_iteration_finished_segment, tvb(seg_offset, seg_len))
            seg_item:append_text(string.format(" (%d)", seg_id))
            seg_offset = seg_offset + seg_len
        end
        offset = offset + finished_size
    end

    -- Entry count (vint)
    local entry_count, entry_count_len = read_vint(tvb, offset)
    if entry_count == nil then
        return offset
    end
    local entry_count_item = tree:add(f_entry_count, tvb(offset, entry_count_len))
    entry_count_item:append_text(string.format(" (%d)", entry_count))
    offset = offset + entry_count_len

    -- Number of value projections (vint) - only if entry_count > 0
    local num_projections = 1  -- Default to 1 (full value)
    if entry_count > 0 then
        local proj, proj_len = read_vint(tvb, offset)
        if proj == nil then
            return offset
        end
        local proj_item = tree:add(f_iteration_num_projections, tvb(offset, proj_len))
        proj_item:append_text(string.format(" (%d)", proj))
        offset = offset + proj_len
        num_projections = proj
    end

    -- Entries array
    for i = 1, entry_count do
        local entry_tree = tree:add(hotrod_protocol, tvb(offset, 0)):set_text(string.format("Entry %d", i))

        -- Metadata present flag (u1)
        if offset >= tvb:len() then
            break
        end
        local metadata_present = tvb(offset, 1):uint()
        entry_tree:add(f_iteration_metadata_present, tvb(offset, 1)):append_text(
            metadata_present == 1 and " (Yes)" or " (No)")
        offset = offset + 1

        -- Metadata (if present)
        if metadata_present == 1 then
            local meta_tree = entry_tree:add(hotrod_protocol, tvb(offset, 0)):set_text("Metadata")

            -- Expiration flag (u1)
            if offset >= tvb:len() then
                break
            end
            local exp_flag = tvb(offset, 1):uint()
            local flag_text = ""
            if bit.band(exp_flag, 0x01) ~= 0 then
                flag_text = flag_text .. " INFINITE_LIFESPAN"
            end
            if bit.band(exp_flag, 0x02) ~= 0 then
                flag_text = flag_text .. " INFINITE_MAXIDLE"
            end
            meta_tree:add(f_iteration_expiration_flag, tvb(offset, 1)):append_text(flag_text)
            offset = offset + 1

            -- Created (s8) - only if INFINITE_LIFESPAN not set
            if bit.band(exp_flag, 0x01) == 0 then
                if offset + 8 > tvb:len() then
                    break
                end
                meta_tree:add(f_metadata_created, tvb(offset, 8))
                offset = offset + 8
            end

            -- Lifespan (vint) - only if INFINITE_LIFESPAN not set
            if bit.band(exp_flag, 0x01) == 0 then
                local lifespan, lifespan_len = read_vint(tvb, offset)
                if lifespan == nil then
                    break
                end
                local lifespan_item = meta_tree:add(f_metadata_lifespan, tvb(offset, lifespan_len))
                lifespan_item:append_text(string.format(" (%d)", lifespan))
                offset = offset + lifespan_len
            end

            -- Last used (s8) - only if INFINITE_MAXIDLE not set
            if bit.band(exp_flag, 0x02) == 0 then
                if offset + 8 > tvb:len() then
                    break
                end
                meta_tree:add(f_metadata_last_used, tvb(offset, 8))
                offset = offset + 8
            end

            -- Max idle (vint) - only if INFINITE_MAXIDLE not set
            if bit.band(exp_flag, 0x02) == 0 then
                local max_idle, max_idle_len = read_vint(tvb, offset)
                if max_idle == nil then
                    break
                end
                local max_idle_item = meta_tree:add(f_metadata_max_idle, tvb(offset, max_idle_len))
                max_idle_item:append_text(string.format(" (%d)", max_idle))
                offset = offset + max_idle_len
            end

            -- Entry version (s8) - always present
            if offset + 8 > tvb:len() then
                break
            end
            meta_tree:add(f_metadata_version, tvb(offset, 8))
            offset = offset + 8
        end

        -- Key (lp_bytes)
        offset = add_lp_bytes_with_length(entry_tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

        -- Values (array of lp_bytes, count = num_projections)
        for j = 1, num_projections do
            offset = add_lp_bytes_with_length(entry_tree, tvb, offset, f_value, f_value_string, f_value_length,
                num_projections > 1 and string.format("Value %d", j) or "Value")
            if offset == nil then
                break
            end
        end
    end

    return offset
end

-- ITERATION_END Request (0x35)
function parse_iteration_end_request(tvb, offset, tree)
    -- Iteration ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_iteration_id, f_iteration_id_string, f_iteration_id_length, "Iteration ID")

    return offset
end

-- ITERATION_END Response (0x36) - No body (status only)
-- No parser needed

-- ============================================================================
-- Counter Operation Parsers (Batch 5)
-- ============================================================================

-- Helper: Parse counter configuration
function parse_counter_configuration(tvb, offset, tree)
    local config_tree = tree:add(hotrod_protocol, tvb(offset, 0)):set_text("Counter Configuration")

    -- Flags (u1)
    if offset >= tvb:len() then
        return offset
    end
    local flags = tvb(offset, 1):uint()
    local flag_text = ""
    if bit.band(flags, 0x01) ~= 0 then flag_text = flag_text .. " WEAK" else flag_text = flag_text .. " STRONG" end
    if bit.band(flags, 0x02) ~= 0 then flag_text = flag_text .. " BOUNDED" else flag_text = flag_text .. " UNBOUNDED" end
    if bit.band(flags, 0x04) ~= 0 then flag_text = flag_text .. " PERSISTENT" else flag_text = flag_text .. " VOLATILE" end
    config_tree:add(f_counter_config_flags, tvb(offset, 1)):append_text(flag_text)
    offset = offset + 1

    -- Concurrency level (vint) - only if WEAK (bit 0 set)
    if bit.band(flags, 0x01) ~= 0 then
        local concurrency, concurrency_len = read_vint(tvb, offset)
        if concurrency == nil then
            return offset
        end
        local concurrency_item = config_tree:add(f_counter_concurrency, tvb(offset, concurrency_len))
        concurrency_item:append_text(string.format(" (%d)", concurrency))
        offset = offset + concurrency_len
    end

    -- Lower bound (s8) - only if BOUNDED (bit 1 set)
    if bit.band(flags, 0x02) ~= 0 then
        if offset + 8 > tvb:len() then
            return offset
        end
        config_tree:add(f_counter_lower_bound, tvb(offset, 8))
        offset = offset + 8
    end

    -- Upper bound (s8) - only if BOUNDED (bit 1 set)
    if bit.band(flags, 0x02) ~= 0 then
        if offset + 8 > tvb:len() then
            return offset
        end
        config_tree:add(f_counter_upper_bound, tvb(offset, 8))
        offset = offset + 8
    end

    -- Initial value (s8) - always present
    if offset + 8 > tvb:len() then
        return offset
    end
    config_tree:add(f_counter_initial_value, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- COUNTER_CREATE Request (0x4B)
function parse_counter_create_request(tvb, offset, tree)
    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")

    -- Configuration
    offset = parse_counter_configuration(tvb, offset, tree)

    return offset
end

-- COUNTER_CREATE Response (0x4C) - No body (status only)

-- COUNTER_GET_CONFIGURATION Request (0x4D)
function parse_counter_name_request(tvb, offset, tree)
    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")
    return offset
end

-- COUNTER_GET_CONFIGURATION Response (0x4E)
function parse_counter_get_configuration_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Configuration
    offset = parse_counter_configuration(tvb, offset, tree)

    return offset
end

-- COUNTER_IS_DEFINED Request (0x4F) - uses counter_name_request
-- COUNTER_IS_DEFINED Response (0x50) - No body (status only)

-- COUNTER_ADD_AND_GET Request (0x52)
function parse_counter_add_and_get_request(tvb, offset, tree)
    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")

    -- Delta (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_delta, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- COUNTER_ADD_AND_GET Response (0x53)
function parse_counter_value_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Value (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_value, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- COUNTER_RESET Request (0x54) - uses counter_name_request
-- COUNTER_RESET Response (0x55) - No body (status only)

-- COUNTER_GET_VALUE Request (0x56) - uses counter_name_request
-- COUNTER_GET_VALUE Response (0x57) - uses counter_value_response

-- COUNTER_CAS Request (0x58)
function parse_counter_cas_request(tvb, offset, tree)
    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")

    -- Expected value (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_expect, tvb(offset, 8))
    offset = offset + 8

    -- Update value (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_update, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- COUNTER_CAS Response (0x59) - uses counter_value_response

-- COUNTER_ADD_LISTENER Request (0x5A) - uses counter_name_request
-- COUNTER_ADD_LISTENER Response (0x5B) - No body (status only)

-- COUNTER_REMOVE_LISTENER Request (0x5C) - uses counter_name_request
-- COUNTER_REMOVE_LISTENER Response (0x5D) - No body (status only)

-- COUNTER_REMOVE Request (0x5E) - uses counter_name_request
-- COUNTER_REMOVE Response (0x5F) - No body (status only)

-- COUNTER_GET_AND_SET Request (0x7F)
function parse_counter_get_and_set_request(tvb, offset, tree)
    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")

    -- Value (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_value, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- COUNTER_GET_AND_SET Response (0x80) - uses counter_value_response

-- ============================================================================
-- Multimap Operation Parsers (Batch 6.1)
-- ============================================================================

-- MULTIMAP_GET Request (0x67) - also used for MULTIMAP_REMOVE_KEY (0x6D) and MULTIMAP_CONTAINS_KEY (0x75)
function parse_multimap_get_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Support duplicates (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_multimap_support_duplicates, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset
end

-- MULTIMAP_GET Response (0x68)
function parse_multimap_get_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Value count (vint)
    local value_count, count_len = read_vint(tvb, offset)
    if value_count == nil then
        return offset
    end
    local count_item = tree:add(f_multimap_value_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", value_count))
    offset = offset + count_len

    -- Values array
    for i = 1, value_count do
        offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length,
            value_count > 1 and string.format("Value %d", i) or "Value")
        if offset == nil then
            break
        end
    end

    return offset
end

-- MULTIMAP_GET_WITH_METADATA Request (0x69) - uses multimap_get_request

-- MULTIMAP_GET_WITH_METADATA Response (0x6A)
function parse_multimap_get_with_metadata_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Metadata
    offset = parse_entry_metadata(tvb, offset, tree)

    -- Value count (vint)
    local value_count, count_len = read_vint(tvb, offset)
    if value_count == nil then
        return offset
    end
    local count_item = tree:add(f_multimap_value_count, tvb(offset, count_len))
    count_item:append_text(string.format(" (%d)", value_count))
    offset = offset + count_len

    -- Values array
    for i = 1, value_count do
        offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length,
            value_count > 1 and string.format("Value %d", i) or "Value")
        if offset == nil then
            break
        end
    end

    return offset
end

-- MULTIMAP_PUT Request (0x6B) - also used for MULTIMAP_REMOVE_ENTRY (0x6F)
function parse_multimap_put_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Time units (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_time_units, tvb(offset, 1))
    local time_units = tvb(offset, 1):uint()
    offset = offset + 1

    -- Lifespan (vlong) - only if low nibble < 0x07
    if bit.band(time_units, 0x0F) < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan == nil then
            return offset
        end
        local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Max idle (vlong) - only if high nibble < 0x07
    if bit.rshift(bit.band(time_units, 0xF0), 4) < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle == nil then
            return offset
        end
        local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Value (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")

    -- Support duplicates (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_multimap_support_duplicates, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset
end

-- MULTIMAP_PUT Response (0x6C) - No body (status only)

-- MULTIMAP_SIZE Request (0x71) - No body
-- MULTIMAP_SIZE Response (0x72)
function parse_multimap_size_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Size (vlong)
    local size, size_len = read_vlong(tvb, offset)
    if size == nil then
        return offset
    end
    local size_item = tree:add(f_cache_size, tvb(offset, size_len))
    size_item:append_text(string.format(" (%d)", size))
    offset = offset + size_len

    return offset
end

-- MULTIMAP_CONTAINS_VALUE Request (0x77)
function parse_multimap_contains_value_request(tvb, offset, tree)
    -- Value (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")

    -- Support duplicates (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_multimap_support_duplicates, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset
end

-- MULTIMAP_CONTAINS_ENTRY Request (0x73)
function parse_multimap_contains_entry_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Time units (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_time_units, tvb(offset, 1))
    local time_units = tvb(offset, 1):uint()
    offset = offset + 1

    -- Lifespan (vlong) - only if high nibble < 0x07
    if bit.rshift(bit.band(time_units, 0xF0), 4) < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan == nil then
            return offset
        end
        local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Max idle (vlong) - only if low nibble < 0x07
    if bit.band(time_units, 0x0F) < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle == nil then
            return offset
        end
        local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Value (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")

    -- Support duplicates (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_multimap_support_duplicates, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset
end

-- MULTIMAP_CONTAINS_* Responses (0x6E, 0x70, 0x74, 0x76, 0x78)
function parse_multimap_contains_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Result (u1) - boolean
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_multimap_result, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (True)" or " (False)")
    offset = offset + 1

    return offset
end

-- ============================================================================
-- Stream Operation Parsers (Batch 6.2)
-- ============================================================================

-- GET_STREAM_START Request (0xE9)
function parse_get_stream_start_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Batch size (vint)
    local batch_size, batch_len = read_vint(tvb, offset)
    if batch_size == nil then
        return offset
    end
    local batch_item = tree:add(f_stream_batch_size, tvb(offset, batch_len))
    batch_item:append_text(string.format(" (%d)", batch_size))
    offset = offset + batch_len

    return offset
end

-- GET_STREAM_START Response (0xEA)
function parse_get_stream_start_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Stream ID (s4)
    if offset + 4 > tvb:len() then
        return offset
    end
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    -- Complete flag (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_stream_complete, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    -- Metadata
    offset = parse_entry_metadata(tvb, offset, tree)

    -- Value (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")

    return offset
end

-- GET_STREAM_NEXT Request (0xE7)
function parse_get_stream_next_request(tvb, offset, tree)
    -- Stream ID (s4)
    if offset + 4 > tvb:len() then
        return offset
    end
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- GET_STREAM_NEXT Response (0xE8) - same as GET_STREAM_START response

-- GET_STREAM_END Request (0xE5) - same as GET_STREAM_NEXT request
-- GET_STREAM_END Response (0xE6) - No body (status only)

-- PUT_STREAM_START Request (0xEF)
function parse_put_stream_start_request(tvb, offset, tree)
    -- Key (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

    -- Time units (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_time_units, tvb(offset, 1))
    local time_units = tvb(offset, 1):uint()
    offset = offset + 1

    -- Lifespan (vlong) - only if low nibble < 0x07
    if bit.band(time_units, 0x0F) < 0x07 then
        local lifespan, lifespan_len = read_vlong(tvb, offset)
        if lifespan == nil then
            return offset
        end
        local lifespan_item = tree:add(f_lifespan, tvb(offset, lifespan_len))
        lifespan_item:append_text(string.format(" (%d)", lifespan))
        offset = offset + lifespan_len
    end

    -- Max idle (vlong) - only if high nibble < 0x07
    if bit.rshift(bit.band(time_units, 0xF0), 4) < 0x07 then
        local max_idle, max_idle_len = read_vlong(tvb, offset)
        if max_idle == nil then
            return offset
        end
        local max_idle_item = tree:add(f_max_idle, tvb(offset, max_idle_len))
        max_idle_item:append_text(string.format(" (%d)", max_idle))
        offset = offset + max_idle_len
    end

    -- Condition version (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_stream_condition_version, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- PUT_STREAM_START Response (0xF0)
function parse_put_stream_start_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Stream ID (s4)
    if offset + 4 > tvb:len() then
        return offset
    end
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    return offset
end

-- PUT_STREAM_NEXT Request (0xED)
function parse_put_stream_next_request(tvb, offset, tree)
    -- Stream ID (s4)
    if offset + 4 > tvb:len() then
        return offset
    end
    tree:add(f_stream_id, tvb(offset, 4))
    offset = offset + 4

    -- Data chunk (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_stream_chunk, nil, f_bytes_length, "Data Chunk")

    return offset
end

-- PUT_STREAM_NEXT Response (0xEE) - No body (status only)

-- PUT_STREAM_END Request (0xEB) - same as GET_STREAM_NEXT request (stream ID only)
-- PUT_STREAM_END Response (0xEC) - No body (status only)

-- ============================================================================
-- Transaction Operation Parsers (Batch 6.3)
-- ============================================================================

-- Helper: Parse XID (transaction ID)
function parse_xid(tvb, offset, tree)
    local xid_tree = tree:add(hotrod_protocol, tvb(offset, 0)):set_text("Transaction ID (XID)")

    -- Format ID (vint)
    local format_id, format_len = read_vint(tvb, offset)
    if format_id == nil then
        return offset
    end
    local format_item = xid_tree:add(f_tx_xid_format, tvb(offset, format_len))
    format_item:append_text(string.format(" (%d)", format_id))
    offset = offset + format_len

    -- Global TX ID length (u1)
    if offset >= tvb:len() then
        return offset
    end
    local global_len = tvb(offset, 1):uint()
    xid_tree:add(f_tx_xid_global_length, tvb(offset, 1))
    offset = offset + 1

    -- Global TX ID (bytes)
    if global_len > 0 then
        if offset + global_len > tvb:len() then
            return offset
        end
        xid_tree:add(f_tx_xid_global, tvb(offset, global_len))
        offset = offset + global_len
    end

    -- Branch qualifier length (u1)
    if offset >= tvb:len() then
        return offset
    end
    local branch_len = tvb(offset, 1):uint()
    xid_tree:add(f_tx_xid_branch_length, tvb(offset, 1))
    offset = offset + 1

    -- Branch qualifier (bytes)
    if branch_len > 0 then
        if offset + branch_len > tvb:len() then
            return offset
        end
        xid_tree:add(f_tx_xid_branch, tvb(offset, branch_len))
        offset = offset + branch_len
    end

    return offset
end

-- COMMIT Request (0x3D) - No body (just uses transaction context from request header)
-- COMMIT Response (0x3E) - No body (status only)

-- ROLLBACK Request (0x3F) - No body
-- ROLLBACK Response (0x40) - No body (status only)

-- FORGET_TX Request (0x79)
function parse_forget_tx_request(tvb, offset, tree)
    offset = parse_xid(tvb, offset, tree)
    return offset
end

-- FORGET_TX Response (0x7A) - No body (status only)

-- FETCH_IN_DOUBT_TX Request (0x7B) - No body
-- FETCH_IN_DOUBT_TX Response (0x7C)
function parse_fetch_in_doubt_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- Number of XIDs (vint)
    local num_xids, num_len = read_vint(tvb, offset)
    if num_xids == nil then
        return offset
    end
    local num_item = tree:add(f_tx_num_xids, tvb(offset, num_len))
    num_item:append_text(string.format(" (%d)", num_xids))
    offset = offset + num_len

    -- XIDs array
    for i = 1, num_xids do
        offset = parse_xid(tvb, offset, tree)
    end

    return offset
end

-- PREPARE_V2 Request (0x7D)
function parse_prepare_v2_request(tvb, offset, tree)
    -- Transaction ID (XID)
    offset = parse_xid(tvb, offset, tree)

    -- One phase commit (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_tx_one_phase, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    -- Recoverable (u1)
    if offset >= tvb:len() then
        return offset
    end
    tree:add(f_tx_recoverable, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    -- Timeout (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_tx_timeout, tvb(offset, 8))
    offset = offset + 8

    -- Number of keys (vint)
    local num_keys, num_len = read_vint(tvb, offset)
    if num_keys == nil then
        return offset
    end
    local num_item = tree:add(f_tx_num_keys, tvb(offset, num_len))
    num_item:append_text(string.format(" (%d)", num_keys))
    offset = offset + num_len

    -- TX write entries array
    for i = 1, num_keys do
        local entry_tree = tree:add(hotrod_protocol, tvb(offset, 0)):set_text(string.format("Write Entry %d", i))

        -- Key (lp_bytes)
        offset = add_lp_bytes_with_length(entry_tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

        -- Control byte (u1)
        if offset >= tvb:len() then
            break
        end
        local control_byte = tvb(offset, 1):uint()
        local control_text = ""
        if bit.band(control_byte, 0x01) ~= 0 then control_text = control_text .. " NOT_READ" end
        if bit.band(control_byte, 0x02) ~= 0 then control_text = control_text .. " NON_EXISTING" end
        if bit.band(control_byte, 0x04) ~= 0 then control_text = control_text .. " REMOVE_OPERATION" end
        entry_tree:add(f_tx_control_byte, tvb(offset, 1)):append_text(control_text)
        offset = offset + 1

        -- Version read (s8) - only if NOT_READ and NON_EXISTING are both clear
        if bit.band(control_byte, 0x01) == 0 and bit.band(control_byte, 0x02) == 0 then
            if offset + 8 > tvb:len() then
                break
            end
            entry_tree:add(f_metadata_version, tvb(offset, 8))
            offset = offset + 8
        end

        -- Time units (u1) - only if REMOVE_OPERATION is clear
        if bit.band(control_byte, 0x04) == 0 then
            if offset >= tvb:len() then
                break
            end
            entry_tree:add(f_time_units, tvb(offset, 1))
            local time_units = tvb(offset, 1):uint()
            offset = offset + 1

            -- Lifespan (vlong) - conditional
            if bit.band(time_units, 0x0F) < 0x07 then
                local lifespan, lifespan_len = read_vlong(tvb, offset)
                if lifespan == nil then
                    break
                end
                local lifespan_item = entry_tree:add(f_lifespan, tvb(offset, lifespan_len))
                lifespan_item:append_text(string.format(" (%d)", lifespan))
                offset = offset + lifespan_len
            end

            -- Max idle (vlong) - conditional
            if bit.rshift(bit.band(time_units, 0xF0), 4) < 0x07 then
                local max_idle, max_idle_len = read_vlong(tvb, offset)
                if max_idle == nil then
                    break
                end
                local max_idle_item = entry_tree:add(f_max_idle, tvb(offset, max_idle_len))
                max_idle_item:append_text(string.format(" (%d)", max_idle))
                offset = offset + max_idle_len
            end

            -- Value (lp_bytes)
            offset = add_lp_bytes_with_length(entry_tree, tvb, offset, f_value, f_value_string, f_value_length, "Value")
        end
    end

    return offset
end

-- PREPARE_V2 Response (0x7E)
function parse_prepare_v2_response(tvb, offset, tree, status)
    if status ~= 0x00 then  -- Not SUCCESS
        return offset
    end

    -- XA Return Code (vint)
    local xa_code, xa_len = read_vint(tvb, offset)
    if xa_code == nil then
        return offset
    end
    local xa_item = tree:add(hotrod_protocol, tvb(offset, xa_len))
    xa_item:set_text(string.format("XA Return Code: %d", xa_code))
    offset = offset + xa_len

    return offset
end

-- ============================================================================
-- Event Parsers (Batch 6.4)
-- ============================================================================

-- Helper: Parse event header (common to all cache events)
function parse_event_header(tvb, offset, tree)
    -- Status (u1)
    if offset >= tvb:len() then
        return offset, nil
    end
    tree:add(f_resp_status, tvb(offset, 1))
    offset = offset + 1

    -- Topology change marker (u1)
    if offset >= tvb:len() then
        return offset, nil
    end
    tree:add(f_resp_topology_marker, tvb(offset, 1))
    offset = offset + 1

    -- Listener ID (lp_bytes)
    offset = add_lp_bytes_with_length(tree, tvb, offset, f_event_listener_id, f_event_listener_id_string, f_event_listener_id_length, "Listener ID")

    -- Custom marker (u1)
    if offset >= tvb:len() then
        return offset, nil
    end
    local custom_marker = tvb(offset, 1):uint()
    tree:add(f_event_custom_marker, tvb(offset, 1))
    offset = offset + 1

    -- Command retried (u1)
    if offset >= tvb:len() then
        return offset, nil
    end
    tree:add(f_event_command_retried, tvb(offset, 1)):append_text(
        tvb(offset, 1):uint() == 1 and " (Yes)" or " (No)")
    offset = offset + 1

    return offset, custom_marker
end

-- CACHE_ENTRY_CREATED_EVENT (0x60)
-- CACHE_ENTRY_MODIFIED_EVENT (0x61)
-- CACHE_ENTRY_REMOVED_EVENT (0x62)
-- CACHE_ENTRY_EXPIRED_EVENT (0x63)
function parse_cache_entry_event(tvb, offset, tree)
    local custom_marker
    offset, custom_marker = parse_event_header(tvb, offset, tree)

    if custom_marker == nil then
        return offset
    end

    if custom_marker == 1 or custom_marker == 2 then
        -- Custom data (lp_bytes)
        offset = add_lp_bytes_with_length(tree, tvb, offset, f_event_custom_data, nil, f_bytes_length, "Custom Data")
    else
        -- Key (lp_bytes)
        offset = add_lp_bytes_with_length(tree, tvb, offset, f_key, f_key_string, f_key_length, "Key")

        -- Version (s8)
        if offset + 8 > tvb:len() then
            return offset
        end
        tree:add(f_metadata_version, tvb(offset, 8))
        offset = offset + 8
    end

    return offset
end

-- COUNTER_EVENT (0x66)
function parse_counter_event(tvb, offset, tree)
    offset = parse_event_header(tvb, offset, tree)

    -- Counter name (lp_string)
    offset = add_lp_string_with_length(tree, tvb, offset, f_counter_name, f_counter_name_length, "Counter Name")

    -- Counter value (s8)
    if offset + 8 > tvb:len() then
        return offset
    end
    tree:add(f_counter_value, tvb(offset, 8))
    offset = offset + 8

    return offset
end

-- ============================================================================
-- Request Header Parser
-- ============================================================================

function parse_request_header(tvb, offset, tree, pinfo)
    local start_offset = offset

    -- Calculate remaining length for header tree
    local remaining = tvb:len() - offset
    if remaining < 1 then
        return nil
    end

    -- Create header tree using ProtoField
    local header_tree = tree:add(f_req_header, tvb(offset, remaining))

    -- Message ID (vlong)
    local message_id, id_len = read_vlong(tvb, offset)
    if message_id == nil or id_len == 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read message ID")
        return nil
    end

    -- For vlong (custom encoding), add bytes and append decoded text
    local msg_id_item = header_tree:add(f_req_message_id, tvb(offset, id_len))
    msg_id_item:append_text(string.format(" (%d)", message_id))
    offset = offset + id_len

    -- Version (u1)
    local version = tvb(offset, 1):uint()
    header_tree:add(f_req_version, tvb(offset, 1)):append_text(string.format(" (Protocol %d.%d)",
        math.floor(version / 10), version % 10))
    offset = offset + 1

    -- Opcode (u1)
    local opcode = tvb(offset, 1):uint()
    local opcode_name = request_opcodes[opcode] or "UNKNOWN"
    header_tree:add(f_req_opcode, tvb(offset, 1)):append_text(string.format(" (%s)", opcode_name))
    offset = offset + 1

    -- Cache name (vint length + UTF-8 string)
    local cache_name, cache_name_len = read_lp_string(tvb, offset)
    if cache_name == nil or cache_name_len == 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read cache name")
        return nil
    end
    header_tree:add(f_req_cache_name, tvb(offset, cache_name_len), cache_name)
    offset = offset + cache_name_len

    -- Flags (vint)
    local flags, flags_len = read_vint(tvb, offset)
    if flags == nil or flags_len == 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read flags")
        return nil
    end
    -- For vint (custom encoding), add bytes and append decoded text
    local flags_item = header_tree:add(f_req_flags, tvb(offset, flags_len))
    flags_item:append_text(string.format(" (%d)", flags))
    offset = offset + flags_len

    -- Client Intelligence (u1)
    local intelligence = tvb(offset, 1):uint()
    local intelligence_name = client_intelligence[intelligence] or "Unknown"
    header_tree:add(f_req_client_intelligence, tvb(offset, 1)):append_text(string.format(" (%s)", intelligence_name))
    offset = offset + 1

    -- Topology ID (vint)
    local topology_id, topo_len = read_vint(tvb, offset)
    if topology_id == nil or topo_len == 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read topology ID")
        return nil
    end
    -- For vint (custom encoding), add bytes and append decoded text
    local topo_item = header_tree:add(f_req_topology_id, tvb(offset, topo_len))
    topo_item:append_text(string.format(" (%d)", topology_id))
    offset = offset + topo_len

    -- MediaType parsing (protocol 2.8+)
    if version >= 28 then
        -- Key Media Type
        local key_media, key_media_len = parse_media_type(tvb, offset, header_tree, "Key Media Type")
        if key_media ~= nil then
            offset = offset + key_media_len
        else
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to parse key media type")
            return nil
        end

        -- Value Media Type
        local value_media, value_media_len = parse_media_type(tvb, offset, header_tree, "Value Media Type")
        if value_media ~= nil then
            offset = offset + value_media_len
        else
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to parse value media type")
            return nil
        end
    end

    -- Other Params parsing (protocol 4.0+)
    if version >= 40 then
        local other_param_count, param_count_len = read_vint(tvb, offset)
        if other_param_count == nil then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read other param count")
            return nil
        end

        -- For vint, add bytes and append decoded text
        local other_count_item = header_tree:add(f_other_param_count, tvb(offset, param_count_len))
        other_count_item:append_text(string.format(" (%d)", other_param_count))
        offset = offset + param_count_len

        -- Read other parameters
        for i = 1, other_param_count do
            -- Parameter key (lp_string)
            local param_key, key_len = read_lp_string(tvb, offset)
            if param_key == nil then
                break
            end

            local param_item = header_tree:add(tvb(offset, 1), string.format("Other Parameter %d", i - 1))
            param_item:add(f_other_param_key, tvb(offset, key_len), param_key)
            offset = offset + key_len

            -- Parameter value (lp_bytes - raw bytes, not string)
            local param_value_range, value_len = read_lp_bytes(tvb, offset)
            if param_value_range == nil then
                break
            end
            param_item:add(f_other_param_value, tvb(offset, value_len))
            param_item:set_len(key_len + value_len)
            offset = offset + value_len
        end
    end

    local header_info = {
        message_id = message_id,
        version = version,
        opcode = opcode,
        opcode_name = opcode_name,
        cache_name = cache_name,
        intelligence = intelligence,
        header_length = offset - start_offset
    }

    -- Store request for correlation (first pass only)
    if not pinfo.visited then
        -- Mark this message_id as pending, waiting for response
        pending_requests[message_id] = pinfo.number
    end

    -- Check if we have a response for this request
    local response_frame = request_to_response[pinfo.number]
    if response_frame then
        local resp_frame_item = header_tree:add(f_req_in_frame, response_frame)
        resp_frame_item:set_generated()
    end

    return header_info
end

-- ============================================================================
-- Response Header Parser
-- ============================================================================

function parse_response_header(tvb, offset, tree, pinfo)
    local start_offset = offset

    -- Calculate remaining length for header tree
    local remaining = tvb:len() - offset
    if remaining < 1 then
        return nil
    end

    -- Create header tree using ProtoField
    local header_tree = tree:add(f_resp_header, tvb(offset, remaining))

    -- Message ID (vlong)
    local message_id, id_len = read_vlong(tvb, offset)
    if message_id == nil or id_len == 0 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to read message ID")
        return nil
    end

    -- For vlong (custom encoding), add bytes and append decoded text
    local msg_id_item = header_tree:add(f_resp_message_id, tvb(offset, id_len))
    msg_id_item:append_text(string.format(" (%d)", message_id))
    offset = offset + id_len

    -- Opcode (u1)
    local opcode = tvb(offset, 1):uint()
    local opcode_name = response_opcodes[opcode] or "UNKNOWN"
    header_tree:add(f_resp_opcode, tvb(offset, 1)):append_text(string.format(" (%s)", opcode_name))
    offset = offset + 1

    -- Status (u1) - Not present for event opcodes (0x60-0x63)
    local status = nil
    local is_event = (opcode >= 0x60 and opcode <= 0x63)
    if not is_event then
        status = tvb(offset, 1):uint()
        local status_name = status_codes[status] or "Unknown"
        header_tree:add(f_resp_status, tvb(offset, 1)):append_text(string.format(" (%s)", status_name))
        offset = offset + 1

        -- Topology Change Marker (u1)
        local topology_marker = tvb(offset, 1):uint()
        header_tree:add(f_resp_topology_marker, tvb(offset, 1))
        offset = offset + 1

        -- Parse topology change if marker != 0 (assumes intelligence 0x03)
        if topology_marker ~= 0 then
            local topo_change, topo_len = parse_topology_change(tvb, offset, header_tree)
            if topo_change ~= nil then
                offset = offset + topo_len
            else
                tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Failed to parse topology change")
            end
        end
    end

    local header_info = {
        message_id = message_id,
        opcode = opcode,
        opcode_name = opcode_name,
        status = status,
        is_event = is_event,
        header_length = offset - start_offset
    }

    -- Match response with pending request (first pass only)
    if not pinfo.visited then
        local request_frame = pending_requests[message_id]
        if request_frame then
            -- Found the matching request, create bidirectional mapping
            request_to_response[request_frame] = pinfo.number
            response_to_request[pinfo.number] = request_frame
            -- Clear the pending request
            pending_requests[message_id] = nil
        end
    end

    -- Check if we have a request for this response
    local request_frame = response_to_request[pinfo.number]
    if request_frame then
        local req_frame_item = header_tree:add(f_resp_in_frame, request_frame)
        req_frame_item:set_generated()
    end

    return header_info
end

-- ============================================================================
-- Main Dissector Function
-- ============================================================================

function hotrod_protocol.dissector(tvb, pinfo, tree)
    -- Check minimum length (at least magic byte + message_id start)
    if tvb:len() < 2 then
        return 0
    end

    -- Ensure tree is valid
    if not tree then
        return 0
    end

    -- Check magic byte
    local magic = tvb(0, 1):uint()
    if magic ~= 0xA0 and magic ~= 0xA1 then
        -- Not a Hot Rod packet
        return 0
    end

    -- Set protocol column
    pinfo.cols.protocol = "HotRod"

    -- Create protocol tree
    local subtree = tree:add(hotrod_protocol, tvb(), "Hot Rod Protocol")

    -- Add magic byte
    local magic_item = subtree:add(f_magic, tvb(0, 1))
    local offset = 1

    -- Determine if request or response
    local is_request = (magic == 0xA0)

    if is_request then
        magic_item:append_text(" (Request)")
        pinfo.cols.info = "Request: "

        local header_info = parse_request_header(tvb, offset, subtree, pinfo)
        if header_info == nil then
            return tvb:len()
        end

        pinfo.cols.info:append(header_info.opcode_name)
        offset = offset + header_info.header_length

        -- Parse request body based on opcode
        if header_info.opcode == 0x01 then  -- PUT
            offset = parse_put_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x03 then  -- GET
            offset = parse_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x05 then  -- PUT_IF_ABSENT
            offset = parse_put_if_absent_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x07 then  -- REPLACE
            offset = parse_replace_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x09 then  -- REPLACE_IF_UNMODIFIED
            offset = parse_replace_if_unmodified_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x0B then  -- REMOVE
            offset = parse_remove_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x0D then  -- REMOVE_IF_UNMODIFIED
            offset = parse_remove_if_unmodified_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x0F then  -- CONTAINS_KEY
            offset = parse_contains_key_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x1B then  -- GET_WITH_METADATA
            offset = parse_get_with_metadata_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x19 then  -- BULK_GET
            offset = parse_bulk_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x1D then  -- BULK_GET_KEYS
            offset = parse_bulk_get_keys_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x1F then  -- QUERY
            offset = parse_query_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x21 then  -- AUTH_MECH_LIST
            offset = parse_auth_mech_list_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x23 then  -- AUTH
            offset = parse_auth_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x25 then  -- ADD_CLIENT_LISTENER
            offset = parse_add_client_listener_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x27 then  -- REMOVE_CLIENT_LISTENER
            offset = parse_remove_client_listener_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x2B then  -- EXEC
            offset = parse_exec_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x2D then  -- PUT_ALL
            offset = parse_put_all_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x2F then  -- GET_ALL
            offset = parse_get_all_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x31 then  -- ITERATION_START
            offset = parse_iteration_start_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x33 then  -- ITERATION_NEXT
            offset = parse_iteration_next_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x35 then  -- ITERATION_END
            offset = parse_iteration_end_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x3B then  -- PREPARE
            offset = parse_prepare_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x3D then  -- COMMIT
            offset = parse_commit_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x3F then  -- ROLLBACK
            offset = parse_rollback_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x41 then  -- ADD_BLOOM_FILTER_LISTENER
            offset = parse_add_bloom_filter_listener_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x43 then  -- UPDATE_BLOOM_FILTER
            offset = parse_update_bloom_filter_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x4B then  -- COUNTER_CREATE
            offset = parse_counter_create_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x4D then  -- COUNTER_GET_CONFIGURATION
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x4F then  -- COUNTER_IS_DEFINED
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x52 then  -- COUNTER_ADD_AND_GET
            offset = parse_counter_add_and_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x54 then  -- COUNTER_RESET
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x56 then  -- COUNTER_GET_VALUE
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x58 then  -- COUNTER_CAS
            offset = parse_counter_cas_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x5A then  -- COUNTER_ADD_LISTENER
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x5C then  -- COUNTER_REMOVE_LISTENER
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x5E then  -- COUNTER_REMOVE
            offset = parse_counter_name_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x7F then  -- COUNTER_GET_AND_SET
            offset = parse_counter_get_and_set_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x67 then  -- MULTIMAP_GET
            offset = parse_multimap_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x69 then  -- MULTIMAP_GET_WITH_METADATA
            offset = parse_multimap_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x6B then  -- MULTIMAP_PUT
            offset = parse_multimap_put_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x6D then  -- MULTIMAP_REMOVE_KEY
            offset = parse_multimap_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x6F then  -- MULTIMAP_REMOVE_ENTRY
            offset = parse_multimap_put_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x73 then  -- MULTIMAP_CONTAINS_ENTRY
            offset = parse_multimap_contains_entry_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x75 then  -- MULTIMAP_CONTAINS_KEY
            offset = parse_multimap_get_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x77 then  -- MULTIMAP_CONTAINS_VALUE
            offset = parse_multimap_contains_value_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xE9 then  -- GET_STREAM_START
            offset = parse_get_stream_start_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xE7 then  -- GET_STREAM_NEXT
            offset = parse_get_stream_next_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xE5 then  -- GET_STREAM_END
            offset = parse_get_stream_next_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xEF then  -- PUT_STREAM_START
            offset = parse_put_stream_start_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xED then  -- PUT_STREAM_NEXT
            offset = parse_put_stream_next_request(tvb, offset, subtree)
        elseif header_info.opcode == 0xEB then  -- PUT_STREAM_END
            offset = parse_get_stream_next_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x79 then  -- FORGET_TX
            offset = parse_forget_tx_request(tvb, offset, subtree)
        elseif header_info.opcode == 0x7D then  -- PREPARE_V2
            offset = parse_prepare_v2_request(tvb, offset, subtree)
        end

    else
        magic_item:append_text(" (Response)")
        pinfo.cols.info = "Response: "

        local header_info = parse_response_header(tvb, offset, subtree, pinfo)
        if header_info == nil then
            return tvb:len()
        end

        pinfo.cols.info:append(header_info.opcode_name)
        offset = offset + header_info.header_length

        -- Parse response body based on opcode
        -- We need the request version for protocol-specific parsing
        -- For now, assume protocol 4.0+ (we can enhance this with version tracking later)
        local version = 40  -- Default to 4.0 for now

        if header_info.opcode == 0x02 then  -- PUT response
            offset = parse_put_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x04 then  -- GET response
            offset = parse_get_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x06 then  -- PUT_IF_ABSENT response
            offset = parse_put_if_absent_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x08 then  -- REPLACE response
            offset = parse_replace_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x0A then  -- REPLACE_IF_UNMODIFIED response
            offset = parse_replace_if_unmodified_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x0C then  -- REMOVE response
            offset = parse_remove_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x0E then  -- REMOVE_IF_UNMODIFIED response
            offset = parse_remove_if_unmodified_response(tvb, offset, subtree, header_info.status, version)
        elseif header_info.opcode == 0x10 then  -- CONTAINS_KEY response
            offset = parse_contains_key_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x14 then  -- CLEAR response
            offset = parse_clear_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x18 then  -- PING response
            offset = parse_ping_response(tvb, offset, subtree)
        elseif header_info.opcode == 0x16 then  -- STATS response
            offset = parse_stats_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x2A then  -- SIZE response
            offset = parse_size_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x1C then  -- GET_WITH_METADATA response
            offset = parse_get_with_metadata_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x1A then  -- BULK_GET response
            offset = parse_bulk_get_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x1E then  -- BULK_GET_KEYS response
            offset = parse_bulk_get_keys_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x20 then  -- QUERY response
            offset = parse_query_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x22 then  -- AUTH_MECH_LIST response
            offset = parse_auth_mech_list_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x24 then  -- AUTH response
            offset = parse_auth_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x26 then  -- ADD_CLIENT_LISTENER response
            offset = parse_add_client_listener_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x28 then  -- REMOVE_CLIENT_LISTENER response
            offset = parse_remove_client_listener_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x2C then  -- EXEC response
            offset = parse_exec_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x2E then  -- PUT_ALL response
            offset = parse_put_all_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x30 then  -- GET_ALL response
            offset = parse_get_all_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x32 then  -- ITERATION_START response
            offset = parse_iteration_start_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x34 then  -- ITERATION_NEXT response
            offset = parse_iteration_next_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x36 then  -- ITERATION_END response
            offset = parse_iteration_end_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x3C then  -- PREPARE response
            offset = parse_prepare_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x3E then  -- COMMIT response
            offset = parse_commit_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x40 then  -- ROLLBACK response
            offset = parse_rollback_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x42 then  -- ADD_BLOOM_FILTER_LISTENER response
            offset = parse_add_bloom_filter_listener_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x44 then  -- UPDATE_BLOOM_FILTER response
            offset = parse_update_bloom_filter_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x4C then  -- COUNTER_CREATE response
            offset = parse_counter_create_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x4E then  -- COUNTER_GET_CONFIGURATION response
            offset = parse_counter_get_configuration_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x50 then  -- ERROR response
            offset = parse_error_response(tvb, offset, subtree)
        elseif header_info.opcode == 0x51 then  -- COUNTER_IS_DEFINED response
            offset = parse_counter_is_defined_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x53 then  -- COUNTER_ADD_AND_GET response
            offset = parse_counter_value_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x55 then  -- COUNTER_RESET response
            offset = parse_counter_reset_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x57 then  -- COUNTER_GET_VALUE response
            offset = parse_counter_value_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x59 then  -- COUNTER_CAS response
            offset = parse_counter_value_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x5B then  -- COUNTER_ADD_LISTENER response
            offset = parse_counter_add_listener_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x5D then  -- COUNTER_REMOVE_LISTENER response
            offset = parse_counter_remove_listener_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x5F then  -- COUNTER_REMOVE response
            offset = parse_counter_remove_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x65 then  -- COUNTER_GET_NAMES response
            offset = parse_counter_get_names_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x80 then  -- COUNTER_GET_AND_SET response
            offset = parse_counter_value_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x68 then  -- MULTIMAP_GET response
            offset = parse_multimap_get_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x6A then  -- MULTIMAP_GET_WITH_METADATA response
            offset = parse_multimap_get_with_metadata_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x6C then  -- MULTIMAP_PUT response
            offset = parse_multimap_put_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x6E then  -- MULTIMAP_REMOVE_KEY response
            offset = parse_multimap_contains_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x70 then  -- MULTIMAP_REMOVE_ENTRY response
            offset = parse_multimap_contains_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x72 then  -- MULTIMAP_SIZE response
            offset = parse_multimap_size_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x74 then  -- MULTIMAP_CONTAINS_ENTRY response
            offset = parse_multimap_contains_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x76 then  -- MULTIMAP_CONTAINS_KEY response
            offset = parse_multimap_contains_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x78 then  -- MULTIMAP_CONTAINS_VALUE response
            offset = parse_multimap_contains_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x7A then  -- FORGET_TX response
            offset = parse_forget_tx_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xE4 then  -- GET_STREAM_END response
            offset = parse_get_stream_end_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xE6 then  -- GET_STREAM_NEXT response
            offset = parse_get_stream_next_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xE8 then  -- GET_STREAM_START response
            offset = parse_get_stream_start_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xEA then  -- GET_STREAM_START response (duplicate?)
            offset = parse_get_stream_start_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xEC then  -- PUT_STREAM_NEXT response
            offset = parse_put_stream_next_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0xEE then  -- PUT_STREAM_START response
            offset = parse_put_stream_start_response_ex(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x7C then  -- FETCH_IN_DOUBT_TX response
            offset = parse_fetch_in_doubt_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x7E then  -- PREPARE_V2 response
            offset = parse_prepare_v2_response(tvb, offset, subtree, header_info.status)
        elseif header_info.opcode == 0x60 then  -- CACHE_ENTRY_CREATED_EVENT
            offset = parse_cache_entry_event(tvb, offset, subtree)
        elseif header_info.opcode == 0x61 then  -- CACHE_ENTRY_MODIFIED_EVENT
            offset = parse_cache_entry_event(tvb, offset, subtree)
        elseif header_info.opcode == 0x62 then  -- CACHE_ENTRY_REMOVED_EVENT
            offset = parse_cache_entry_event(tvb, offset, subtree)
        elseif header_info.opcode == 0x63 then  -- CACHE_ENTRY_EXPIRED_EVENT
            offset = parse_cache_entry_event(tvb, offset, subtree)
        elseif header_info.opcode == 0x66 then  -- COUNTER_EVENT
            offset = parse_counter_event(tvb, offset, subtree)
        end
    end

    return tvb:len()
end

-- ============================================================================
-- Protocol Registration
-- ============================================================================

-- Register on TCP port 11222 (default Hot Rod port)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(11222, hotrod_protocol)

-- Heuristic dissector for auto-detection on non-standard ports
local function heuristic_checker(tvb, pinfo, tree)
    -- Need at least 2 bytes to check magic
    if tvb:len() < 2 then
        return false
    end

    -- Check for Hot Rod magic byte
    local magic = tvb(0, 1):uint()
    if magic ~= 0xA0 and magic ~= 0xA1 then
        return false
    end

    -- Looks like Hot Rod - dissect it
    hotrod_protocol.dissector(tvb, pinfo, tree)
    pinfo.conversation = hotrod_protocol
    return true
end

-- Register heuristic dissector
-- NOTE: Auto-detects HotRod traffic on any TCP port by checking for magic bytes (0xA0/0xA1)
-- This may slow down plugin reload on very large capture files (>10k packets)
hotrod_protocol:register_heuristic("tcp", heuristic_checker)

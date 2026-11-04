meta:
  id: hotrod40
  title: Infinispan Hot Rod Protocol 4.x
  endian: be
  license: Apache-2.0

doc: |
  Hot Rod is a binary TCP client-server protocol used by Infinispan.
  This schema describes protocol versions 4.0 and 4.1.

  Protocol 4.0 was introduced in Infinispan 14.0.
  Protocol 4.1 was introduced in Infinispan 15.1.

  Key differences from 3.x:
  - PUT/REPLACE/REMOVE responses with previous values now include metadata
    (created, lifespan, lastUsed, maxIdle, version) in addition to the value
  - Request headers include "other params" field for additional parameters
  - Protocol 4.1 adds new stream operations (GetStreamStart, PutStreamStart, etc.)

  For more information, see:
  https://infinispan.org/docs/stable/titles/hotrod_java/hotrod_java.html

seq:
  - id: magic
    type: u1
  - id: message
    type:
      switch-on: magic
      cases:
        0xA0: request_message
        0xA1: response_message

types:

  request_message:
    seq:
      - id: header
        type: request_header
      - id: body
        type:
          switch-on: header.opcode
          cases:
            'request_opcode::put': put_request
            'request_opcode::put_if_absent': put_request
            'request_opcode::replace': put_request
            'request_opcode::replace_if_unmodified': replace_if_unmodified_request
            'request_opcode::remove_if_unmodified': remove_if_unmodified_request
            'request_opcode::get': key_request
            'request_opcode::get_with_metadata': key_request
            'request_opcode::contains_key': key_request
            'request_opcode::remove': key_request
            'request_opcode::bulk_get': bulk_get_request
            'request_opcode::put_all': put_all_request
            'request_opcode::get_all': get_all_request
            'request_opcode::query': query_request
            'request_opcode::auth': auth_request
            'request_opcode::exec': exec_request
            'request_opcode::iteration_start': iteration_start_request
            'request_opcode::iteration_next': iteration_next_or_end_request
            'request_opcode::iteration_end': iteration_next_or_end_request
            'request_opcode::add_client_listener': add_listener_request
            'request_opcode::remove_client_listener': remove_listener_request
            'request_opcode::add_bloom_filter_listener': bloom_filter_listener_request
            'request_opcode::update_bloom_filter': update_bloom_filter_request
            'request_opcode::get_stream_start': get_stream_start_request
            'request_opcode::get_stream_next': get_stream_next_request
            'request_opcode::get_stream_end': get_stream_end_request
            'request_opcode::put_stream_start': put_stream_start_request
            'request_opcode::put_stream_next': put_stream_next_request
            'request_opcode::put_stream_end': put_stream_end_request
            'request_opcode::commit': tx_commit_or_rollback_request
            'request_opcode::rollback': tx_commit_or_rollback_request
            'request_opcode::forget_tx': forget_tx_request
            'request_opcode::counter_create': counter_create_request
            'request_opcode::counter_get_value': counter_name_request
            'request_opcode::counter_reset': counter_name_request
            'request_opcode::counter_add_and_get': counter_add_and_get_request
            'request_opcode::counter_cas': counter_cas_request
            'request_opcode::counter_is_defined': counter_name_request
            'request_opcode::counter_remove': counter_name_request
            'request_opcode::counter_get_configuration': counter_name_request
            'request_opcode::counter_get_and_set': counter_get_and_set_request
            'request_opcode::prepare_v2': prepare_request_v2
            'request_opcode::multimap_get': multimap_get_request
            'request_opcode::multimap_get_with_metadata': multimap_get_request
            'request_opcode::multimap_put': multimap_put_request
            'request_opcode::multimap_remove_key': multimap_get_request
            'request_opcode::multimap_remove_entry': multimap_put_request
            'request_opcode::multimap_size': multimap_size_request
            'request_opcode::multimap_contains_key': multimap_get_request
            'request_opcode::multimap_contains_value': multimap_contains_value_request
            'request_opcode::multimap_contains_entry': multimap_contains_entry_request
        if: |
          header.opcode != request_opcode::ping and
          header.opcode != request_opcode::clear and
          header.opcode != request_opcode::stats and
          header.opcode != request_opcode::size and
          header.opcode != request_opcode::auth_mech_list and
          header.opcode != request_opcode::bulk_get_keys and
          header.opcode != request_opcode::prepare and
          header.opcode != request_opcode::fetch_in_doubt_tx and
          header.opcode != request_opcode::counter_add_listener and
          header.opcode != request_opcode::counter_remove_listener

  response_message:
    seq:
      - id: header
        type: response_header
      - id: body
        type:
          switch-on: header.opcode
          cases:
            'response_opcode::get': get_response
            'response_opcode::get_with_metadata': get_with_metadata_response
            'response_opcode::put': put_response
            'response_opcode::put_if_absent': put_response
            'response_opcode::replace': put_response
            'response_opcode::replace_if_unmodified': put_response
            'response_opcode::remove': put_response
            'response_opcode::remove_if_unmodified': put_response
            'response_opcode::bulk_get': bulk_get_response
            'response_opcode::get_all': get_all_response
            'response_opcode::query': query_response
            'response_opcode::exec': exec_response
            'response_opcode::auth_mech_list': auth_mech_list_response
            'response_opcode::auth': auth_response
            'response_opcode::iteration_start': iteration_start_response
            'response_opcode::iteration_next': iteration_next_response
            'response_opcode::get_stream_start': get_stream_start_response
            'response_opcode::get_stream_next': get_stream_next_response
            'response_opcode::put_stream_start': put_stream_start_response
            'response_opcode::prepare': tx_response
            'response_opcode::prepare_v2': tx_response
            'response_opcode::commit': tx_response
            'response_opcode::rollback': tx_response
            'response_opcode::fetch_tx_recovery': fetch_in_doubt_response
            'response_opcode::counter_get_configuration': counter_get_configuration_response
            'response_opcode::counter_get_value': counter_value_response
            'response_opcode::counter_add_and_get': counter_value_response
            'response_opcode::counter_cas': counter_value_response
            'response_opcode::counter_get_and_set': counter_value_response
            'response_opcode::counter_get_names': counter_get_names_response
            'response_opcode::ping': ping_response
            'response_opcode::stats': stats_response
            'response_opcode::size': size_response
            'response_opcode::error': error_response
            'response_opcode::cache_entry_created_event': cache_entry_created_event
            'response_opcode::cache_entry_modified_event': cache_entry_modified_event
            'response_opcode::cache_entry_removed_event': cache_entry_removed_event
            'response_opcode::cache_entry_expired_event': cache_entry_expired_event
            'response_opcode::multimap_get': multimap_get_response
            'response_opcode::multimap_get_with_metadata': multimap_get_with_metadata_response
            'response_opcode::multimap_size': multimap_size_response
            'response_opcode::multimap_remove_key': multimap_contains_response
            'response_opcode::multimap_remove_entry': multimap_contains_response
            'response_opcode::multimap_contains_entry': multimap_contains_response
            'response_opcode::multimap_contains_key': multimap_contains_response
            'response_opcode::multimap_contains_value': multimap_contains_response
        if: |
          header.opcode != response_opcode::contains_key and
          header.opcode != response_opcode::clear and
          header.opcode != response_opcode::add_client_listener and
          header.opcode != response_opcode::remove_client_listener and
          header.opcode != response_opcode::add_bloom_filter_listener and
          header.opcode != response_opcode::update_bloom_filter and
          header.opcode != response_opcode::counter_create and
          header.opcode != response_opcode::counter_reset and
          header.opcode != response_opcode::counter_remove and
          header.opcode != response_opcode::iteration_end and
          header.opcode != response_opcode::get_stream_end and
          header.opcode != response_opcode::put_stream_end and
          header.opcode != response_opcode::put_stream_next and
          header.opcode != response_opcode::counter_event and
          header.opcode != response_opcode::counter_is_defined and
          header.opcode != response_opcode::forget_tx and
          header.opcode != response_opcode::multimap_put


  # ============================================================================
  # Fundamental Types
  # ============================================================================
  
  # Variable-length unsigned integer (1-5 bytes).
  # High bit of each byte indicates continuation.
  # Identical to protobuf varint32.
  vint:
    seq:
      - id: groups
        type: vint_group
        repeat: until
        repeat-until: not _.has_more
    instances:
      value:
        value: >-
          groups[0].value
          + (groups.size > 1 ? (groups[1].value << 7) : 0)
          + (groups.size > 2 ? (groups[2].value << 14) : 0)
          + (groups.size > 3 ? (groups[3].value << 21) : 0)
          + (groups.size > 4 ? (groups[4].value << 28) : 0)

  vint_group:
    seq:
      - id: b
        type: u1
    instances:
      has_more:
        value: (b & 0x80) != 0
      value:
        value: b & 0x7F

  # Variable-length signed integer (1-5 bytes).
  # ZigZag encoding
  # Identical to protobuf varint32.
  signed_vint:
    seq:
      - id: groups
        type: vint_group
        repeat: until
        repeat-until: not _.has_more
    instances:
      value:
        value: >-
          groups[0].value
          + (groups.size > 1 ? (groups[1].value << 7) : 0)
          + (groups.size > 2 ? (groups[2].value << 14) : 0)
          + (groups.size > 3 ? (groups[3].value << 21) : 0)
          + (groups.size > 4 ? (groups[4].value << 28) : 0)
      signed:
        value: (value >> 1) ^ -(value & 1)

  # Variable-length unsigned long (1-9 bytes).
  # Same encoding as vint but extended to 64-bit values.
  vlong:
    seq:
      - id: groups
        type: vint_group
        repeat: until
        repeat-until: not _.has_more
    instances:
      value:
        value: >-
          groups[0].value
          + (groups.size > 1 ? (groups[1].value << 7) : 0)
          + (groups.size > 2 ? (groups[2].value << 14) : 0)
          + (groups.size > 3 ? (groups[3].value << 21) : 0)
          + (groups.size > 4 ? (groups[4].value << 28) : 0)
          + (groups.size > 5 ? (groups[5].value << 35) : 0)
          + (groups.size > 6 ? (groups[6].value << 42) : 0)
          + (groups.size > 7 ? (groups[7].value << 49) : 0)
          + (groups.size > 8 ? (groups[8].value << 56) : 0)

  # A length-prefixed byte array: vInt length followed by that many bytes.
  lp_bytes:
    seq:
      - id: length
        type: vint
      - id: data
        size: length.value

  # A length-prefixed UTF-8 string: vInt length followed by UTF-8 bytes.
  lp_string:
    seq:
      - id: length
        type: vint
      - id: data
        type: str
        encoding: UTF-8
        size: length.value

  # ============================================================================
  # MediaType Encoding (Protocol 2.8+)
  # ============================================================================
  
  # MediaType descriptor used in request headers since protocol 2.8.
  media_type:
    seq:
      - id: type_indicator
        type: u1
        enum: media_type_kind
      - id: predefined_id
        type: vint
        enum: predefined_media_type_id
        if: type_indicator == media_type_kind::predefined
      - id: custom_string
        type: lp_string
        if: type_indicator == media_type_kind::custom
      - id: param_count
        type: vint
        if: type_indicator == media_type_kind::predefined or type_indicator == media_type_kind::custom
      - id: params
        type: media_type_param
        repeat: expr
        repeat-expr: param_count.value
        if: (type_indicator == media_type_kind::predefined or type_indicator == media_type_kind::custom) and param_count.value > 0

  media_type_param:
    seq:
      - id: key
        type: lp_string
      - id: value
        type: lp_string

  other_param:
    seq:
      - id: key
        type: lp_string
      - id: value
        type: lp_bytes

  # ============================================================================
  # Request Header (Protocol 4.1)
  # ============================================================================
  
  # Full request header for protocol versions >= 2.8 (with MediaType support).
  request_header:
    seq:
        # Expected: 0xA0
      - id: message_id
        type: vlong
      - id: version
        type: u1
        # 40 for protocol 4.0, 41 for protocol 4.1
      - id: opcode
        type: u1
        enum: request_opcode
      - id: cache_name_length
        type: vint
      - id: cache_name
        type: str
        encoding: UTF-8
        size: cache_name_length.value
      - id: flags
        type: vint
      - id: client_intelligence
        type: u1
        enum: client_intelligence_type
      - id: topology_id
        type: vint
      # MediaType fields added in protocol 2.8
      - id: key_media_type
        type: media_type
        if: version >= 28
      - id: value_media_type
        type: media_type
        if: version >= 28
      # Other params added in protocol 4.0
      - id: other_param_count
        type: vint
        if: version >= 40
      - id: other_params
        type: other_param
        repeat: expr
        repeat-expr: other_param_count.value
        if: version >= 40 and other_param_count.value > 0

  # ============================================================================
  # Response Header
  # ============================================================================
  
  response_header:
    seq:
      - id: message_id
        type: vlong
      - id: opcode
        type: u1
        enum: response_opcode
      - id: status
        type: u1
        enum: response_status
        if: |
          opcode != response_opcode::cache_entry_created_event and
          opcode != response_opcode::cache_entry_modified_event and
          opcode != response_opcode::cache_entry_removed_event and
          opcode != response_opcode::cache_entry_expired_event
      - id: topology_change_marker
        type: u1
        if: |
          opcode != response_opcode::cache_entry_created_event and
          opcode != response_opcode::cache_entry_modified_event and
          opcode != response_opcode::cache_entry_removed_event and
          opcode != response_opcode::cache_entry_expired_event
      - id: topology_change
        type: topology_change_header
        if: |
          (opcode != response_opcode::cache_entry_created_event and
           opcode != response_opcode::cache_entry_modified_event and
           opcode != response_opcode::cache_entry_removed_event and
           opcode != response_opcode::cache_entry_expired_event) and
          topology_change_marker != 0
    instances:
      has_previous:
        value: |
          status == response_status::success_with_previous or
          status == response_status::not_executed_with_previous

  # ============================================================================
  # Topology Change Headers
  # ============================================================================
  
  # Topology-aware topology change (client intelligence 0x02)
  topology_aware_header:
    seq:
      - id: topology_id
        type: vint
      - id: num_servers
        type: vint
      - id: servers
        type: server_address
        repeat: expr
        repeat-expr: num_servers.value

  server_address:
    seq:
      - id: host
        type: lp_string
      - id: port
        type: u2

  # Hash-distribution-aware topology change (client intelligence 0x03, protocol >= 2.0)
  hash_dist_header_v2:
    seq:
      - id: topology_id
        type: vint
      - id: num_servers
        type: vint
      - id: servers
        type: server_address
        repeat: expr
        repeat-expr: num_servers.value
      - id: hash_function_version
        type: u1
      - id: num_segments
        type: vint
      - id: segments
        type: segment_owners
        repeat: expr
        repeat-expr: num_segments.value

  segment_owners:
    seq:
      - id: num_owners
        type: u1
      - id: owner_indices
        type: u1
        repeat: expr
        repeat-expr: num_owners

  # Generic topology change header - dispatches based on client intelligence.
  #
  # CRITICAL LIMITATION: The actual response format depends on the client_intelligence
  # value sent in the REQUEST header, but the RESPONSE does not indicate which
  # intelligence level was used. The format is:
  #   - Intelligence 0x01 (BASIC): No topology change info at all
  #   - Intelligence 0x02 (TOPOLOGY_AWARE): Only topology_id + servers
  #   - Intelligence 0x03 (HASH_DISTRIBUTION_AWARE): Full format with segments
  #
  # ⚠️  THIS SCHEMA ASSUMES INTELLIGENCE 0x03 (HASH_DISTRIBUTION_AWARE) ⚠️
  #
  # If you are parsing responses from intelligence 0x02 clients, this schema
  # will FAIL because it expects hash_function_version and segments after the
  # servers, but 0x02 responses go directly to the operation body.
  #
  # There is NO reliable way to auto-detect the intelligence level from the
  # response bytes alone. You must know which intelligence level your client used.
  #
  # For intelligence 0x02 support, use topology_aware_header type instead,
  # or create a custom parser that knows the client intelligence level.
  topology_change_header:
    seq:
      - id: topology_id
        type: vint
      - id: num_servers
        type: vint
      - id: servers
        type: server_address
        repeat: expr
        repeat-expr: num_servers.value
      # Fields below only present for HASH_DISTRIBUTION_AWARE (0x03)
      - id: hash_function_version
        type: u1
      - id: num_segments
        type: vint
      - id: segments
        type: segment_owners
        repeat: expr
        repeat-expr: num_segments.value

  # ============================================================================
  # Entry Metadata (Protocol 4.0+)
  # ============================================================================

  # Metadata block returned with previous values since protocol 4.0,
  # and with GetWithMetadata/GetStream responses since protocol 1.2.
  #
  # IMPORTANT: In protocol 3.x, PUT/REPLACE/REMOVE responses with previous
  # values return ONLY the value (no metadata). In protocol 4.x, they return
  # this metadata structure followed by the value.
  entry_metadata:
    seq:
      - id: flag
        type: u1
        # Bitwise OR of: 0x01 = INFINITE_LIFESPAN, 0x02 = INFINITE_MAXIDLE
      - id: created
        type: s8
        if: (flag & 0x01) == 0
      - id: lifespan
        type: vint
        if: (flag & 0x01) == 0
      - id: last_used
        type: s8
        if: (flag & 0x02) == 0
      - id: max_idle
        type: vint
        if: (flag & 0x02) == 0
      - id: entry_version
        type: s8

  # Expiration parameters used in PUT/REPLACE operations.
  # Encodes lifespan and maxIdle with their time units in a single byte,
  # followed by optional vlong values if not default/infinite.
  expiration_params:
    seq:
      - id: time_units
        type: u1
        # High nibble: lifespan time unit, Low nibble: maxIdle time unit
        # 0x0-0x6 = specific time unit (SECONDS, MILLIS, NANOS, MICROS, MINUTES, HOURS, DAYS)
        # 0x7 = DEFAULT (use server default)
        # 0x8 = INFINITE
      - id: lifespan
        type: vlong
        if: (time_units >> 4) != 0x07 and (time_units >> 4) != 0x08
      - id: max_idle
        type: vlong
        if: (time_units & 0x0F) != 0x07 and (time_units & 0x0F) != 0x08

  # ============================================================================
  # Operations
  # ============================================================================
  
  # --- Key-only request body (Get, Remove, ContainsKey, GetWithVersion) ---
  key_request:
    seq:
      - id: key
        type: lp_bytes

  # --- Put/Replace/PutIfAbsent request body (protocol >= 2.2 with TimeUnits) ---
  put_request:
    seq:
      - id: key
        type: lp_bytes
      - id: time_units
        type: u1
        # High nibble (bits 4-7): lifespan time unit, Low nibble (bits 0-3): maxIdle time unit
      - id: lifespan
        type: vlong
        if: (time_units >> 4) < 0x07
      - id: max_idle
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: value
        type: lp_bytes

  # --- Multimap Put request body (0x6B) ---
  multimap_put_request:
    seq:
      - id: key
        type: lp_bytes
      - id: time_units
        type: u1
      - id: lifespan
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: max_idle
        type: vlong
        if: ((time_units >> 4) & 0x0F) < 0x07
      - id: value
        type: lp_bytes
      - id: support_duplicates
        type: u1

  # --- ReplaceIfUnmodified request body ---
  replace_if_unmodified_request:
    seq:
      - id: key
        type: lp_bytes
      - id: time_units
        type: u1
      - id: lifespan
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: max_idle
        type: vlong
        if: ((time_units >> 4) & 0x0F) < 0x07
      - id: entry_version
        type: s8
      - id: value
        type: lp_bytes

  # --- RemoveIfUnmodified request body ---
  remove_if_unmodified_request:
    seq:
      - id: key
        type: lp_bytes
      - id: entry_version
        type: s8

  # --- Get response (0x04) ---
  get_response:
    seq:
      - id: value
        type: lp_bytes
        if: _parent.header.status == response_status::success

  # --- GetWithMetadata response (0x1C) ---
  get_with_metadata_response:
    seq:
      - id: metadata
        type: entry_metadata
        if: _parent.header.status == response_status::success
      - id: value
        type: lp_bytes
        if: _parent.header.status == response_status::success

  # --- Put/Remove/Replace response with metadata (protocol 4.0+) ---
  # Returned when status indicates previous value present (0x03 or 0x04).
  #
  # Protocol 3.x difference: In 3.x, only the value is returned (no metadata).
  # Protocol 4.x: Returns metadata + value for operations:
  #   - put, putIfAbsent, replace, replaceIfUnmodified
  #   - remove, removeIfUnmodified
  previous_value_with_metadata:
    seq:
      - id: metadata
        type: entry_metadata
      - id: value
        type: lp_bytes

  # --- Put/Replace/PutIfAbsent response ---
  # Protocol 4.x: Returns metadata + value when there's a previous value
  put_response:
    seq:
      - id: previous_value_with_metadata
        type: previous_value_with_metadata
        if: _parent.header.has_previous

# --- BulkGet response (0x05) ---
  bulk_get_response:
    seq:
      - id: entries
        type: bulk_arrays
        if: _parent.header.status == response_status::success

  chunk:
    seq:
      - id: more
        type: u1
      - id: value
        type: lp_bytes
        if: more != 0

  bulk_arrays:
    seq:
      - id: chunks
        type: chunk
        repeat: until
        repeat-until: _.more == 0

  # --- Exec response 0x2C ---
  exec_response:
    seq:
      - id: value
        type: lp_bytes
        if: _parent.header.status == response_status::success

  # --- Error response (0x50) ---
  # Contains error message for all error status codes
  error_response:
    seq:
      - id: error_message
        type: lp_string

  # --- PutAll request ---
  put_all_request:
    seq:
      - id: time_units
        type: u1
        # High nibble: lifespan time unit, Low nibble: maxIdle time unit
      - id: lifespan
        type: vlong
        if: (time_units >> 4) < 0x07
      - id: max_idle
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: entry_count
        type: vint
      - id: entries
        type: key_value_pair
        repeat: expr
        repeat-expr: entry_count.value

  key_value_pair:
    seq:
      - id: key
        type: lp_bytes
      - id: value
        type: lp_bytes

  # --- GetAll request ---
  get_all_request:
    seq:
      - id: key_count
        type: vint
      - id: keys
        type: lp_bytes
        repeat: expr
        repeat-expr: key_count.value

  # --- GetAll response ---
  get_all_response:
    seq:
      - id: entry_count
        type: vint
      - id: entries
        type: key_value_pair
        repeat: expr
        repeat-expr: entry_count.value

  # --- Stats response ---
  stats_response:
    seq:
      - id: num_stats
        type: vint
      - id: stats
        type: stat_entry
        repeat: expr
        repeat-expr: num_stats.value

  stat_entry:
    seq:
      - id: name
        type: lp_string
      - id: value
        type: lp_string

  # --- Query request (0x1F) ---
  query_request:
    seq:
      - id: query_payload
        type: lp_bytes

  # --- Query response (0x20) ---
  query_response:
    seq:
      - id: response_payload
        type: lp_bytes

  # --- Size response (0x2A) ---
  size_response:
    seq:
      - id: size
        type: vint

  # --- Exec request (0x2B) ---
  exec_request:
    seq:
      - id: script_name
        type: lp_string
      - id: param_count
        type: vint
      - id: params
        type: exec_param
        repeat: expr
        repeat-expr: param_count.value

  exec_param:
    seq:
      - id: name
        type: lp_string
      - id: value
        type: lp_bytes

  # --- Auth mech list response (0x22) ---
  auth_mech_list_response:
    seq:
      - id: mech_count
        type: vint
      - id: mechs
        type: lp_string
        repeat: expr
        repeat-expr: mech_count.value

  # --- Auth request (0x23) ---
  auth_request:
    seq:
      - id: mech
        type: lp_string
      - id: response_data
        type: lp_bytes

  # --- Auth response (0x24) ---
  auth_response:
    seq:
      - id: completed
        type: u1
      - id: challenge_data
        type: lp_bytes

  # --- Iteration Start request (0x31, protocol >= 2.5) ---
  iteration_start_request:
    seq:
      - id: segments_size
        type: signed_vint
        # Signed: -1 means no segment filtering
      - id: segments
        size: segments_size.signed
        if: segments_size.signed > 0
      - id: filter_converter_size
        type: signed_vint
        # Signed: -1 means no filter
      - id: filter_converter
        type: str
        encoding: UTF-8
        size: filter_converter_size.signed
        if: filter_converter_size.signed >= 0
      - id: param_count
        type: u1
        if: filter_converter_size.signed >= 0
      - id: params
        type: lp_bytes
        repeat: expr
        repeat-expr: param_count
        if: filter_converter_size.signed >= 0 and param_count > 0
      - id: batch_size
        type: vint
      - id: metadata
        type: u1
        # 1 = return metadata, 0 = no metadata

  # --- Iteration Start response (0x32, protocol >= 2.5) ---
  iteration_start_response:
   seq:
      - id: iteration_id
        type: lp_bytes

  # --- Iteration Next request (0x33) ---
  iteration_next_or_end_request:
    seq:
      - id: iteration_id
        type: lp_bytes

  # --- Iteration Next response (0x34) ---
  iteration_next_response:
    seq:
      - id: finished_segments_size
        type: vint
      - id: finished_segments
        size: finished_segments_size.value
      - id: entry_count
        type: vint
      - id: num_value_projections
        type: vint
        if: entry_count.value > 0
      - id: entries
        type: iteration_entry
        repeat: expr
        repeat-expr: entry_count.value

  # --- Iteration Entry (used in iteration_next_response) ---
  iteration_entry:
    seq:
      - id: metadata_present
        type: u1
        # 1 if metadata is present, 0 otherwise (protocol 2.5+)
      - id: metadata
        type: iteration_entry_metadata
        if: metadata_present == 1
      - id: key
        type: lp_bytes
      - id: values
        type: lp_bytes
        repeat: expr
        repeat-expr: _parent.num_value_projections.value

  # --- Iteration Entry Metadata (Protocol 2.5+) ---
  # Similar to entry_metadata but with different structure for iteration responses.
  # This metadata format is used in iteration responses across both 3.x and 4.x protocols.
  #
  # Note: iteration_entry has metadata_present flag to indicate presence,
  # while entry_metadata (used in PUT responses) does not have such a flag.
  iteration_entry_metadata:
    seq:
      - id: expiration_flag
        type: u1
        # Bitwise OR of: 0x01 = INFINITE_LIFESPAN, 0x02 = INFINITE_MAXIDLE
      - id: created
        type: s8
        if: (expiration_flag & 0x01) == 0
      - id: lifespan
        type: vint
        if: (expiration_flag & 0x01) == 0
      - id: last_used
        type: s8
        if: (expiration_flag & 0x02) == 0
      - id: max_idle
        type: vint
        if: (expiration_flag & 0x02) == 0
      - id: entry_version
        type: s8

  # --- BulkGet request (0x19) ---
  bulk_get_request:
    seq:
      - id: entry_count
        type: vint
        # 0 = return all entries

  # --- GetStreamStart request (0xE9, protocol 4.1) ---
  get_stream_start_request:
    seq:
      - id: key
        type: lp_bytes
      - id: batch_size
        type: vint

  # --- GetStreamStart response (0xE8) ---
  get_stream_start_response:
    seq:
      - id: stream_id
        type: s4
        if: _parent.header.status == response_status::success
      - id: complete
        type: u1
        if: _parent.header.status == response_status::success
      - id: metadata
        type: entry_metadata
        if: _parent.header.status == response_status::success
      - id: value
        type: lp_bytes
        if: _parent.header.status == response_status::success

  # --- GetStreamNext request (0xE7) ---
  get_stream_next_request:
    seq:
      - id: stream_id
        type: s4

  # --- GetStreamNext response (0xE6) ---
  get_stream_next_response:
    seq:
      - id: stream_id
        type: s4
        if: _parent.header.status == response_status::success
      - id: complete
        type: u1
        if: _parent.header.status == response_status::success
      - id: value
        type: lp_bytes
        if: _parent.header.status == response_status::success

  # --- GetStreamEnd request (0xE4) ---
  get_stream_end_request:
    seq:
      - id: stream_id
        type: s4

  # --- PutStreamStart request (0xEF) ---
  put_stream_start_request:
    seq:
      - id: key
        type: lp_bytes
      - id: expiration
        type: expiration_params
      - id: condition_version
        type: s8
        # 0 = unconditional, -1 = put-if-absent, other = conditional replace

  # --- PutStreamStart response (0xEE) ---
  put_stream_start_response:
    seq:
      - id: stream_id
        type: s4

  # --- PutStreamNext request (0xED) ---
  put_stream_next_request:
    seq:
      - id: stream_id
        type: s4
      - id: complete
        type: u1
      - id: chunk
        type: lp_bytes

  # --- PutStreamEnd request (0xEB) ---
  put_stream_end_request:
    seq:
      - id: stream_id
        type: s4

  # --- Add Client Listener request (0x25, protocol >= 2.6) ---
  add_listener_request:
    seq:
      - id: listener_id
        type: lp_bytes
      - id: include_state
        type: u1
      - id: filter_factory_name
        type: lp_string
      - id: filter_factory_params
        type: listener_factory_params
        if: filter_factory_name.length.value > 0
      - id: converter_factory_name
        type: lp_string
      - id: converter_factory_params
        type: listener_factory_params
        if: converter_factory_name.length.value > 0
      - id: use_raw_data
        type: u1
      - id: event_type_interests
        type: vint
        # Bitmask: 0x01=created, 0x02=modified, 0x04=removed, 0x08=expired

  listener_factory_params:
    seq:
      - id: param_count
        type: u1
      - id: params
        type: lp_bytes
        repeat: expr
        repeat-expr: param_count

  # --- Remove Client Listener request (0x27) ---
  remove_listener_request:
    seq:
      - id: listener_id
        type: lp_bytes

  # --- Bloom Filter Listener request (0x41, protocol 3.1) ---
  bloom_filter_listener_request:
    seq:
      - id: listener_id
        type: lp_bytes
      - id: bloom_filter_bit_size
        type: vint

  # --- Update Bloom Filter request (0x42) ---
  update_bloom_filter_request:
    seq:
      - id: bloom_filter_bits
        type: lp_bytes

  # --- Cache Entry Event (sent by server, protocol 2.1+) ---
  # custom_marker: 0=normal event, 1=custom marshalled object, 2=raw custom data
  cache_entry_created_event:
    seq:
      - id: status
        type: u1
      - id: topology_change_marker
        type: u1
      - id: listener_id
        type: lp_bytes
      - id: custom_marker
        type: u1
      - id: command_retried
        type: u1
      - id: custom_data
        type: lp_bytes
        if: custom_marker == 1 or custom_marker == 2
      - id: key
        type: lp_bytes
        if: custom_marker == 0
      - id: version
        type: s8
        if: custom_marker == 0

  cache_entry_modified_event:
    seq:
      - id: status
        type: u1
      - id: topology_change_marker
        type: u1
      - id: listener_id
        type: lp_bytes
      - id: custom_marker
        type: u1
      - id: command_retried
        type: u1
      - id: custom_data
        type: lp_bytes
        if: custom_marker == 1 or custom_marker == 2
      - id: key
        type: lp_bytes
        if: custom_marker == 0
      - id: version
        type: s8
        if: custom_marker == 0

  cache_entry_removed_event:
    seq:
      - id: status
        type: u1
      - id: topology_change_marker
        type: u1
      - id: listener_id
        type: lp_bytes
      - id: custom_marker
        type: u1
      - id: command_retried
        type: u1
      - id: custom_data
        type: lp_bytes
        if: custom_marker == 1 or custom_marker == 2
      - id: key
        type: lp_bytes
        if: custom_marker == 0

  cache_entry_expired_event:
    seq:
      - id: status
        type: u1
      - id: topology_change_marker
        type: u1
      - id: listener_id
        type: lp_bytes
      - id: custom_marker
        type: u1
      - id: command_retried
        type: u1
      - id: custom_data
        type: lp_bytes
        if: custom_marker == 1 or custom_marker == 2
      - id: key
        type: lp_bytes
        if: custom_marker == 0

  # --- XID (X/Open XA Transaction ID) ---
  xid:
    seq:
      - id: format_id
        type: vint
        # Signed vInt (ZigZag encoded)
      - id: global_tx_id_length
        type: u1
      - id: global_tx_id
        size: global_tx_id_length
      - id: branch_qualifier_length
        type: u1
      - id: branch_qualifier
        size: branch_qualifier_length

  # --- Transaction Prepare request (0x7D, protocol >= 2.9) ---
  prepare_request_v2:
    seq:
      - id: transaction_id
        type: xid
      - id: one_phase_commit
        type: u1
      - id: recoverable
        type: u1
      - id: timeout
        type: s8
      - id: num_keys
        type: vint
      - id: keys
        type: tx_write_entry
        repeat: expr
        repeat-expr: num_keys.value

  tx_write_entry:
    seq:
      - id: key
        type: lp_bytes
      - id: control_byte
        type: u1
        # 0x01 = NOT_READ, 0x02 = NON_EXISTING, 0x04 = REMOVE_OPERATION
      - id: version_read
        type: s8
        if: (control_byte & 0x01) == 0 and (control_byte & 0x02) == 0
      - id: time_units
        type: u1
        if: (control_byte & 0x04) == 0
      - id: lifespan
        type: vlong
        if: (control_byte & 0x04) == 0 and (time_units & 0x0F) < 0x07
      - id: max_idle
        type: vlong
        if: (control_byte & 0x04) == 0 and ((time_units >> 4) & 0x0F) < 0x07
      - id: value
        type: lp_bytes
        if: (control_byte & 0x04) == 0

  # --- Transaction Commit/Rollback request ---
  tx_commit_or_rollback_request:
    seq:
      - id: transaction_id
        type: xid

  # --- Transaction Prepare/Commit/Rollback response ---
  tx_response:
    seq:
      - id: xa_return_code
        type: s4
        # XA_OK=0, XA_RDONLY=3, or XA error codes

  # --- Forget Transaction request (0x79) ---
  forget_tx_request:
    seq:
      - id: transaction_id
        type: xid

  # --- Fetch In-Doubt Transactions response (0x7C) ---
  fetch_in_doubt_response:
    seq:
      - id: num_xids
        type: vint
      - id: xids
        type: xid
        repeat: expr
        repeat-expr: num_xids.value

  # --- Counter Configuration ---
  counter_configuration:
    seq:
      - id: flags
        type: u1
        # Bit 0: 1=WEAK, 0=STRONG
        # Bit 1: 1=BOUNDED, 0=UNBOUNDED
        # Bit 2: 1=PERSISTENT, 0=VOLATILE
      - id: concurrency_level
        type: vint
        if: (flags & 0x01) != 0
      - id: lower_bound
        type: s8
        if: (flags & 0x02) != 0
      - id: upper_bound
        type: s8
        if: (flags & 0x02) != 0
      - id: initial_value
        type: s8

  # --- Counter Create request (0x4B) ---
  counter_create_request:
    seq:
      - id: name
        type: lp_string
      - id: configuration
        type: counter_configuration

  # --- Counter Get/Set/Add/Reset/Remove request ---
  counter_name_request:
    seq:
      - id: name
        type: lp_string

  # --- Counter Add-And-Get request (0x52) ---
  counter_add_and_get_request:
    seq:
      - id: name
        type: lp_string
      - id: delta
        type: s8

  # --- Counter Compare-And-Swap request (0x58) ---
  counter_cas_request:
    seq:
      - id: name
        type: lp_string
      - id: expect
        type: s8
      - id: update
        type: s8

  # --- Counter Get-And-Set request (0x7F, protocol 3.1) ---
  counter_get_and_set_request:
    seq:
      - id: name
        type: lp_string
      - id: value
        type: s8

  # --- Counter value response ---
  counter_value_response:
    seq:
      - id: value
        type: s8

  # --- Counter Get Names response (0x65) ---
  counter_get_names_response:
    seq:
      - id: count
        type: vint
        if: _parent.header.status == response_status::success
      - id: names
        type: lp_string
        repeat: expr
        repeat-expr: count.value
        if: _parent.header.status == response_status::success

  # --- Counter Get Configuration response (0x4E) ---
  counter_get_configuration_response:
    seq:
      - id: configuration
        type: counter_configuration
        if: _parent.header.status == response_status::success

  # --- Ping response (0x18, protocol >= 3.0) ---
  # Protocol 3.0+ added MediaType info and supported operations list.
  # Earlier protocols had no body (header only).
  ping_response:
    seq:
      - id: key_type
        type: media_type
      - id: value_type
        type: media_type
      - id: server_version
        type: u1
      - id: op_count
        type: vint
      - id: supported_opcodes
        type: u2
        repeat: expr
        repeat-expr: op_count.value

  # --- Multimap Get request (0x67) ---
  multimap_get_request:
    seq:
      - id: key
        type: lp_bytes
      - id: support_duplicates
        type: u1

  # --- Multimap Get response (0x68) ---
  multimap_get_response:
    seq:
      - id: value_count
        type: vint
        if: _parent.header.status == response_status::success
      - id: values
        type: lp_bytes
        repeat: expr
        repeat-expr: value_count.value
        if: _parent.header.status == response_status::success

  # --- Multimap Get with Metadata response (0x6A) ---
  multimap_get_with_metadata_response:
    seq:
      - id: metadata
        type: entry_metadata
        if: _parent.header.status == response_status::success
      - id: value_count
        type: vint
        if: _parent.header.status == response_status::success
      - id: values
        type: lp_bytes
        repeat: expr
        repeat-expr: value_count.value
        if: _parent.header.status == response_status::success

  # --- Multimap Size request (0x71) ---
  multimap_size_request:
    seq:
      - id: support_duplicates
        type: u1

  # --- Multimap Size response (0x72) ---
  multimap_size_response:
    seq:
      - id: size
        type: vlong
        if: _parent.header.status == response_status::success

  # --- Multimap Contains Value request (0x77) ---
  multimap_contains_value_request:
    seq:
      - id: time_units
        type: u1
        # High nibble (bits 4-7): lifespan time unit, Low nibble (bits 0-3): maxIdle time unit
      - id: lifespan
        type: vlong
        if: (time_units >> 4) < 0x07
      - id: max_idle
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: value
        type: lp_bytes
      - id: support_duplicates
        type: u1

  # --- Multimap Contains Entry request (0x73) ---
  multimap_contains_entry_request:
    seq:
      - id: key
        type: lp_bytes
      - id: time_units
        type: u1
        # High nibble (bits 4-7): lifespan time unit, Low nibble (bits 0-3): maxIdle time unit
      - id: lifespan
        type: vlong
        if: (time_units >> 4) < 0x07
      - id: max_idle
        type: vlong
        if: (time_units & 0x0F) < 0x07
      - id: value
        type: lp_bytes
      - id: support_duplicates
        type: u1

  # --- Multimap Boolean responses (0x6C, 0x6E, 0x70, 0x74, 0x76, 0x78) ---
  # These operations return success/failure status only (no body):
  # - PUT (0x6C)
  # - REMOVE_KEY (0x6E)
  # - REMOVE_ENTRY (0x70)
  # All "contains" operations return a boolean in the body:
  # - CONTAINS_ENTRY (0x74)
  # - CONTAINS_KEY (0x76)
  # - CONTAINS_VALUE (0x78)
  multimap_contains_response:
    seq:
      - id: result
        type: u1
        if: _parent.header.status == response_status::success
        # 1 = true, 0 = false

# ============================================================================
# Enums
# ============================================================================

enums:
  request_opcode:
    0x01: put
    0x03: get
    0x05: put_if_absent
    0x07: replace
    0x09: replace_if_unmodified
    0x0B: remove
    0x0D: remove_if_unmodified
    0x0F: contains_key
    0x11: get_with_version # deprecated
    0x13: clear
    0x15: stats
    0x17: ping
    0x19: bulk_get
    0x1B: get_with_metadata
    0x1D: bulk_get_keys
    0x1F: query
    0x21: auth_mech_list
    0x23: auth
    0x25: add_client_listener
    0x27: remove_client_listener
    0x29: size
    0x2B: exec
    0x2D: put_all
    0x2F: get_all
    0x31: iteration_start
    0x33: iteration_next
    0x35: iteration_end
    0x3B: prepare
    0x3D: commit
    0x3F: rollback
    0x41: add_bloom_filter_listener
    0x43: update_bloom_filter
    0x4B: counter_create
    0x4D: counter_get_configuration
    0x4F: counter_is_defined
    0x52: counter_add_and_get
    0x54: counter_reset
    0x56: counter_get_value
    0x58: counter_cas
    0x5A: counter_add_listener
    0x5C: counter_remove_listener
    0x5E: counter_remove
    0x67: multimap_get
    0x69: multimap_get_with_metadata
    0x6B: multimap_put
    0x6D: multimap_remove_key
    0x6F: multimap_remove_entry
    0x71: multimap_size
    0x73: multimap_contains_entry
    0x75: multimap_contains_key
    0x77: multimap_contains_value
    0x79: forget_tx
    0x7B: fetch_in_doubt_tx
    0x7D: prepare_v2
    0x7F: counter_get_and_set
    0xE5: get_stream_end
    0xE7: get_stream_next
    0xE9: get_stream_start
    0xEB: put_stream_end
    0xED: put_stream_next
    0xEF: put_stream_start

  response_opcode:
    0x02: put
    0x04: get
    0x06: put_if_absent
    0x08: replace
    0x0A: replace_if_unmodified
    0x0C: remove
    0x0E: remove_if_unmodified
    0x10: contains_key
    0x12: get_with_version # deprecated
    0x14: clear
    0x16: stats
    0x18: ping
    0x1A: bulk_get
    0x1C: get_with_metadata
    0x1E: bulk_get_keys
    0x20: query
    0x22: auth_mech_list
    0x24: auth
    0x26: add_client_listener
    0x28: remove_client_listener
    0x2A: size
    0x2C: exec
    0x2E: put_all
    0x30: get_all
    0x32: iteration_start
    0x34: iteration_next
    0x36: iteration_end
    0x3C: prepare
    0x3E: commit
    0x40: rollback
    0x42: add_bloom_filter_listener
    0x44: update_bloom_filter
    0x4C: counter_create
    0x4E: counter_get_configuration
    0x50: error
    0x51: counter_is_defined
    0x53: counter_add_and_get
    0x55: counter_reset
    0x57: counter_get_value
    0x59: counter_cas
    0x5B: counter_add_listener
    0x5D: counter_remove_listener
    0x5F: counter_remove
    0x60: cache_entry_created_event
    0x61: cache_entry_modified_event
    0x62: cache_entry_removed_event
    0x63: cache_entry_expired_event
    0x65: counter_get_names
    0x66: counter_event
    0x68: multimap_get
    0x6A: multimap_get_with_metadata
    0x6C: multimap_put
    0x6E: multimap_remove_key
    0x70: multimap_remove_entry
    0x72: multimap_size
    0x74: multimap_contains_entry
    0x76: multimap_contains_key
    0x78: multimap_contains_value
    0x7A: forget_tx
    0x7C: fetch_tx_recovery
    0x7E: prepare_v2
    0x80: counter_get_and_set
    0xE4: get_stream_end
    0xE6: get_stream_next
    0xE8: get_stream_start
    0xEA: put_stream_end
    0xEC: put_stream_next
    0xEE: put_stream_start

  response_status:
    0x00: success
    0x01: not_executed
    0x02: key_does_not_exist
    0x03: success_with_previous
    0x04: not_executed_with_previous
    0x81: invalid_magic_or_message_id
    0x82: unknown_command
    0x83: unknown_version
    0x84: parse_error
    0x85: server_error
    0x86: command_timed_out
    0x87: node_suspected
    0x88: illegal_lifecycle_state

  client_intelligence_type:
    0x01: basic
    0x02: topology_aware
    0x03: hash_distribution_aware

  media_type_kind:
    0x00: none
    0x01: predefined
    0x02: custom

  predefined_media_type_id:
    1: application_x_java_object
    2: application_json
    3: application_octet_stream
    4: application_pdf
    5: application_rtf
    6: application_zip
    7: image_gif
    8: image_jpeg
    9: image_png
    10: text_css
    11: text_csv
    12: application_x_protostream
    13: text_plain
    14: text_html
    15: application_x_jboss_marshalling
    17: application_unknown

  time_unit:
    0x00: seconds
    0x01: milliseconds
    0x02: nanoseconds
    0x03: microseconds
    0x04: minutes
    0x05: hours
    0x06: days
    0x07: default
    0x08: infinite

  hash_function_version:
    0x01: murmur_hash_2
    0x02: murmur_hash_3
    0x03: murmur_hash_3_with_segments
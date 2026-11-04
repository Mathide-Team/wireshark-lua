-- SPDX-License-Identifier: GPL-3.0-or-later
-- Importé de https://github.com/10etennba/chia-wireshark-dissector-lua (chia.lua),
-- commit cf48287ddbdf3c25e1e173024fec24d340ca4227 du 15/02/2025.
-- Licence amont : GPL-3.0-or-later (LICENSE amont) — voir README.md.
--[[
    Chia Blockchain Protocol Dissector
    Version: 2.5.1.dev1
    Copyright (C) 2025 10etennba

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
--]]


local plugin_info = {
    version = "2.5.1.dev1",
    author = "10etennba",
    description = "Chia Blockchain Protocol Dissector",
    repository = "https://github.com/10etennba/chia-wireshark-dissector-lua/",
    gratuity = "xch1a5ysw83rsk80aw65fn4zrfuha3jup96f4yc392fsy83paeccpvjs7jrxpr"
}
set_plugin_info(plugin_info)



-- Define the ports the dissector is listening to:
local CHIA_PORTS = {
    8000,   -- TimeLord
    8444,   -- Full node, Wallet
    8447,   -- Farmer, Harvester
    58444,  -- testnet: Full node, Wallet
}


--Display Chia's de/serialization protocol fields (default is false).
local SHOW_SERIAL_PROTO = false


-- Register protocol
p_chia = Proto.new("Chia","Chia Blockchain Protocol")

--------------------------------------------------------------------------------
-- Fields for the various message types
--------------------------------------------------------------------------------
local pf = {

    -- message / Message
    msg__type = ProtoField.uint8(
        "chia.type",
        "type (uint8)"),
    msg__type__enum = ProtoField.string(
        "chia.type.enum",
        "type.enum (str)"),
    msg__id__option = ProtoField.bool(
        "chia.id.option",
        "{id_option (bool)}"),
    msg__id = ProtoField.uint16(
        "chia.id",
        "id (uint16)"),
    msg__data__length = ProtoField.uint32(
        "chia.data.length",
        "{data.length (uint32)}"),
    msg__data = ProtoField.bytes(
        "chia.data",
        "data (bytes)"),


    -- 1 handshake / Handshake
    handshake__network_id__length = ProtoField.uint32(
        "chia.data.handshake.network_id.length",
        "{network_id.length (uint32)}"),
    handshake__network_id = ProtoField.string(
        "chia.data.handshake.network_id",
        "network_id (str)"),
    handshake__protocol_version__length = ProtoField.uint32(
        "chia.data.handshake.protocol_version.length",
        "{protocol_version.length (uint32)}"),
    handshake__protocol_version = ProtoField.string(
        "chia.data.handshake.protocol_version",
        "protocol_version (str)"),
    handshake__software_version__length = ProtoField.uint32(
        "chia.data.handshake.software_version.length",
        "{software_version.length (uint32)}"),
    handshake__software_version = ProtoField.string(
        "chia.data.handshake.software_version",
        "software_version (str)"),
    handshake__server_port = ProtoField.uint16(
        "chia.data.handshake.server_port",
        "server_port (uint16)"),
    handshake__node_type = ProtoField.uint8(
        "chia.data.handshake.node_type",
        "node_type (uint8)"),
    handshake__node_type__enum = ProtoField.string(
        "chia.data.handshake.node_type.enum",
        "{node_type.enum (str)}"),
    handshake__capabilities__count = ProtoField.uint32(
        "chia.data.handshake.capabilities.count",
        "{capabilities.count (uint32)}"),   
    handshake__capability__enum = ProtoField.string(
        "chia.data.handshake.capability.enum",
        "{capability.enum (str)}"),
    handshake__capability__uint16 = ProtoField.uint16(
        "chia.data.handshake.capability.uint16",
        "uint16 (uint16)"),
    handshake__capability__str__length = ProtoField.uint32(
        "chia.data.handshake.capability.str.length",
        "{str.length (uint32)}"),
    handshake__capability__str = ProtoField.string(
        "chia.data.handshake.capability.str",
        "str (str)"),


    -- 2 (undefined)


    -- 3 harvester_handshake / HarvesterHandshake
    harvester_handshake__farmer_public_keys__count = ProtoField.uint32(
        "chia.data.harvester_handshake.farmer_public_keys.count",
        "{farmer_public_keys.count (uint32)}"),
    harvester_handshake__farmer_public_key = ProtoField.bytes(
        "chia.data.harvester_handshake.farmer_public_key",
        "farmer_public_key (G1Element)"),
    harvester_handshake__pool_public_keys__count = ProtoField.uint32(
        "chia.data.harvester_handshake.pool_public_keys.count",
        "{pool_public_keys.count (uint32)}"),
    harvester_handshake__pool_public_key = ProtoField.bytes(
        "chia.data.harvester_handshake.pool_public_key",
        "pool_public_key (G1Element)"),


    -- 4 (undefined)


    -- 5 new_proof_of_space / NewProofOfSpace
    new_proof_of_space__challenge_hash = ProtoField.bytes(
        "chia.data.new_proof_of_space.challenge_hash",
        "challenge_hash (bytes32)"),
    new_proof_of_space__sp_hash = ProtoField.bytes(
        "chia.data.new_proof_of_space.sp_hash",
        "sp_hash (bytes32)"),
    new_proof_of_space__plot_identifier__length = ProtoField.uint32(
        "chia.data.new_proof_of_space.plot_identifier.length",
        "{plot_identifier.length (uint32)}"),
    new_proof_of_space__plot_identifier = ProtoField.string(
        "chia.data.new_proof_of_space.plot_identifier",
        "plot_identifier (str)"),
    new_proof_of_space__signage_point_index = ProtoField.uint8(
        "chia.data.new_proof_of_space.signage_point_index",
        "signage_point_index (uint8)"),
    new_proof_of_space__include_source_signature_data = ProtoField.bool(
        "chia.data.new_proof_of_space.include_source_signature_data",
        "include_source_signature_data (bool)"),
    new_proof_of_space__farmer_reward_address_override__option = ProtoField.bool(
        "chia.data.new_proof_of_space.farmer_reward_address_override.option",
        "{farmer_reward_address_override.option (bool)}"),
    new_proof_of_space__farmer_reward_address_override = ProtoField.bytes(
        "chia.data.new_proof_of_space.farmer_reward_address_override",
        "farmer_reward_address_override (bytes32)"),
    new_proof_of_space__fee_info__option = ProtoField.bool(
        "chia.data.new_proof_of_space.fee_info.option",
        "{fee_info.option (bool)}"),
    new_proof_of_space__fee_info__applied_fee_threshold = ProtoField.uint32(
        "chia.data.new_proof_of_space.fee_info.applied_fee_threshold",
        "applied_fee_threshold (uint32)"),


    -- 6 request_signatures / RequestSignatures
    request_signatures__plot_identifier__length = ProtoField.uint32(
        "chia.data.request_signatures.plot_identifier.length",
        "{plot_identifier.length (uint32)}"),
    request_signatures__plot_identifier = ProtoField.string(
        "chia.data.request_signatures.plot_identifier",
        "plot_identifier (str)"),
    request_signatures__challenge_hash = ProtoField.bytes(
        "chia.data.request_signatures.challenge_hash",
        "challenge_hash (bytes32)"),
    request_signatures__sp_hash = ProtoField.bytes(
        "chia.data.request_signatures.sp_hash",
        "sp_hash (bytes32)"),
    request_signatures__messages__count = ProtoField.uint32(
        "chia.data.request_signatures.messages.count",
        "{messages.count (uint32)}"),
    request_signatures__message = ProtoField.bytes(
        "chia.data.request_signatures.message",
        "message (bytes32)"),
    request_signatures__message_data__option = ProtoField.bool(
        "chia.data.request_signatures.message_data.option",
        "{message_data.option (bool)}"),
    request_signatures__message_data__count = ProtoField.uint32(
        "chia.data.request_signatures.message_data.count",
        "{message_data.count (uint32)}"),
    request_signatures__message_data__SignatureRequestSourceData__option = ProtoField.bool(
        "chia.data.request_signatures.message_data.SignatureRequestSourceData.option",
         "{SignatureRequestSourceData.option (bool)}"),
    request_signatures__message_data__SignatureRequestSourceData__kind = ProtoField.uint8(
        "chia.data.request_signatures.message_data.SignatureRequestSourceData.kind",
        "kind (uint8)"),
    request_signatures__message_data__SignatureRequestSourceData__data__length = ProtoField.uint32(
        "chia.data.request_signatures.message_data.SignatureRequestSourceData.data.length",
        "{data.length (uint32)}"),
    request_signatures__message_data__SignatureRequestSourceData__data = ProtoField.bytes(
        "chia.data.request_signatures.SignatureRequestSourceData.data",
        "data (bytes)"),
    request_signatures__rc_block_unfinished__option = ProtoField.bool(
        "chia.data.request_signatures.rc_block_unfinished.option",
        "{rc_block_unfinished.option (bool)}"),


    -- 7 respond_signatures / RespondSignatures
    respond_signatures__plot_identifier__length = ProtoField.uint32(
        "chia.data.respond_signatures.plot_identifier.length",
        "{plot_identifier.length (uint32)}"),
    respond_signatures__plot_identifier = ProtoField.string(
        "chia.data.respond_signatures.plot_identifier",
        "plot_identifier (str)"),
    respond_signatures__challenge_hash = ProtoField.bytes(
        "chia.data.respond_signatures.challenge_hash",
        "challenge_hash (bytes32)"),
    respond_signatures__sp_hash = ProtoField.bytes(
        "chia.data.respond_signatures.sp_hash",
        "sp_hash (bytes32)"),
    respond_signatures__local_pk = ProtoField.bytes(
        "chia.data.respond_signatures.local_pk",
        "local_pk (G1Element)"),
    respond_signatures__farmer_pk = ProtoField.bytes(
        "chia.data.respond_signatures.farmer_pk",
        "farmer_pk (G1Element)"),
    respond_signatures__message_signatures__count = ProtoField.uint32(
        "chia.data.respond_signatures.message_signatures.count",
        "{message_signatures.count (uint32)}"),
    respond_signatures__message_signature__bytes32 = ProtoField.bytes(
        "chia.data.respond_signatures.message_signatures.message_signature.bytes32",
        "bytes32 (bytes32)"),
    respond_signatures__message_signature__signature = ProtoField.bytes(
        "chia.data.respond_signatures.message_signatures.message_signature.signature",
        "signature (G2Element)"),
    respond_signatures__include_source_signature_data = ProtoField.bool(
        "chia.data.respond_signatures.include_source_signature_data",
        "include_source_signature_data (bool)"),
    respond_signatures__farmer_reward_address_override__option = ProtoField.bool(
        "chia.data.respond_signatures.farmer_reward_address_override.option",
        "{farmer_reward_address_override.option (bool)}"),
    respond_signatures__farmer_reward_address_override = ProtoField.bytes(
        "chia.data.respond_signatures.farmer_reward_address_override",
        "farmer_reward_address_override (bytes32)"),


    -- 8 new_signage_point / NewSignagePoint
    new_signage_point__challenge_hash = ProtoField.bytes(
        "chia.data.new_signage_point.challenge_hash",
        "challenge_hash (bytes32)"),
    new_signage_point__challenge_chain_sp = ProtoField.bytes(
        "chia.data.new_signage_point.challenge_chain_sp",
        "challenge_chain_sp (bytes32)"),
    new_signage_point__reward_chain_sp = ProtoField.bytes(
        "chia.data.new_signage_point.reward_chain_sp",
        "reward_chain_sp (bytes32)"),
    new_signage_point__difficulty = ProtoField.uint64(
        "chia.data.new_signage_point.difficulty",
        "difficulty (uint64)"),
    new_signage_point__sub_slot_iters = ProtoField.uint64(
        "chia.data.new_signage_point.sub_slot_iters",
        "sub_slot_iters (uint64)"),
    new_signage_point__signage_point_index = ProtoField.uint8(
        "chia.data.new_signage_point.signage_point_index",
        "signage_point_index (uint8)"),
    new_signage_point__peak_height = ProtoField.uint32(
        "chia.data.new_signage_point.peak_height",
        "peak_height (uint32)"),
    new_signage_point__sp_source_data__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.option",
        "{sp_source_data.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.option",
        "{sub_slot_data.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__infused_challenge_chain_sub_slot_hash__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.infused_challenge_chain_sub_slot_hash.option",
        "{infused_challenge_chain_sub_slot_hash.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__infused_challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.infused_challenge_chain_sub_slot_hash",
        "infused_challenge_chain_sub_slot_hash (Bytes32)"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__subepoch_summary_hash__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.subepoch_summary_hash.option",
        "{subepoch_summary_hash.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__subepoch_summary_hash = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.subepoch_summary_hash",
        "subepoch_summary_hash (Bytes32)"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_sub_slot_iters__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.new_sub_slot_iters.option",
        "{new_sub_slot_iters.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_sub_slot_iters = ProtoField.uint64(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.new_sub_slot_iters",
        "new_sub_slot_iters (u64)"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_difficulty__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.new_difficulty.option",
        "{new_difficulty.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_difficulty = ProtoField.uint64(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.cc_sub_slot.new_difficulty",
        "new_difficulty (u64)"),
    new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.rc_sub_slot.challenge_chain_sub_slot_hash",
        "challenge_chain_sub_slot_hash (Bytes32)"),
    new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__infused_challenge_chain_sub_slot_hash__option = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.rc_sub_slot.infused_challenge_chain_sub_slot_hash.option",
        "{infused_challenge_chain_sub_slot_hash.option (bool)}"),
    new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__infused_challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.rc_sub_slot.infused_challenge_chain_sub_slot_hash",
        "infused_challenge_chain_sub_slot_hash (Bytes32)"),
    new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__deficit = ProtoField.uint8(
        "chia.data.new_signage_point.sp_source_data.sub_slot_data.rc_sub_slot.deficit",
        "deficit (u8)"),
    new_signage_point__sp_source_data__vdf_data__option = ProtoField.bool(
        "chia.data.new_signage_point.sp_source_data.vdf_data.option",
        "{vdf_data.option (bool)}"),
    new_signage_point__sp_source_data__vdf_data__cc_vdf__ClassgroupElement__data = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.vdf_data.cc_vdf.ClassgroupElement.data",
        "data (bytes100)"),
    new_signage_point__sp_source_data__vdf_data__rc_vdf__ClassgroupElement__data = ProtoField.bytes(
        "chia.data.new_signage_point.sp_source_data.vdf_data.rc_vdf.ClassgroupElement.data",
        "data (bytes100)"),
    

    -- 9 declare_proof_of_space / DeclareProofOfSpace
    declare_proof_of_space__challenge_hash = ProtoField.bytes(
        "chia.data.declare_proof_of_space.challenge_hash",
        "challenge_hash (bytes32)"),
    declare_proof_of_space__challenge_chain_sp = ProtoField.bytes(
        "chia.data.declare_proof_of_space.challenge_chain_sp",
        "challenge_chain_sp (bytes32)"),
    declare_proof_of_space__signage_point_index = ProtoField.bytes(
        "chia.data.declare_proof_of_space.signage_point_index",
        "signage_point_index (uint8)"),
    declare_proof_of_space__reward_chain_sp = ProtoField.bytes(
        "chia.data.declare_proof_of_space.reward_chain_sp",
        "reward_chain_sp (bytes32)"),
    declare_proof_of_space__challenge_chain_sp_signature = ProtoField.bytes(
        "chia.data.declare_proof_of_space.challenge_chain_sp_signature",
        "challenge_chain_sp_signature (G2Element)"),
    declare_proof_of_space__reward_chain_sp_signature = ProtoField.bytes(
        "chia.data.declare_proof_of_space.reward_chain_sp_signature",
        "reward_chain_sp_signature (G2Element)"),
    declare_proof_of_space__farmer_puzzle_hash = ProtoField.bytes(
        "chia.data.declare_proof_of_space.farmer_puzzle_hash",
        "farmer_puzzle_hash (bytes32)"),
    declare_proof_of_space__pool_target__option = ProtoField.bytes(
        "chia.data.declare_proof_of_space.pool_target.option",
        "{pool_target.option (bool)}"),
    declare_proof_of_space__pool_target__puzzle_hash = ProtoField.bytes(
        "chia.data.declare_proof_of_space.pool_target.puzzle_hash",
        "puzzle_hash (Bytes32)"),
    declare_proof_of_space__pool_target__height = ProtoField.bytes(
        "chia.data.declare_proof_of_space.pool_target.height",
        "pool_target.height (u32)"),
    declare_proof_of_space__pool_signature__option = ProtoField.bytes(
        "chia.data.declare_proof_of_space.pool_signature.option",
        "{pool_signature.option (bool)}"),
    declare_proof_of_space__pool_signature = ProtoField.bytes(
        "chia.data.declare_proof_of_space.pool_signature",
        "signature (G2Element)"),
    declare_proof_of_space__include_signature_source_data = ProtoField.bool(
        "chia.data.declare_proof_of_space.include_signature_source_data",
        "include_signature_source_data (bool)"),


    -- 10 request_signed_values / RequestSignedValues
    request_signed_values__quality_string = ProtoField.bytes(
        "chia.data.request_signed_values.quality_string",
        "quality_string (bytes32)"),
    request_signed_values__foliage_block_data_hash = ProtoField.bytes(
        "chia.data.request_signed_values.foliage_block_data_hash",
        "foliage_block_data_hash (bytes32)"),
    request_signed_values__foliage_transaction_block_hash = ProtoField.bytes(
        "chia.data.request_signed_values.foliage_transaction_block_hash",
        "foliage_transaction_block_hash (bytes32)"),
    request_signed_values__foliage_block_data__option = ProtoField.bytes(
        "chia.data.request_signed_values.foliage_block_data.option",
        "{foliage_block_data.option (bool)}"),
    request_signed_values__foliage_transaction_block_data__option = ProtoField.bytes(
        "chia.data.request_signed_values.foliage_transaction_block_data.option",
        "{foliage_transaction_block_data.option (bool)}"),
    request_signed_values__rc_block_unfinished__option = ProtoField.bytes(
        "chia.data.request_signed_values.rc_block_unfinished.option",
        "{rc_block_unfinished.option (bool)}"),


    -- 11 signed_values / SignedValues
    signed_values__quality_string = ProtoField.bytes(
        "chia.data.signed_values.quality_string",
        "quality_string (bytes32)"),
    signed_values__foliage_block_data_signature = ProtoField.bytes(
        "chia.data.signed_values.foliage_block_data_signature",
        "foliage_block_data_signature (G2Element)"),
    signed_values__foliage_transaction_block_signature = ProtoField.bytes(
        "chia.data.signed_values.foliage_transaction_block_signature",
        "foliage_transaction_block_signature (G2Element)"),


    -- 12 farming_info / FarmingInfo
    farming_info__challenge_hash = ProtoField.bytes(
        "chia.data.farming_info.challenge_hash",
        "challenge_hash (bytes32)"),
    farming_info__sp_hash = ProtoField.bytes(
        "chia.data.farming_info.sp_hash",
        "sp_hash (bytes32)"),
    farming_info__timestamp = ProtoField.uint64(
        "chia.data.farming_info.timestamp",
        "timestamp (uint64)"),
    farming_info__passed = ProtoField.uint32(
        "chia.data.farming_info.passed",
        "passed (uint32)"),
    farming_info__proofs = ProtoField.uint32(
        "chia.data.farming_info.proofs",
        "proofs (uint32)"),
    farming_info__total_plots = ProtoField.uint32(
        "chia.data.farming_info.total_plots",
        "total_plots (uint32)"),
    farming_info__lookup_time = ProtoField.uint64(
        "chia.data.farming_info.lookup_time",
        "lookup_time (uint64)"),


    -- 13 new_peak_timelord / NewPeakTimelord
    new_peak_timelord__difficulty = ProtoField.uint64(
        "chia.data.new_peak_timelord.difficulty",
        "difficulty (uint64)"),
    new_peak_timelord__deficit = ProtoField.uint8(
        "chia.data.new_peak_timelord.deficit",
        "deficit (uint8)"),
    new_peak_timelord__sub_slot_iters = ProtoField.uint64(
        "chia.data.new_peak_timelord.sub_slot_iters",
        "sub_slot_iters (uint64)"),
    new_peak_timelord__sub_epoch_summary__option = ProtoField.bool(
        "chia.data.new_peak_timelord.sub_epoch_summary.option",
        "{sub_epoch_summary.option (bool)}"),
    new_peak_timelord__previous_reward_challenges__count = ProtoField.uint32(
        "chia.data.new_peak_timelord.previous_reward_challenges.count",
        "{previous_reward_challenges.count (uint32)}"),
    new_peak_timelord__previous_reward_challenges__tuples__bytes32 = ProtoField.bytes(
        "chia.data.new_peak_timelord.previous_reward_challenges.tuples.bytes32",
        "bytes32 (bytes32)"),
    new_peak_timelord__previous_reward_challenges__tuples__uint128 = ProtoField.string(
        "chia.data.new_peak_timelord.previous_reward_challenges.tuples.uint128",
        "uint128 (uint128)"),
    new_peak_timelord__last_challenge_sb_or_eos_total_iters = ProtoField.string(
        "chia.data.new_peak_timelord.last_challenge_sb_or_eos_total_iters",
        "last_challenge_sb_or_eos_total_iters (uint128)"),
    new_peak_timelord__passes_ses_height_but_not_yet_included = ProtoField.bool(
        "chia.data.new_peak_timelord.passes_ses_height_but_not_yet_included",
        "passes_ses_height_but_not_yet_included (bool)"),


    -- 14 new_unfinished_block_timelord / NewUnfinishedBlockTimelord
    new_unfinished_block_timelord__difficulty = ProtoField.uint64(
        "chia.data.new_unfinished_block_timelord.difficulty",
        "difficulty (uint64)"),
    new_unfinished_block_timelord__sub_slot_iters = ProtoField.uint64(
        "chia.data.new_unfinished_block_timelord.sub_slot_iters",
        "sub_slot_iters (uint64)"),
    new_unfinished_block_timelord__sub_epoch_summary__option = ProtoField.bool(
        "chia.data.new_unfinished_block_timelord.sub_epoch_summary.option",
        "{sub_epoch_summary.option (bool)}"),
    new_unfinished_block_timelord__rc_prev = ProtoField.bytes(
        "chia.data.new_unfinished_block_timelord.rc_prev",
        "rc_prev (bytes32)"),


    -- 15 new_infusion_point_vdf / NewInfusionPointVDF
    new_infusion_point_vdf__unfinished_reward_hash = ProtoField.bytes(
        "chia.data.new_infusion_point_vdf.unfinished_reward_hash",
        "unfinished_reward_hash (bytes32)"),
    new_infusion_point_vdf__infused_challenge_chain_ip_vdf__option = ProtoField.bool(
        "chia.data.new_infusion_point_vdf.infused_challenge_chain_ip_vdf.option",
        "{infused_challenge_chain_ip_vdf.option (bool)}"),
    new_infusion_point_vdf__infused_challenge_chain_ip_proof__option = ProtoField.bool(
        "chia.data.new_infusion_point_vdf.infused_challenge_chain_ip_proof.option",
        "{infused_challenge_chain_ip_proof.option (bool)}"),


    -- 16 new_signage_point_vdf / NewSignagePointVDF
    new_signage_point_vdf__index_from_challenge = ProtoField.uint8(
        "chia.data.new_signage_point_vdf.index_from_challenge",
        "index_from_challenge (uint8)"),


    -- 17 new_end_of_sub_slot_vdf / NewEndOfSubSlotVDF


    -- 18 request_compact_proof_of_time / RequestCompactProofOfTime
    request_compact_proof_of_time__header_hash = ProtoField.bytes(
        "chia.data.request_compact_proof_of_time.header_hash",
        "header_hash (bytes32)"),
    request_compact_proof_of_time__height = ProtoField.uint32(
        "chia.data.request_compact_proof_of_time.height",
        "height (uint32)"),
    request_compact_proof_of_time__field_vdf = ProtoField.uint8(
        "chia.data.request_compact_proof_of_time.field_vdf",
        "field_vdf (uint8)"),


    -- 19 respond_compact_proof_of_time / RespondCompactProofOfTime
    respond_compact_proof_of_time__header_hash = ProtoField.bytes(
        "chia.data.respond_compact_proof_of_time.header_hash",
        "header_hash (bytes32)"),
    respond_compact_proof_of_time__height = ProtoField.uint32(
        "chia.data.respond_compact_proof_of_time.height",
        "height (uint32)"),
    respond_compact_proof_of_time__field_vdf = ProtoField.uint8(
        "chia.data.respond_compact_proof_of_time.field_vd",
        "field_vd (uint8)"),


    -- 20 new_peak / NewPeak
    new_peak__header_hash = ProtoField.bytes(
        "chia.data.new_peak.header_hash",
        "header_hash (bytes32)"),
    new_peak__height = ProtoField.uint32(
        "chia.data.new_peak.height",
        "height (uint32)"),
    new_peak__weight = ProtoField.string(
        "chia.data.new_peak.weight",
        "weight (uint128)"),
    new_peak__fork_point_with_previous_peak = ProtoField.uint32(
        "chia.data.new_peak.fork_point_with_previous_peak",
        "fork_point_with_previous_peak (uint32)"),
    new_peak__unfinished_reward_block_hash = ProtoField.bytes(
        "chia.data.new_peak.unfinished_reward_block_hash",
        "unfinished_reward_block_hash (bytes32)"),
 

    -- 21 new_transaction / NewTransaction
    new_transaction__transaction_id = ProtoField.bytes(
        "chia.data.new_transaction.transaction_id",
        "transaction_id (bytes32)"),
    new_transaction__cost = ProtoField.uint64(
        "chia.data.new_transaction__cost",
        "cost (uint64)"),
    new_transaction__fees = ProtoField.uint64(
        "chia.data.new_transaction__fees",
        "fees (uint64)"),


    -- 22 request_transaction / RequestTransaction
    request_transaction__transaction_id = ProtoField.bytes(
        "chia.data.request_transaction.transaction_id",
        "transaction_id (bytes32)"),


    -- 23 respond_transaction / RespondTransaction


    -- 24 request_proof_of_weight / RequestProofOfWeight
    request_proof_of_weight__total_number_of_blocks = ProtoField.uint32(
        "chia.data.request_proof_of_weight.total_number_of_blocks",
        "total_number_of_blocks (uint32)"),
    request_proof_of_weight__tip = ProtoField.bytes(
        "chia.data.request_proof_of_weight.tip",
        "tip (bytes32)"),


    -- 25 respond_proof_of_weight / RespondProofOfWeight
    respond_proof_of_weight__wp__sub_epochs__count = ProtoField.uint32(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.count",
        "{sub_epochs.count (uint32)}"),
    respond_proof_of_weight__wp__sub_epochs__reward_chain_hash = ProtoField.bytes(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.reward_chain_hash",
        "reward_chain_hash (Bytes32)"),
    respond_proof_of_weight__wp__sub_epochs__num_blocks_overflow = ProtoField.uint8(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.num_blocks_overflow",
        "num_blocks_overflow (u8)"),
    respond_proof_of_weight__wp__sub_epochs__new_sub_slot_iters__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.new_sub_slot_iters.option",
        "{new_sub_slot_iters.option (bool)}"),
    respond_proof_of_weight__wp__sub_epochs__new_sub_slot_iters = ProtoField.uint64(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.new_sub_slot_iters",
        "new_sub_slot_iters (u64)"),
    respond_proof_of_weight__wp__sub_epochs__new_difficulty__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.new_difficulty.option",
        "{new_difficulty.option (bool)}"),
    respond_proof_of_weight__wp__sub_epochs__new_difficulty = ProtoField.uint64(
        "chia.data.respond_proof_of_weight.wp.sub_epochs.new_difficulty",
        "new_difficulty (u64)"),
    respond_proof_of_weight__wp__sub_epoch_segments__count = ProtoField.uint32(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.count",
        "{sub_epoch_segments.count (uint32)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_epoch_n = ProtoField.uint32(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_epoch_n",
        "sub_epoch_n (u32)"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__count = ProtoField.uint32(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.count",
        "{sub_slots.count (uint32)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__proof_of_space__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.proof_of_space.option",
        "{proof_of_space.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_signage_point__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_signage_point.option",
        "{cc_signage_point.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_infusion_point__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_infusion_point.option",
        "{cc_infusion_point.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_infusion_point__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.icc_infusion_point.option",
        "{icc_infusion_point.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_sp_vdf_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_sp_vdf_info.option",
        "{cc_sp_vdf_info.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__signage_point_index__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.signage_point_index.option",
        "{signage_point_index.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__signage_point_index = ProtoField.uint8(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.signage_point_index",
        "signage_point_index (u8)"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_slot_end__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_slot_end.option",
        "{cc_slot_end.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_slot_end__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.icc_slot_end.option",
        "{icc_slot_end.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_slot_end_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_slot_end_info.option",
        "{cc_slot_end_info.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_slot_end_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.icc_slot_end_info.option",
        "{icc_slot_end_info.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_ip_vdf_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.cc_ip_vdf_info.option",
        "{cc_ip_vdf_info.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_ip_vdf_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.icc_ip_vdf_info.option",
        "{icc_ip_vdf_info.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__total_iters__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.total_iters.option",
        "{total_iters.option (bool)}"),
    respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__total_iters = ProtoField.string(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.sub_slots.total_iters",
        "total_iters (u128)"),
    respond_proof_of_weight__wp__sub_epoch_segments__rc_slot_end_info__option = ProtoField.bool(
        "chia.data.respond_proof_of_weight.wp.sub_epoch_segments.rc_slot_end_info.option",
        "{rc_slot_end_info.option (bool)}"),
    respond_proof_of_weight__wp__recent_chain_data__count = ProtoField.uint32(
        "chia.data.respond_proof_of_weight.wp.recent_chain_data.count",
        "{recent_chain_data.count (uint32)}"),
    respond_proof_of_weight__tip = ProtoField.bytes(
        "chia.data.respond_proof_of_weight.tip",
        "tip (bytes32)"),


    -- 26 request_block / RequestBlock
    request_block__height = ProtoField.uint32(
        "chia.data.request_block.height",
        "height (uint32)"),
    request_block__include_transaction_block = ProtoField.bool(
        "chia.data.request_block.include_transaction_block",
        "include_transaction_block (bool)"),


    -- 27 respond_block / RespondBlock
    

    -- 28 reject_block / RejectBlock
    reject_block__height = ProtoField.uint32(
        "chia.data.reject_block.height",
        "height (uint32)"),
    

    -- 29 request_blocks / RequestBlocks
    request_blocks__start_height = ProtoField.uint32(
        "chia.data.request_blocks.start_height",
        "start_height (uint32)"),
    request_blocks__end_height = ProtoField.uint32(
        "chia.data.request_blocks.end_height",
        "end_height (uint32)"),
    request_blocks__include_transaction_block = ProtoField.bool(
        "chia.data.request_blocks.include_transaction_block",
        "include_transaction_block (bool)"),


    -- 30 respond_blocks / RespondBlocks
    respond_blocks__start_height = ProtoField.uint32(
        "chia.data.respond_blocks.start_height",
        "start_height (uint32)"),
    respond_blocks__end_height = ProtoField.uint32(
        "chia.data.respond_blocks.end_height",
        "end_height (uint32)"),
    respond_blocks__blocks__count = ProtoField.uint32(
        "chia.data.respond_blocks.blocks.count",
        "{blocks.count (uint32)}"),


    -- 31 reject_blocks / RejectBlocks
    reject_blocks__start_height = ProtoField.uint32(
        "chia.data.reject_blocks.start_height",
        "start_height (uint32)"),
    reject_blocks__end_height = ProtoField.uint32(
        "chia.data.reject_blocks.end_height",
        "end_height (uint32)"),


    -- 32 new_unfinished_block / NewUnfinishedBlock
    new_unfinished_block__unfinished_reward_hash = ProtoField.bytes(
        "chia.data.new_unfinished_block.unfinished_reward_hash",
        "unfinished_reward_hash (bytes32)"),


    -- 33 request_unfinished_block / RequestUnfinishedBlock
    request_unfinished_block__unfinished_reward_hash = ProtoField.bytes(
        "chia.data.request_unfinished_block.unfinished_reward_hash",
        "unfinished_reward_hash (bytes32)"),


    -- 34 respond_unfinished_block / RespondUnfinishedBlock


    -- 35 new_signage_point_or_end_of_sub_slot / NewSignagePointOrEndOfSubSlot
    new_signage_point_or_end_of_sub_slot__prev_challenge_hash__option = ProtoField.bool(
        "chia.data.new_signage_point_or_end_of_sub_slot.prev_challenge_hash.option",
        "{prev_challenge_hash.option (bool)}"),
    new_signage_point_or_end_of_sub_slot__prev_challenge_hash = ProtoField.bytes(
        "chia.data.new_signage_point_or_end_of_sub_slot.prev_challenge_hash",
        "prev_challenge_hash (bytes32)"),
    new_signage_point_or_end_of_sub_slot__challenge_hash = ProtoField.bytes(
        "chia.data.new_signage_point_or_end_of_sub_slot.challenge_hash",
        "challenge_hash (bytes32)"),
    new_signage_point_or_end_of_sub_slot__index_from_challenge = ProtoField.uint8(
        "chia.data.new_signage_point_or_end_of_sub_slot.index_from_challenge",
        "index_from_challenge (uint8)"),
    new_signage_point_or_end_of_sub_slot__last_rc_infusion = ProtoField.bytes(
        "chia.data.new_signage_point_or_end_of_sub_slot.last_rc_infusion",
        "last_rc_infusion (bytes32)"),


    -- 36 request_signage_point_or_end_of_sub_slot / RequestSignagePointOrEndOfSubSlot
    request_signage_point_or_end_of_sub_slot__challenge_hash = ProtoField.bytes(
        "chia.data.request_signage_point_or_end_of_sub_slot.challenge_hash",
        "challenge_hash (bytes32)"),
    request_signage_point_or_end_of_sub_slot__index_from_challenge = ProtoField.uint8(
        "chia.data.request_signage_point_or_end_of_sub_slot.index_from_challenge",
        "index_from_challenge (uint8)"),
    request_signage_point_or_end_of_sub_slot__last_rc_infusion = ProtoField.bytes(
        "chia.data.request_signage_point_or_end_of_sub_slot",
        "last_rc_infusion (bytes32)"),


    -- 37 respond_signage_point / RespondSignagePoint
    respond_signage_point__index_from_challenge = ProtoField.uint8(
        "chia.data.respond_signage_point.index_from_challenge",
        "index_from_challenge (uint8)"),


    -- 38 respond_end_of_sub_slot / RespondEndOfSubSlot


    -- 39 request_mempool_transactions / RequestMempoolTransactions
    request_mempool_transactions__filter__length = ProtoField.uint32(
        "chia.data.request_mempool_transactions.filter.length",
        "{filter.length (uint32)}"),
    request_mempool_transactions__filter = ProtoField.bytes(
        "chia.data.request_mempool_transactions.filter",
        "filter (bytes)"),


    -- 40 request_compact_vdf / RequestCompactVDF
    request_compact_vdf__height = ProtoField.uint32(
        "chia.data.request_compact_vdf.height",
        "height (uint32)"),
    request_compact_vdf__header_hash = ProtoField.bytes(
        "chia.data.request_compact_vdf.header_hash",
        "header_hash (bytes32)"),
    request_compact_vdf__field_vdf = ProtoField.uint8(
        "chia.data.request_compact_vdf.field_vdf",
        "field_vdf (uint8)"),


    -- 41 respond_compact_vdf / RespondCompactVDF
    respond_compact_vdf__height = ProtoField.uint32(
        "chia.data.respond_compact_vdf.height",
        "height (uint32)"),
    respond_compact_vdf__header_hash = ProtoField.bytes(
        "chia.data.respond_compact_vdf.header_hash",
        "header_hash (bytes32)"),
    respond_compact_vdf__field_vdf = ProtoField.uint8(
        "chia.data.respond_compact_vdf.field_vdf",
        "field_vdf (uint8)"),


    -- 42 new_compact_vdf / NewCompactVDF
    new_compact_vdf__height = ProtoField.uint32(
        "chia.data.new_compact_vdf.height",
        "height (uint32)"),
    new_compact_vdf__header_hash = ProtoField.bytes(
        "chia.data.new_compact_vdf.header_hash",
        "header_hash (bytes32)"),
    new_compact_vdf__field_vdf = ProtoField.uint8(
        "chia.data.new_compact_vdf.field_vdf",
        "field_vdf (uint8)"),


    -- 43 request_peers / RequestPeers


    -- 44 respond_peers / RespondPeers
    respond_peers__peer_list__count = ProtoField.uint32(
        "chia.data.respond_peers_peer_list.count",
        "{peer_list.count (uint32)}"),
    

    -- 45 request_puzzle_solution / RequestPuzzleSolution
    request_puzzle_solution__coin_name = ProtoField.bytes(
        "chia.data.request_puzzle_solution_coin_name",
        "coin_name (bytes32)"),
    request_puzzle_solution__height = ProtoField.uint32(
        "chia.data.request_puzzle_solution_height",
        "height (uint32)"),


    -- 46 respond_puzzle_solution / RespondPuzzleSolution
    respond_puzzle_solution__coin_name = ProtoField.bytes(
        "chia.data.request_puzzle_solution_coin_name",
        "coin_name (bytes32)"),
    respond_puzzle_solution__height = ProtoField.uint32(
        "chia.data.request_puzzle_solution_height",
        "height (uint32)"),
    respond_puzzle_solution__puzzle = ProtoField.bytes(
        "chia.data.request_puzzle_solution_puzzle",
        "puzzle (SerializedProgram)"),
    respond_puzzle_solution__solution = ProtoField.bytes(
        "chia.data.request_puzzle_solution_solution",
        "solution (SerializedProgram)"),


    -- 47 reject_puzzle_solution / RejectPuzzleSolution
    reject_puzzle_solution__coin_name = ProtoField.bytes(
        "rchia.data.eject_puzzle_solution.coin_name",
        "coin_name (bytes32)"),
    reject_puzzle_solution__height = ProtoField.uint32(
        "rchia.data.eject_puzzle_solution.height",
        "height (uint32)"),


    -- 48 send_transaction / SendTransaction


    -- 49 transaction_ack / TransactionAck
    transaction_ack__txid = ProtoField.bytes(
        "transaction_ack__txid.txid",
        "txid (bytes32)"),
    transaction_ack__status = ProtoField.uint8(
        "transaction_ack__txid.status",
        "status (uint8)"),
    transaction_ack__status__enum = ProtoField.string(
        "transaction_ack__txid.status.enum",
        "status_enum (str)"),
    transaction_ack__error__option = ProtoField.bool(
        "transaction_ack__txid.error.option",
        "{error.option (bool)}"),
    transaction_ack__error__length = ProtoField.uint32(
        "transaction_ack__txid.error.length",
        "{error.length (uint32)}"),
    transaction_ack__error = ProtoField.string(
        "transaction_ack__txid.error",
        "error (str)"),


    -- 50 new_peak_wallet / NewPeakWallet
    new_peak_wallet__header_hash = ProtoField.bytes(
        "chia.data.new_peak_wallet.header_hash",
        "header_hash (bytes32)"),
    new_peak_wallet__height = ProtoField.uint32(
        "chia.data.new_peak_wallet.height",
        "height (uint32)"),
    new_peak_wallet__weight = ProtoField.string(
        "chia.data.new_peak_wallet.weight",
        "weight (uint128)"),
    new_peak_wallet__fork_point_with_previous_peak = ProtoField.uint32(
        "chia.data.new_peak_wallet.fork_point_with_previous_peak",
        "fork_point_with_previous_peak (uint32)"),


    -- 51 request_block_header / RequestBlockHeader
    request_block_header__height = ProtoField.uint32(
        "chia.data.request_block_header.height",
        "height (uint32)"),


    -- 52 respond_block_header / RespondBlockHeader


    -- 53 reject_header_request / RejectHeaderRequest
    reject_header_request__height = ProtoField.uint32(
        "reject_header_request.height",
        "height (uint32)"),


    -- 54 request_removals / RequestRemovals
    request_removals__height = ProtoField.uint32(
        "chia.data.request_removals.height",
        "height (uint32)"),
    request_removals__header_hash = ProtoField.bytes(
        "chia.data.request_removals.header_hash",
        "header_hash (bytes32)"),
    request_removals__coin_names__option = ProtoField.bool(
        "chia.data.request_removals.coin_names.option",
        "coin_names.option (bool)"),
    request_removals__coin_names__count = ProtoField.uint32(
        "chia.data.request_removals.coin_names.count",
        "coin_names.count (uint32)"),
    request_removals__coin_names__coin_name = ProtoField.bytes(
        "chia.data.request_removals.coin_names.coin_name",
        "coin_name (bytes32)"),


    -- 55 respond_removals / RespondRemovals
    respond_removals__height = ProtoField.uint32(
        "chia.data.respond_removals.height",
        "height (uint32)"),
    respond_removals__header_hash = ProtoField.bytes(
        "chia.data.respond_removals.header_hash",
        "header_hash (bytes32)"),
    respond_removals__coins__coin_tuple__count = ProtoField.uint32(
        "chia.data.respond_removals.coins.coin_tuple.count",
        "{coin_tuple.count (uint32)}"),
    respond_removals__coins__coin_tuple__bytes32 = ProtoField.bytes(
        "chia.data.respond_removals.coins.coin_tuple.bytes32",
        "bytes32 (bytes32)"),
    respond_removals__coins__coin_tuple__coin__option = ProtoField.bool(
        "chia.data.respond_removals.coins.coin_tuple.coin.option",
        "{coin.option (bool)}"),
    respond_removals__proofs__option = ProtoField.bool(
        "chia.data.respond_removals.proofs.option",
        "{proofs.option (bool)}"),
    respond_removals__proofs__count = ProtoField.uint32(
        "chia.data.respond_removals.proofs.count",
        "{proofs.count (uint32)}"),
    respond_removals__proofs__proof_tuple__bytes32 = ProtoField.bytes(
        "chia.data.respond_removals.proofs.proof_tuple.bytes32",
        "bytes32 (bytes32)"),
    respond_removals__proofs__proof_tuple__bytes__length = ProtoField.uint32(
        "chia.data.respond_removals.proofs.proof_tuple.bytes.length",
        "{bytes.length (uint32)}"),
    respond_removals__proofs__proof_tuple__bytes = ProtoField.bytes(
        "chia.data.respond_removals.proofs.proof_tuple.bytes",
        "bytes (bytes)"),


    -- 56 reject_removals_request / RejectRemovalsRequest
    reject_removals_request__height = ProtoField.uint32(
        "chia.data.reject_removals_request.height",
        "height (uint32)"),
    reject_removals_request__header_hash = ProtoField.uint32(
        "chia.data.reject_removals_request.header_hash",
        "header_hash (bytes32)"),


    -- 57 request_additions / RequestAdditions
    request_additions__height = ProtoField.uint32(
        "chia.data.request_additions.height",
        "height (uint32)"),
    request_additions__header_hash__option = ProtoField.bool(
        "chia.data.request_additions.header_hash.option",
        "{header_hash.option (bool)}"),
    request_additions__header_hash = ProtoField.bytes(
        "chia.data.request_additions.header_hash",
        "header_hash (bytes32)"),
    request_additions__puzzle_hashes__option = ProtoField.bool(
        "chia.data.request_additions.puzzle_hashes.option",
        "{puzzle_hashes.option (bool)}"),
    request_additions__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.request_additions.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    request_additions__puzzle_hash = ProtoField.bytes(
        "chia.data.request_additions.puzzle_hashes",
        "puzzle_hash (bytes32)"),


    -- 58 respond_additions / RespondAdditions
    respond_additions__height = ProtoField.uint32(
        "chia.data.respond_additions.height",
        "height (uint32)"),
    respond_additions__header_hash = ProtoField.bytes(
        "chia.data.respond_additions.header_hash",
        "header_hash (bytes32)"),
    respond_additions__coins__count = ProtoField.uint32(
        "chia.data.respond_additions.coins.count",
        "{coins.count (uint32)}"),
    respond_additions__coins__bytes32 = ProtoField.bytes(
        "chia.data.respond_additions.coins.bytes32",
        "bytes32 (bytes32)"),
    respond_additions__coins__coin__count= ProtoField.uint32(
        "chia.data.respond_additions.coins.coin.coint",
        "{list[Coin].count (uint32)}"),
    respond_additions__proofs__option = ProtoField.bool(
        "chia.data.respond_additions.proofs.option",
        "{proofs.option (bool)}"),
    respond_additions__proofs__count = ProtoField.uint32(
        "chia.data.respond_additions.proofs.count",
        "{proofs.count (uint32)}"),
    respond_additions__proofs__proof_tuple__bytes32 = ProtoField.bytes(
        "chia.data.respond_additions.proofs.proof.bytes32",
        "bytes32 (bytes32)"),
    respond_additions__proofs__proof_tuple__bytes__length = ProtoField.uint32(
        "chia.data.respond_additions.proofs.proof.bytes.length",
        "{bytes.length (uint32)}"),
    respond_additions__proofs__proof_tuple__bytes = ProtoField.bytes(
        "chia.data.respond_additions.proofs.proof.bytes",
        "bytes (bytes)"),
    respond_additions__proofs__proof_tuple__bytes2__option = ProtoField.bool(
        "chia.data.respond_additions.proofs.proof.bytes2__option",
        "{bytes.option (bool)}"),
    respond_additions__proofs__proof_tuple__bytes2__length = ProtoField.uint32(
        "chia.data.respond_additions.proofs.proof.bytes2__length",
        "{bytes.length (uint32)}"),
    respond_additions__proofs__proof_tuple__bytes2 = ProtoField.bytes(
        "chia.data.respond_additions.proofs.proof.bytes2",
        "bytes (bytes)"),


    -- 59 reject_additions_request / RejectAdditionsRequest
    reject_additions_request__height = ProtoField.uint32(
        "chia.data.reject_additions_request.height",
        "height (uint32)"),
    reject_additions_request__header_hash = ProtoField.uint32(
        "chia.data.reject_additions_request.header_hash",
        "header_hash (bytes32)"),


    -- 60 request_header_blocks / RequestHeaderBlocks
    request_header_blocks__start_height = ProtoField.uint32(
        "chia.data.request_header_blocks.start_height",
        "start_height (uint32)"),
    request_header_blocks__end_height = ProtoField.uint32(
        "chia.data.request_header_blocks.end_height",
        "end_height (uint32)"),


    -- 61 reject_header_blocks / RejectHeaderBlocks
    reject_header_blocks__start_height = ProtoField.uint32(
        "chia.data.reject_header_blocks.start_height",
        "start_height (uint32)"),
    reject_header_blocks__end_height = ProtoField.uint32(
        "chia.data.reject_header_blocks.end_height",
        "end_height (uint32)"),


    -- 62 respond_header_blocks / RespondHeaderBlocks
    respond_header_blocks__start_height = ProtoField.uint32(
        "chia.data.respond_header_blocks.start_height",
        "start_height (uint32)"),
    respond_header_blocks__end_height = ProtoField.uint32(
        "chia.data.respond_header_blocks.end_height",
        "end_height (uint32)"),


    -- 63 request_peers_introducer / RequestPeersIntroducer


    -- 64 respond_peers_introducer / RespondPeersIntroducer
    respond_peers_introducer__peer_list__count = ProtoField.uint32(
        "chia.data.respond_peers_introducer.peer_list.count",
        "{peer_list.count (uint32)}"),


    -- 65 farm_new_block / FarmNewBlockProtocol
    farm_new_block__puzzle_hash = ProtoField.bytes(
        "chia.data.farm_new_block.puzzle_hash",
        "puzzle_hash (bytes32)"),


    -- 66 new_signage_point_harvester / NewSignagePointHarvester
    new_signage_point_harvester__challenge_hash = ProtoField.bytes(
        "chia.data.new_signage_point_harvester.challenge_hash",
        "challenge_hash (bytes32)"),
    new_signage_point_harvester__difficulty = ProtoField.uint64(
        "chia.data.new_signage_point_harvester.difficulty",
        "difficulty (uint64)"),
    new_signage_point_harvester__sub_slot_iters = ProtoField.uint64(
        "chia.data.new_signage_point_harvester.sub_slot_iters",
        "sub_slot_iters (uint64)"),
    new_signage_point_harvester__signage_point_index = ProtoField.uint8(
        "chia.data.new_signage_point_harvester.signage_point_index",
        "signage_point_index (uint8)"),
    new_signage_point_harvester__sp_hash = ProtoField.bytes(
        "chia.data.new_signage_point_harvester.sp_hash",
        "sp_hash (bytes32)"),
    new_signage_point_harvester__pool_difficulties__count = ProtoField.uint32(
        "chia.data.new_signage_point_harvester.pool_difficulties.count",
        "{pool_difficulties.count}"),
    new_signage_point_harvester__PoolDifficulty__difficulty = ProtoField.uint64(
        "chia.data.new_signage_point_harvester.PoolDifficulty.difficulty",
        "difficulty (uint64)"),
    new_signage_point_harvester__PoolDifficulty__sub_slot_iters = ProtoField.uint64(
        "chia.data.new_signage_point_harvester.PoolDifficulty.sub_slot_iters",
        "sub_slot_iters (uint64)"),
    new_signage_point_harvester__PoolDifficulty__pool_contract_puzzle_hash = ProtoField.bytes(
        "chia.data.new_signage_point_harvester.PoolDifficulty.pool_contract_puzzle_hash",
        "pool_contract_puzzle_hash (bytes32)"),
    new_signage_point_harvester__filter_prefix_bits = ProtoField.uint8(
        "chia.data.new_signage_point_harvester.filter_prefix_bits",
        "filter_prefix_bits (uint8)"),


    -- 67 request_plots / RequestPlots


    -- 68 respond_plots / RespondPlots
    respond_plots__failed_to_open_filenames__count = ProtoField.uint32(
        "chia.data.respond_plots.failed_to_open_filenames.count",
        "{failed_to_open_filenames.count (uint32)}"),
    respond_plots__failed_to_open_filenames__filename__length = ProtoField.uint32(
        "chia.data.respond_plots.failed_to_open_filenames.filename.length",
        "{filename.length (uint32)}"),
    respond_plots__failed_to_open_filenames__filename = ProtoField.string(
        "chia.data.respond_plots.failed_to_open_filenames.filename",
        "filename (str)"),
    respond_plots__no_key_filenames__count = ProtoField.uint32(
        "chia.data.respond_plots.no_key_filenames.count",
        "{no_key_filenames.count (uint32)}"),
    respond_plots__no_key_filenames__filename__length = ProtoField.uint32(
        "chia.data.respond_plots.no_key_filenames.filename.length",
        "{filename.length (uint32)}"),
    respond_plots__no_key_filenames__filename = ProtoField.string(
        "chia.data.respond_plots.no_key_filenames.filename",
        "filename (str)"),


    -- 69 coin_state_update / CoinStateUpdate
    coin_state_update__height = ProtoField.uint32(
        "chia.data.coin_state_update.height",
        "height (uint32)"),
    coin_state_update__fork_height = ProtoField.uint32(
        "chia.data.coin_state_update.fork_height",
        "fork_height (uint32)"),
    coin_state_update__peak_hash = ProtoField.bytes(
        "chia.data.coin_state_update.peak_hash",
        "peak_hash (bytes32)"),
    coin_state_update__items__count = ProtoField.uint32(
        "chia.data.coin_state_update.items.count",
        "{items.count (uint32)}"),
    

    -- 70 register_for_ph_updates / RegisterForPhUpdates
    register_for_ph_updates__puzzle_hash = ProtoField.bytes(
        "chia.data.register_for_ph_updates.puzzle_hash",
        "puzzle_hash (bytes32)"),
    register_for_ph_updates__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.register_for_ph_updates.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    register_for_ph_updates__min_height = ProtoField.uint32(
        "chia.data.register_for_ph_updates.min_height",
        "min_height (uint32)"),


    -- 71 respond_to_ph_updates / RespondToPhUpdates
    respond_to_ph_updates__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.to_ph_update.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    respond_to_ph_updates__puzzle_hash = ProtoField.bytes(
        "chia.data.respond_to_ph_updates.puzzle_hash",
        "puzzle_hash (Bytes32)"),
    respond_to_ph_updates__min_height = ProtoField.uint32(
        "chia.data.respond_to_ph_updates.min_height",
        "min_height (u32)"),
    respond_to_ph_updates__coin_states__count = ProtoField.uint32(
        "chia.data.respond_to_ph_updates.coin_states.count",
        "{coin_states.count (uint32)}"),
    

    -- 72 register_for_coin_updates / RegisterForCoinUpdates
    register_for_coin_updates__coin_ids__count = ProtoField.uint32(
        "chia.data.register_for_coin_updates.coin_ids.count",
        "{coin_ids.count (uint32)}"),
    register_for_coin_updates__coin_ids__coin_id = ProtoField.bytes(
        "chia.data.register_for_coin_updates.coin_ids.coin_id",
        "coin_id (bytes32)"),
    register_for_coin_updates__min_height = ProtoField.uint32(
        "chia.data.register_for_coin_updates.min_height",
        "min_height (uint32)"),


    -- 73 respond_to_coin_updates / RespondToCoinUpdates
    respond_to_coin_updates__coin_ids__count = ProtoField.uint32(
        "chia.data.respond_to_coin_updates.coin_ids.count",
        "{coin_ids.count (uint32)}"),
    respond_to_coin_updates__coin_ids__coin_id = ProtoField.bytes(
        "chia.data.respond_to_coin_updates.coin_ids.coin_id",
        "coin_id (bytes32)"),
    respond_to_coin_updates__min_height = ProtoField.uint32(
        "chia.data.respond_to_coin_updates.min_height",
        "min_height (uint32)"),
    respond_to_coin_updates__coin_states__count = ProtoField.uint32(
        "chia.data.respond_to_coin_updates.coin_states.count",
        "{coin_states.count (uint32)}"),


    -- 74 request_children / RequestChildren
    request_children__coin_name = ProtoField.bytes(
        "chia.data.request_children.coin_name",
        "coin_name (bytes32)"),


    -- 75 respond_children / RespondChildren
    respond_children__coin_states__count = ProtoField.uint32(
        "chia.data.respond_children.coin_states.count",
        "{coin_states.count (uint32)}"),
    

    -- 76 request_ses_hashes / RequestSESInfo
    request_ses_hashes__start_height = ProtoField.uint32(
        "chia.data.request_ses_hashes.start_height",
        "start_height (uint32)"),
    request_ses_hashes__end_height = ProtoField.uint32(
        "chia.data.request_ses_hashes.end_height",
        "end_height (uint32)"),


    -- 77 respond_ses_hashes / RespondSESInfo
    respond_ses_hashes__reward_chain_hash__count = ProtoField.uint32(
        "chia.data.respond_ses_hashes.reward_chain_hash.count",
        "{reward_chain_hash.count (uint32)}"),
    respond_ses_hashes__reward_chain_hash = ProtoField.bytes(
        "chia.data.respond_ses_hashes.reward_chain_hash",
        "reward_chain_hash (bytes32)"),
    respond_ses_hashes__heights__count = ProtoField.uint32(
        "chia.data.respond_ses_hashes.heights.count",
        "{heights.count (uint32)}"),
    respond_ses_hashes__heights__heights_list__count = ProtoField.uint32(
        "chia.data.respond_ses_hashes.heights.heights_list.count",
        "{heights_list.count (uint32)}"),
    respond_ses_hashes__heights__heights_list__height = ProtoField.uint32(
        "chia.data.respond_ses_hashes.heights_list.height",
        "height (uint32)"),


    -- 78 plot_sync_start / PlotSyncStart
    plot_sync_start__initial = ProtoField.bool(
        "chia.data.plot_sync_start.initial",
        "initial (bool)"),
    plot_sync_start__last_sync_id = ProtoField.uint64(
        "chia.data.plot_sync_start.last_sync_id",
        "last_sync_id (uint64)"),
    plot_sync_start__plot_file_count = ProtoField.uint32(
        "chia.data.plot_sync_start.plot_file_count",
        "{plot_file.count (uint32)}"),
    plot_sync_start__harvesting_mode = ProtoField.uint8(
        "chia.data.plot_sync_start.harvesting_mode",
        "harvesting_mode (uint8)"),
    plot_sync_start__harvesting_mode__enum = ProtoField.string(
        "chia.data.plot_sync_start.harvesting_mode.enum",
        "harvesting_mode.enum (str)"),


    -- 79 plot_sync_loaded / PlotSyncPlotList
    plot_sync_loaded__data__count = ProtoField.uint32(
        "chia.data.plot_sync_loaded.data.count",
        "{data.count (uint32)}"),
    plot_sync_loaded__final = ProtoField.bool(
        "chia.data.plot_sync_loaded.final",
        "final (bool)"),


    -- 80 plot_sync_removed / PlotSyncPathtList

    -- 81 plot_sync_invalid / PlotSyncPathtList

    -- 82 plot_sync_keys_missing / PlotSyncPathtList

    -- 83 plot_sync_duplicates / PlotSyncPathtList


    -- 84 plot_sync_done / PlotSyncDone
    plot_sync_done__duration = ProtoField.uint64(
        "chia.data.plot_sync_done.duration",
        "duration (uint64)"),
    

    -- 85 plot_sync_response / PlotSyncResponse
    plot_sync_response__message_type = ProtoField.uint16(
        "chia.data.plot_sync_response.message_type",
        "message_type (uint16)"),
    plot_sync_response__error__option = ProtoField.bool(
        "chia.data.plot_sync_response.error.option",
        "{error.option (bool)}"),
    plot_sync_response__error__code = ProtoField.int16(
        "chia.data.plot_sync_response.error.code",
        "code (int16)"),
    plot_sync_response__error__code__enum = ProtoField.string(
        "chia.data.plot_sync_response.error.code.enum",
        "code.enum (str)"),
    plot_sync_response__error__message__length = ProtoField.uint32(
        "chia.data.plot_sync_response.error.message.length",
        "{message.length (uint32)}"),
    plot_sync_response__error__message = ProtoField.string(
        "chia.data.plot_sync_response.error.message",
        "message (str)"),
    plot_sync_response__error__expected_identifier__option = ProtoField.bool(
        "chia.data.plot_sync_response.error.expected_identifier.option",
        "{expected_identifier.option (bool)}"),


    -- 86 request_block_headers / RequestBlockHeaders
    request_block_headers__start_height = ProtoField.uint32(
        "chia.data.request_block_headers.start_height",
        "start_height (uint32)"),
    request_block_headers__end_height = ProtoField.uint32(
        "chia.data.request_block_headers.end_height",
        "end_height (uint32)"),
    request_block_headers__return_filter = ProtoField.bool(
        "chia.data.request_block_headers.return_filter",
        "return_filter (bool)"),


    -- 87 reject_block_headers / RejectBlockHeaders
    reject_block_headers__start_height = ProtoField.uint32(
        "chia.data.reject_block_headers.start_height",
        "start_height (uint32)"),
    reject_block_headers__end_height = ProtoField.uint32(
        "chia.data.reject_block_headers.end_height",
        "end_height (uint32)"),


    -- 88 respond_block_headers / RespondBlockHeaders
    respond_block_headers__start_height = ProtoField.uint32(
        "chia.data.respond_block_headers.start_height",
        "start_height (uint32)"),
    respond_block_headers__end_height = ProtoField.uint32(
        "chia.data.respond_block_headers.end_height",
        "end_height (uint32)"),
    respond_block_headers__header_blocks__count = ProtoField.uint32(
        "chia.data.respond_block_headers.header_blocks.count",
        "{header_blocks_count (uint32)}"),


    -- 89 request_fee_estimates / RequestFeeEstimates
    request_fee_estimates__time_targets__count = ProtoField.uint32(
        "chia.data.request_fee_estimates.time_targets.count",
        "{time_targets.count (uint32)}"),
    request_fee_estimates__time_targets__time_target = ProtoField.uint64(
        "chia.data.request_fee_estimates.time_targets.time_target",
        "time_target (uint64)"),


    -- 90 respond_fee_estimates / RespondFeeEstimates
    respond_fee_estimates__error__option = ProtoField.bool(
        "chia.data.respond_fee_estimates.error.option",
        "{error.option (bool)}"),
    respond_fee_estimates__error__length = ProtoField.uint32(
        "chia.data.respond_fee_estimates.error.length",
        "{error.length (uint32)}"),
    respond_fee_estimates__error = ProtoField.string(
        "chia.data.respond_fee_estimates.error",
        "error (str)"),
    respond_fee_estimates__estimates__count = ProtoField.uint32(
        "chia.data.respond_fee_estimates.estimates.count",
        "{estimates.count (uint32)}"),
    respond_fee_estimates__estimates__error__option = ProtoField.bool(
        "chia.data.respond_fee_estimates.estimates.error.option",
        "{error.option (bool)}"),
    respond_fee_estimates__estimates__error__length = ProtoField.uint32(
        "chia.data.respond_fee_estimates.estimates.error.length",
        "{error.length (uint32)}"),
    respond_fee_estimates__estimates__error = ProtoField.string(
        "chia.data.respond_fee_estimates.estimates.error",
        "error (str)"),
    respond_fee_estimates__estimates__time_target = ProtoField.uint64(
        "chia.data.respond_fee_estimates.estimates.time_target",
        "time_target (uint64)"),
    respond_fee_estimates__estimates__estimated_fee_rate__mojos_per_clvm_cost = ProtoField.uint64(
        "chia.data.respond_fee_estimates.estimates.estimated_fee_rate.mojos_per_clvm_cost",
        "mojos_per_clvm_cost (uint64)"),


    -- 91 (deprecated) none_response / NoneResponse


    -- 92 new_unfinished_block2 / NewUnfinishedBlock2
    new_unfinished_block2__unfinished_reward_hash = ProtoField.bytes(
        "chia.data.new_unfinished_block2.unfinished_reward_hash",
        "unfinished_reward_hash (bytes32)"),
    new_unfinished_block2__foliage_hash__option = ProtoField.bool(
        "chia.data.new_unfinished_block2.foliage_hash.option",
        "{foliage_hash.option (bool)}"),
    new_unfinished_block2__foliage_hash = ProtoField.bytes(
        "chia.data.new_unfinished_block2.foliage_hash",
        "foliage_hash (bytes32)"),


    -- 93 request_unfinished_block2 / RequestUnfinishedBlock2
    request_unfinished_block2__unfinished_reward_hash = ProtoField.bytes(
        "chia.data.request_unfinished_block2.unfinished_reward_hash",
        "unfinished_reward_hash (bytes32)"),
    request_unfinished_block2__foliage_hash__option = ProtoField.bool(
        "chia.data.request_unfinished_block2.foliage_hash.option",
        "{foliage_hash.option (bool)}"),
    request_unfinished_block2__foliage_hash = ProtoField.bytes(
        "chia.data.request_unfinished_block2.foliage_hash",
        "foliage_hash (bytes32)"),


    -- 94 request_remove_puzzle_subscriptions / RequestRemovePuzzleSubscriptions
    request_remove_puzzle_subscriptions__puzzle_hashes__option = ProtoField.bool(
        "chia.data.request_remove_puzzle_subscriptions.puzzle_hashes.option",
        "{puzzle_hashes.option (bool)}"),
    request_remove_puzzle_subscriptions__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.request_remove_puzzle_subscriptions.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    request_remove_puzzle_subscriptions__puzzle_hash = ProtoField.bytes(
        "chia.data.request_remove_puzzle_subscriptions.puzzle_hashes.puzzle_hash",
        "puzzle_hash (bytes32)"),


    -- 95 respond_remove_puzzle_subscriptions / RespondRemovePuzzleSubscriptions
    respond_remove_puzzle_subscriptions__puzzle_hashes__option = ProtoField.bool(
        "chia.data.respond_remove_puzzle_subscriptions.puzzle_hashes.option",
        "{puzzle_hashes.option (bool)}"),
    respond_remove_puzzle_subscriptions__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.respond_remove_puzzle_subscriptions.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    respond_remove_puzzle_subscriptions__puzzle_hash = ProtoField.bytes(
        "chia.data.respond_remove_puzzle_subscriptions.puzzle_hashes.puzzle_hash",
        "puzzle_hash (bytes32)"),
    

    -- 96 request_remove_coin_subscriptions / RequestRemoveCoinSubscriptions
    request_remove_coin_subscriptions__puzzle_hashes__option = ProtoField.bool(
        "chia.data.request_remove_coin_subscriptions.puzzle_hashes.option",
        "{puzzle_hashes.option (bool)}"),
    request_remove_coin_subscriptions__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.request_remove_coin_subscriptions.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    request_remove_coin_subscriptions__puzzle_hash = ProtoField.bytes(
        "chia.data.request_remove_coin_subscriptions.puzzle_hashes.puzzle_hash",
        "puzzle_hash (bytes32)"),


    -- 97 respond_remove_coin_subscriptions / RespondRemoveCoinSubscriptions
    respond_remove_coin_subscriptions__coin_ids__count = ProtoField.uint32(
        "chia.data.respond_remove_coin_subscriptions.coin_ids.count",
        "{coin_ids.count (uint32)}"),
    respond_remove_coin_subscriptions__coin_ids__coin_id = ProtoField.bytes(
        "chia.data.respond_remove_coin_subscriptions.coin_ids.coin_id",
        "coin_id (bytes32)"),


    -- 98 request_puzzle_state / RequestPuzzleState
    request_puzzle_state__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.request_puzzle_state.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    request_puzzle_state__puzzle_hashes = ProtoField.bytes(
        "chia.data.request_puzzle_state.puzzle_hash",
        "puzzle_hash (bytes32)"),
    request_puzzle_state__previous_height__option = ProtoField.bool(
        "chia.data.request_puzzle_state.previous_height.option",
        "{previous_height.option (bool)}"),
    request_puzzle_state__previous_height = ProtoField.uint32(
        "chia.data.request_puzzle_state.previous_height",
        "previous_height (uint32)"),
    request_puzzle_state__header_hash = ProtoField.bytes(
        "chia.data.request_puzzle_state.header_hash",
        "header_hash (bytes32)"),
    request_puzzle_state__filters__include_spent = ProtoField.bool(
        "chia.data.request_puzzle_state.filters.include_spent",
        "include_spent (bool)"),
    request_puzzle_state__filters__include_unspent = ProtoField.bool(
        "chia.data.request_puzzle_state.filters.include_unspent",
        "include_unspent (bool)"),
    request_puzzle_state__filters__include_hinted = ProtoField.bool(
        "chia.data.request_puzzle_state.filters.include_hinted",
        "include_hinted (bool)"),
    request_puzzle_state__filters__min_amount = ProtoField.uint64(
        "chia.data.request_puzzle_state.filters.filters__min_amount",
        "filters__min_amount (uint64)"),
    request_puzzle_state__subscribe_when_finished = ProtoField.bool(
        "chia.data.request_puzzle_state.subscribe_when_finished",
        "subscribe_when_finished (bool)"),


    -- 99 respond_puzzle_state / RespondPuzzleState
    respond_puzzle_state__puzzle_hashes__count = ProtoField.uint32(
        "chia.data.respond_puzzle_state.puzzle_hashes.count",
        "{puzzle_hashes.count (uint32)}"),
    respond_puzzle_state__puzzle_hashes__puzzle_hash = ProtoField.bytes(
        "chia.data.respond_puzzle_state.puzzle_hashes.puzzle_hash",
        "puzzle_hash (bytes32)"),
    respond_puzzle_state__height = ProtoField.uint32(
        "chia.data.respond_puzzle_state.height",
        "height (uint32)"),
    respond_puzzle_state__header_hash = ProtoField.bytes(
        "chia.data.respond_puzzle_state.header_hash",
        "header_hash (bytes32)"),
    respond_puzzle_state__is_finished = ProtoField.bool(
        "chia.data.respond_puzzle_state.is_finished",
        "is_finished (bool)"),
    respond_puzzle_state__coin_states__count = ProtoField.uint32(
        "chia.data.respond_puzzle_state.coin_states.count",
        "{coin_states.count (uint32)}"),


    -- 100 reject_puzzle_state / RejectPuzzleState
    reject_puzzle_state__reason = ProtoField.uint8(
        "chia.data.reject_puzzle_state.reason",
        "reason (uint8)"),
    reject_puzzle_state__reason__enum = ProtoField.string(
        "chia.data.reject_puzzle_state.reason.enum",
        "reason.enum (str)"),


    -- 101 request_coin_state / RequestCoinState
    request_coin_state__coin_ids__count = ProtoField.uint32(
        "chia.data.request_coin_state.coin_ids.count",
        "{coin_ids.count (uint32)}"),
    request_coin_state__coin_ids__coin_id = ProtoField.bytes(
        "chia.data.request_coin_state.coin_ids.coin_id",
        "coin_id (bytes32)"),
    request_coin_state__previous_height__option = ProtoField.bool(
        "chia.data.request_coin_state.previous_height.option",
        "{previous_height.option (bool)}"),
    request_coin_state__previous_height = ProtoField.uint32(
        "chia.data.request_coin_state.previous_height",
        "previous_height (uint32)"),
    request_coin_state__header_hash = ProtoField.bytes(
        "chia.data.request_coin_state.header_hash",
        "header_hash (bytes32)"),
    request_coin_state__subscribe = ProtoField.bool(
        "chia.data.request_coin_state.subscribe",
        "subscribe_when_finished (bool)"),


    -- 102 respond_coin_state / RespondCoinState
    respond_coin_state__coin_ids__count = ProtoField.uint32(
        "chia.data.respond_coin_state.coin_ids.count",
        "{coin_ids.count (uint32)}"),
    respond_coin_state__coin_ids__coin_id = ProtoField.uint32(
        "chia.data.respond_coin_state.coin_ids.coin_id",
        "coin_id (bytes32)"),
    respond_coin_state__coin_states__count = ProtoField.uint32(
        "chia.data.respond_coin_state.coin_states.count",
        "{coin_states.count (uint32)}"),


    -- 103 reject_coin_state / RejectCoinState
    reject_coin_state__reason = ProtoField.uint8(
        "chia.data.reject_coin_state.reason",
        "reason (uint8)"),
    reject_coin_state__reason__enum = ProtoField.string(
        "chia.data.reject_coin_state.reason.enum",
        "reason.enum (str)"),


    -- 104 mempool_items_added / MempoolItemsAdded
    mempool_items_added__transaction_ids__count = ProtoField.uint32(
        "chia.data.mempool_items_added.transaction_ids.count",
        "{transaction_id.count (uint32)}"),
    mempool_items_added__transaction_ids__transaction_id = ProtoField.bytes(
        "chia.data.mempool_items_added.transaction_ids.transaction_id",
        "transaction_id (bytes32)"),


    -- 105 mempool_items_removed / MempoolItemsRemoved
    mempool_items_removed__removed_items__count = ProtoField.uint32(
        "chia.data.mempool_items_removed.removed_items.count",
        "{removed_items.count (uint32)}"),
    mempool_items_removed__removed_items__transaction_id = ProtoField.bytes(
        "chia.data.mempool_items_removed.removed_items.transaction_id",
        "transaction_id (bytes32)"),
    mempool_items_removed__removed_items__reason = ProtoField.uint8(
        "chia.data.mempool_items_removed.removed_items.reason",
        "reason (uint8)"),
    mempool_items_removed__removed_items__reason__enum = ProtoField.string(
        "chia.data.mempool_items_removed.removed_items.reason.enum",
        "{reason.enum (str)}"),


    -- 106 request_cost_info / RequestCostInfo


    -- 107 respond_cost_info / RespondCostInfo
    respond_cost_info__max_transaction_cost = ProtoField.uint64(
        "chia.data.respond_cost_info.max_transaction_cost",
        "max_transaction_cost (int64)"),
    respond_cost_info__max_block_cost = ProtoField.uint64(
        "chia.data.respond_cost_info.max_block_cost",
        "max_block_cost (uint64)"),
    respond_cost_info__max_mempool_cost = ProtoField.uint64(
        "chia.data.respond_cost_info.max_mempool_cost",
        "max_mempool_cost (uint64)"),
    respond_cost_info__mempool_cost = ProtoField.uint64(
        "chia.data.respond_cost_info.mempool_cost",
        "mempool_cost (uint64)"),
    respond_cost_info__mempool_fee = ProtoField.uint64(
        "chia.data.respond_cost_info.mempool_fee",
        "mempool_fee (uint64)"),
    respond_cost_info__bump_fee_per_cost = ProtoField.uint8(
        "chia.data.respond_cost_info.bump_fee_per_cost",
        "bump_fee_per_cost (uint8)"),
    

    -- 255 error / Error
    error__code = ProtoField.uint16(
        "chia.data.error.code",
        "code (uint16)"),
    error__message__length = ProtoField.uint32(
        "chia.data.error.message.length",
        "{message.length (uint32)}"),
    error__message = ProtoField.string(
        "chia.data.error.message",
        "message (str)"),
    error__data__option = ProtoField.bool(
        "chia.data.error.data.option",
        "{data.option (bool)}"),
    error__data__length = ProtoField.uint32(
        "chia.data.error.data.length",
        "{data.length (uint32)}"),
    error__data = ProtoField.uint32(
        "chia.data.error.data",
        "data (bytes)"),

--------------------------------------------------------------------------------
-- ProtoField variables of functions that get called by multiple message types
--------------------------------------------------------------------------------

    -- misc. dissector fields
    dissector__deprecated_message_type = ProtoField.bytes(
        "dissector.deprecated_message_type",
        "{dissector.deprecated_message_type (bytes)}"),
    dissector__unknown_message_type = ProtoField.bytes(
        "dissector.unknown_message_type",
        "{dissector.unknown_message_type (bytes)}"),
    dissector__error = ProtoField.string("dissector.error",
        "{dissector.error (str)}"),


    -- Block
    Block__finished_sub_slots__count = ProtoField.uint32(
        "chia.data.Block.finished_sub_slots.count",
        "{finished_sub_slots.count (uint32)}"),
    Block__reward_chain_sp_proof__option = ProtoField.bool(
        "chia.data.reward_chain_sp_proof.option",
        "{reward_chain_sp_proof.option (bool)}"),
    Block__challenge_chain_sp_proof__option = ProtoField.bool(
        "chia.data.challenge_chain_sp_proof.option",
        "{challenge_chain_sp_proof.option (bool)}"),
    Block__infused_challenge_chain_ip_proof__option = ProtoField.bool(
        "chia.data.Block.infused_challenge_chain_ip_proof.option",
        "{reward_chain_sp_proof.option (bool)}"),
    Block__foliage_transaction_block__option = ProtoField.bool(
        "chia.data.Block.foliage_transaction_block.option",
        "{foliage_transaction_block.option (bool)}"),
    Block__transactions_info__option = ProtoField.bool(
        "chia.data.Block.transactions_info.option",
        "{transactions_info.option (bool)}"),
    Block__transactions_info__generator_root = ProtoField.bytes(
        "chia.data.Block.transactions_info.generator_root",
        "generator_root (Bytes32)"),
    Block__transactions_info__generator_refs_root = ProtoField.bytes(
        "chia.data.Block.transactions_info.generator_refs_root",
        "generator_refs_root (Bytes32)"),
    Block__transactions_info__aggregated_signature = ProtoField.bytes(
        "chia.data.Block.transactions_info.aggregated_signature",
        "aggregated_signature (G2Element)"),
    Block__transactions_info__fees = ProtoField.uint64(
        "chia.data.Block.transactions_info.fees",
        "fees (u64)"),
    Block__transactions_info__cost = ProtoField.uint64(
        "chia.data.Block.transactions_info.cost",
        "cost (u64)"),
    Block__transactions_info__reward_claims_incorporated__count = ProtoField.uint32(
        "chia.data.Block.transactions_info.reward_claims_incorporated.count",
        "{reward_claims_incorporated.count (uint32)}"),
    Block__transaction_generator= ProtoField.bytes(
        "chia.data.Block.transaction_generator",
        "transaction_generator (Program)"),


    -- ClassgroupElement
    ClassgroupElement__data = ProtoField.bytes(
        "chia.data.ClassgroupElement.data",
        "data (Bytes100)"),


    -- Coin
    Coin__parent_coin_info = ProtoField.bytes(
        "chia.data.Coin.parent_coin_info",
        "parent_coin_info (Bytes32)"),
    Coin__puzzle_hash = ProtoField.bytes(
        "chia.data.Coin.puzzle_hash",
        "puzzle_hash (Bytes32)"),
    Coin__amount = ProtoField.uint64(
        "chia.data.Coin.amount",
        "amount (u64)"),


    -- CoinState
    CoinState__spent_height__option = ProtoField.bool(
        "chia.data.CoinState.spent_height.option",
        "{spent_height.option (bool)}"),
    CoinState__spent_height = ProtoField.uint32(
        "chia.data.CoinState.spent_height",
        "spent_height (u32)"),
    CoinState__created_height__option = ProtoField.bool(
        "chia.data.CoinState.created_height.option",
        "{created_height.option (bool)}"),
    CoinState__created_height = ProtoField.uint32(
        "chia.data.CoinState.created_height",
        "created_height (u32)"),


    -- EndOfSubSlotBundle
    EndOfSubSlotBundle__challenge_chain__infused_challenge_chain_sub_slot_hash__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.challenge_chain.infused_challenge_chain_sub_slot_hash.option",
        "{infused_challenge_chain_sub_slot_hash.option (bool)}"),
    EndOfSubSlotBundle__challenge_chain__infused_challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.EndOfSubSlotBundle.challenge_chain.infused_challenge_chain_sub_slot_hash",
        "infused_challenge_chain_sub_slot_hash (Bytes32)"),
    EndOfSubSlotBundle__challenge_chain__subepoch_summary_hash__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.challenge_chain.subepoch_summary_hash.option",
        "{subepoch_summary_hash.option (bool)}"),
    EndOfSubSlotBundle__challenge_chain__subepoch_summary_hash = ProtoField.bytes(
        "chia.data.EndOfSubSlotBundle.challenge_chain.subepoch_summary_hash",
        "subepoch_summary_hash (Bytes32)"),
    EndOfSubSlotBundle__challenge_chain__new_sub_slot_iters__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.challenge_chain.new_sub_slot_iters.option",
        "{new_sub_slot_iters.option (bool)}"),
    EndOfSubSlotBundle__challenge_chain__new_sub_slot_iters = ProtoField.uint64(
        "chia.data.EndOfSubSlotBundle.challenge_chain.new_sub_slot_iters",
        "new_sub_slot_iters (u64)"),
    EndOfSubSlotBundle__challenge_chain__new_difficulty__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.challenge_chain.new_difficulty.option",
        "{new_difficulty.option (bool)}"),
    EndOfSubSlotBundle__challenge_chain__new_difficulty = ProtoField.uint64(
        "chia.data.EndOfSubSlotBundle.challenge_chain.new_difficulty",
        "new_difficulty (u64)"),
    EndOfSubSlotBundle__infused_challenge_chain__infused_challenge_chain_end_of_slot_vdf__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.infused_challenge_chain.infused_challenge_chain_end_of_slot_vdf.option",
        "{infused_challenge_chain_end_of_slot_vdf.option (bool)}"),
    EndOfSubSlotBundle__reward_chain__challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.EndOfSubSlotBundle.reward_chain.challenge_chain_sub_slot_hash",
        "challenge_chain_sub_slot_hash (Bytes32)"),
    EndOfSubSlotBundle__reward_chain__infused_challenge_chain_sub_slot_hash__option = ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.reward_chain.infused_challenge_chain_sub_slot_hash.option",
        "{infused_challenge_chain_sub_slot_hash.option (bool)}"),
    EndOfSubSlotBundle__reward_chain__infused_challenge_chain_sub_slot_hash = ProtoField.bytes(
        "chia.data.EndOfSubSlotBundle.reward_chain.infused_challenge_chain_sub_slot_hash",
        "infused_challenge_chain_sub_slot_hash (Bytes32)"),
    EndOfSubSlotBundle__reward_chain__deficit = ProtoField.uint8(
        "chia.data.EndOfSubSlotBundle.reward_chain.deficit",
        "deficit (u8)"),
    EndOfSubSlotBundle__proofs__infused_challenge_chain_slot_proof__option= ProtoField.bool(
        "chia.data.EndOfSubSlotBundle.proofs.infused_challenge_chain_slot_proof.option",
        "{infused_challenge_chain_slot_proof.option (bool)}"),
     

    -- Foliage
    Foliage__prev_block_hash = ProtoField.bytes(
        "chia.data.Foliage.prev_block_hash",
        "prev_block_hash (Bytes32)"),
    Foliage__reward_block_hash = ProtoField.bytes(
        "chia.data.Foliage.reward_block_hash",
        "reward_block_hash (Bytes32)"),
    Foliage__foliage_block_data_signature = ProtoField.bytes(
        "chia.data.Foliage.foliage_block_data_signature",
        "foliage_block_data_signature (G2Element)"),
    Foliage__foliage_transaction_block_hash__option = ProtoField.bool(
        "chia.data.Foliage.foliage_transaction_block_hash.option",
        "{foliage_transaction_block_hash.option (bool)}"),
    Foliage__foliage_transaction_block_hash = ProtoField.bytes(
        "chia.data.Foliage.foliage_transaction_block_hash",
        "foliage_transaction_block_hash (Bytes32)"),
    Foliage__foliage_transaction_block_signature__option = ProtoField.bool(
        "chia.data.Foliage.foliage_transaction_block_signature.option",
        "{foliage_transaction_block_signature.option (bool)}"),
    Foliage__foliage_transaction_block_signature = ProtoField.bytes(
        "chia.data.Foliage.foliage_transaction_block_signature",
        "foliage_transaction_block_signature (G2Element)"),
   

    -- FoliageBlockData
    FoliageBlockData__unfinished_reward_block_hash = ProtoField.bytes(
        "chia.data.FoliageBlockData.unfinished_reward_block_hash",
        "unfinished_reward_block_hash (Bytes32)"),
    FoliageBlockData__pool_target__puzzle_hash = ProtoField.bytes(
        "chia.data.FoliageBlockData.pool_target.puzzle_hash",
        "puzzle_hash (Bytes32)"),
    FoliageBlockData__pool_target__max_height = ProtoField.uint32(
        "chia.data.FoliageBlockData.pool_target.max_height",
        "max_height (u32)"),
    FoliageBlockData__pool_signature__option = ProtoField.bool(
        "chia.data.FoliageBlockData.pool_signature.option",
        "{pool_signature.option (bool)}"),
    FoliageBlockData__pool_signature = ProtoField.bytes(
        "chia.data.FoliageBlockData.pool_signature",
        "pool_signature (G2Element)"),
    FoliageBlockData__farmer_reward_puzzle_hash = ProtoField.bytes(
        "chia.data.FoliageBlockData.farmer_reward_puzzle_hash",
        "farmer_reward_puzzle_hash (Bytes32)"),
    FoliageBlockData__extension_data = ProtoField.bytes(
        "chia.data.FoliageBlockData.extension_data",
        "extension_data (Bytes32)"),
   

    -- FoliageTransactionBlock
    FoliageTransactionBlock__option = ProtoField.bool(
        "chia.data.FoliageTransactionBlock.option",
        "{foliage_transaction_block.option (bool)}"),
    FoliageTransactionBlock__prev_transaction_block_hash = ProtoField.bytes(
        "chia.data.FoliageTransactionBlock.prev_transaction_block_hash",
        "prev_transaction_block_hash (Bytes32)"),
    FoliageTransactionBlock__timestamp = ProtoField.uint64(
        "chia.data.FoliageTransactionBlock.timestamp",
        "timestamp (u64)"),
    FoliageTransactionBlock__filter_hash = ProtoField.bytes(
        "chia.data.FoliageTransactionBlock.filter_hash",
        "filter_hash (Bytes32)"),
    FoliageTransactionBlock__additions_root = ProtoField.bytes(
        "chia.data.FoliageTransactionBlock.additions_root",
        "additions_root (Bytes32)"),
    FoliageTransactionBlock__removals_root = ProtoField.bytes(
        "chia.data.FoliageTransactionBlock.removals_root",
        "removals_root (Bytes32)"),
    FoliageTransactionBlock__transactions_info_hash = ProtoField.bytes(
        "chia.data.FoliageTransactionBlock.transactions_info_hash",
        "transactions_info_hash (Bytes32)"),


    -- FullBlock / UnfinishedBlock
    FullBlock__transactions_generator__option = ProtoField.bool(
        "chia.data.FullBlock.transactions_generator.option",
        "{transactions_generator.option (bool)}"),
    FullBlock__transactions_generator_ref_list__count = ProtoField.uint32(
        "chia.data.FullBlock.transactions_generator_ref_list.count",
        "{transactions_generator_ref_list.count (uint32)}"),
    FullBlock__transactions_generator_ref_list__block_height = ProtoField.uint32(
        "chia.data.FullBlock.transactions_generator_ref_list.block_height",
        "block_height (u32)"),


    -- HeaderBlock
    HeaderBlock__transactions_filter__length = ProtoField.uint32(
        "chia.data.HeaderBlock.transactions_filter.length",
        "{transactions_filter.length (uint32)}"),
    HeaderBlock__transactions_filter = ProtoField.bytes(
        "chia.data.HeaderBlock.transactions_filter",
        "transactions_filter (Bytes)"),
   

    -- Plot
    Plot__filename__length = ProtoField.uint32(
        "chia.data.Plot.filename.length",
        "{filename.length (uint32)}"),
    Plot__filename = ProtoField.string(
        "chia.data.Plot.filename",
        "filename (str)"),
    Plot__size = ProtoField.uint8(
        "chia.data.Plot.size",
        "size (uint8)"),
    Plot__plot_id = ProtoField.bytes(
        "chia.data.Plot.plot_id",
        "plot_id (bytes32)"),
    Plot__pool_public_key__option = ProtoField.bool(
        "chia.data.Plot.pool_public_key.option",
        "{pool_public_key.option (bool)}"),
    Plot__pool_public_key = ProtoField.bytes(
        "chia.data.Plot.pool_public_key",
        "pool_public_key (G1Element)"),
    Plot__pool_contract_puzzle_hash__option = ProtoField.bool(
        "chia.data.Plot.contract_puzzle_hash.option",
        "{contract_puzzle_hash.option (bool)}"),
    Plot__pool_contract_puzzle_hash = ProtoField.bytes(
        "chia.data.Plot.contract_puzzle_hash",
        "contract_puzzle_hash (bytes32)"),
    Plot__plot_public_key = ProtoField.bytes(
        "chia.data.Plot.plot_public_key",
        "plot_public_key (G1Element)"),
    Plot__file_size = ProtoField.uint64(
        "chia.data.Plot.file_size",
        "file_size (uint64)"),
    Plot__time_modified = ProtoField.uint64(
        "chia.data.Plot.time_modified",
        "time_modified (uint64)"),
    Plot__compression_level__option = ProtoField.bool(
        "chia.data.Plot.compression_level.option",
        "{compression_level.option (bool)}"),
    Plot__compression_level = ProtoField.uint8(
        "chia.data.Plot.compression_level",
        "compression_level (uint8)"),


    -- PlotSyncIdentifier
    PlotSyncIdentifier__identifier__timestamp = ProtoField.uint64(
        "chia.data.PlotSyncIdentifier.identifier.timestamp",
        "timestamp (uint64)"),
    PlotSyncIdentifier__identifier__sync_id = ProtoField.uint64(
        "chia.data.PlotSyncIdentifier.identifier.sync_id",
        "sync_id (uint64)"),
    PlotSyncIdentifier__identifier__message_id = ProtoField.uint64(
        "chia.data.PlotSyncIdentifier.identifier.message_id",
        "message_id (uint64)"),


    -- PlotSyncPathList
    PlotSyncPathList__data__count = ProtoField.uint32(
        "chia.data.PlotSyncPathList.data.count",
        "{data.count (uint32)}"),
    PlotSyncPathList__data__length = ProtoField.uint32(
        "chia.data.PlotSyncPathList.data.length",
        "{data.length (uint32)}"),
    PlotSyncPathList__data = ProtoField.string(
        "chia.data.PlotSyncPathList.data",
        "data (str)"),
    PlotSyncPathList__final = ProtoField.bool(
        "chia.data.PlotSyncPathList.final",
        "final (bool)"),


    -- ProofOfSpace
    ProofOfSpace__challenge = ProtoField.bytes(
        "chia.data.ProofOfSpace.challenge",
        "challenge (Bytes32)"),
    ProofOfSpace__pool_public_key__option = ProtoField.bool(
        "chia.data.ProofOfSpace.pool_public_key.option",
        "{pool_public_key.option (bool)}"),
    ProofOfSpace__pool_public_key = ProtoField.bytes(
        "chia.data.ProofOfSpace.pool_public_key",
        "pool_public_key (G1Element)"),
    ProofOfSpace__pool_contract_puzzle_hash__option = ProtoField.bool(
        "chia.data.ProofOfSpace.pool_contract_puzzle_hash.option",
        "{pool_contract_puzzle_hash.option (bool)}"),
    ProofOfSpace__pool_contract_puzzle_hash = ProtoField.bytes(
        "chia.data.ProofOfSpace.pool_contract_puzzle_hash",
        "pool_contract_puzzle_hash (Bytes32)"),
    ProofOfSpace__plot_public_key = ProtoField.bytes(
        "chia.data.ProofOfSpace.plot_public_key",
        "plot_public_key (G1Element)"),
    ProofOfSpace__size = ProtoField.uint8(
        "chia.data.ProofOfSpace.size",
        "size (u8)"),
    ProofOfSpace__proof__length = ProtoField.uint32(
        "chia.data.ProofOfSpace.proof.length",
        "{proof.length (uint32)}"),
    ProofOfSpace__proof = ProtoField.bytes(
        "chia.data.ProofOfSpace.proof",
        "proof (Bytes)"),


    -- RewardChainBlock
    RewardChainBlock__weight = ProtoField.string(
        "chia.data.RewardChainBlock.weight",
        "weight (u128)"),
    RewardChainBlock__height = ProtoField.uint32(
        "chia.data.RewardChainBlock.height",
        "height (uint32)"),
    RewardChainBlock__total_iters = ProtoField.string(
        "chia.data.RewardChainBlock.total_iters",
        "total_iters (u128)"),
    RewardChainBlock__signage_point_index = ProtoField.uint8(
        "chia.data.RewardChainBlock.signage_point_index",
        "signage_point_index (u8)"),
    RewardChainBlock__pos_ss_cc_challenge_hash = ProtoField.bytes(
        "chia.data.RewardChainBlock.pos_ss_cc_challenge_hash",
        "pos_ss_cc_challenge_hash (Bytes32)"),
    RewardChainBlock__challenge_chain_sp_vdf__option = ProtoField.bool(
        "chia.data.RewardChainBlock.challenge_chain_sp_vdf.option",
        "{challenge_chain_sp_vdf.option (bool)}"),
    RewardChainBlock__challenge_chain_sp_signature = ProtoField.bytes(
        "chia.data.RewardChainBlock.challenge_chain_sp_signature",
        "challenge_chain_sp_signature (G2Element)"),
    RewardChainBlock__reward_chain_sp_vdf__option = ProtoField.bool(
        "chia.data.RewardChainBlock.reward_chain_sp_vdf.option",
        "{reward_chain_sp_vdf.option (bool)}"),
    RewardChainBlock__reward_chain_sp_signature = ProtoField.bytes(
        "chia.data.RewardChainBlock.reward_chain_sp_signature",
        "reward_chain_sp_signature (G2Element)"),
    RewardChainBlock__infused_challenge_chain_ip_vdf__option = ProtoField.bool(
        "chia.data.RewardChainBlock.infused_challenge_chain_ip_vdf.option",
        "{infused_challenge_chain_ip_vdf.option (bool)}"),
    RewardChainBlock__is_transaction_block = ProtoField.bool(
        "chia.data.RewardChainBlock.is_transaction_block",
        "is_transaction_block (bool)"),


    -- SpendBundle
    SpendBundle__coin_spends__count = ProtoField.uint32(
        "chia.data.SpendBundle.coin_spends.count",
        "{coin_spends.count (uint32)}"),
    SpendBundle__aggregated_signature = ProtoField.bytes(
        "chia.data.SpendBundle.aggregated_signature",
        "aggregated_signature (G2Element)"),
    SpendBundle__puzzle_reveal = ProtoField.bytes(
        "chia.data.SpendBundle.puzzle_reveal",
        "puzzle_reveal (Program)"),
    SpendBundle__solution = ProtoField.bytes(
        "chia.data.SpendBundle.solution",
        "solution (Program)"),


    -- SubEpochSummary
    SubEpochSummary__prev_subepoch_summary_hash = ProtoField.bytes(
        "chia.data.SubEpochSummary.prev_subepoch_summary_hash",
        "prev_subepoch_summary_hash (Bytes32)"),
    SubEpochSummary__reward_chain_hash = ProtoField.bytes(
        "chia.data.SubEpochSummary.reward_chain_hash",
        "reward_chain_hash (Bytes32)"),
    SubEpochSummary__num_blocks_overflow = ProtoField.uint8(
        "chia.data.SubEpochSummary.num_blocks_overflow",
        "num_blocks_overflow (u8)"),
    SubEpochSummary__new_difficulty__option = ProtoField.bool(
        "chia.data.SubEpochSummary.new_difficulty.option",
        "{new_difficulty.option (bool)}"),
    SubEpochSummary__new_difficulty = ProtoField.uint64(
        "chia.data.SubEpochSummary.new_difficulty",
        "new_difficulty (u64)"),
    SubEpochSummary__new_sub_slot_iters__option = ProtoField.bool(
        "chia.data.SubEpochSummary.new_sub_slot_iters.option",
        "{new_sub_slot_iters.option (bool)}"),
    SubEpochSummary__new_sub_slot_iters = ProtoField.uint64(
        "chia.data.SubEpochSummary.new_sub_slot_iters",
        "new_sub_slot_iters (u64)"),


    -- TimestampedPeerInfo
    TimestampedPeerInfo__host__length = ProtoField.uint32(
        "chia.data.TimestampedPeerInfo.host.length",
        "{host.length (uint32)}"),
    TimestampedPeerInfo__host = ProtoField.string(
        "chia.data.TimestampedPeerInfo.host",
        "host (String)"),
    TimestampedPeerInfo__port = ProtoField.uint16(
        "chia.data.TimestampedPeerInfo.port",
        "port (u16)"),
    TimestampedPeerInfo__timestamp = ProtoField.uint64(
        "chia.data.TimestampedPeerInfo.timestamp",
        "timestamp (u64)"),


    -- VDFInfo
    VDFInfo__challenge = ProtoField.bytes(
        "chia.data.VDFInfo.challenge",
        "challenge (Bytes32)"),
    VDFInfo__number_of_iterations = ProtoField.uint64(
        "chia.data.VDFInfo.number_of_iterations",
        "number_of_iterations (u64)"),


    -- VDFProof
    VDFProof__witness_type = ProtoField.uint8(
        "chia.data.VDFProof.witness_type",
        "witness_type (u8)"),
    VDFProof__witness__length = ProtoField.uint32(
        "chia.data.VDFProof.witness.length",
        "{witness.length (uint32)}"),
    VDFProof__witness = ProtoField.bytes(
        "chia.data.VDFProof.witness",
        "witness (Bytes)"),
    VDFProof__normalized_to_identity = ProtoField.bool(
        "chia.data.VDFProof.normalized_to_identity",
        "normalized_to_identity (bool)"),

} -- pf


-- Register protocol fields
p_chia.fields = pf


--------------------------------------------------------------------------------
-- Enums to augment the capture results (:set_generated())
--------------------------------------------------------------------------------

-- chia-blockchain/chia/protocols/shared_protocol.py
local chia_enum_capabilities = {
    [1] = "BASE",
    [2] = "BLOCK_HEADERS",
    [3] = "RATE_LIMITS_V2",
    [4] = "NONE_RESPONSE",
    [5] = "MEMPOOL_UPDATES"
}

-- chia-blockchain/chia/plot_sync/util.py
local chia_enum_ErrorCodes = {
    [-1] = "unknown",
    [0] = "invalid_state",
    [1] = "invalid_peer_id",
    [2] = "invalid_identifier",
    [3] = "invalid_last_sync_id",
    [4] = "invalid_connection_type",
    [5] = "plot_already_available",
    [6] = "plot_not_available",
    [7] = "sync_ids_match",
}

-- chia-blockchain/chia/plotting/util.py
local chia_enum_HarvestingMode = {
    [1] = "CPU",
    [2] = "GPU",
}

-- chia-blockchain/chia/types/mempool_inclusion_status.py
local chia_enum_MempoolInclusionStatus = {
    [1] = "SUCCESS",
    [2] = "PENDING",
    [3] = "FAILED",
}

-- chia-blockchain/chia/full_node/mempool.py
local chia_enum_MempoolRemoveReason = {
    [1] = "CONFLICT",
    [2] = "BLOCK_INCLUSION",
    [3] = "POOL_FULL",
    [4] = "EXPIRED"
}

-- chia_rs/crates/chia-protocol/src/chia_protocol.rs
local chia_enum_node_type = {
    [1] = "FULL_NODE",
    [2] = "HARVESTER",
    [3] = "FARMER",
    [4] = "TIMELORD",
    [5] = "INTRODUCER",
    [6] = "WALLET",
    [7] = "DATALAYER"
}

-- chia-blockchain/chia/protocols/wallet_protocol.py
local chia_enum_RejectStateReason = {
    [0] = "REORG",
    [1] = "EXCEEDED_SUBSCRIPTION_LIMIT",
}

-- chia-blockchain/chia/protocols/protocol_message_types.py
local chia_enum_ProtocolMessageTypes = {
    -- Shared protocol (all services)
    [1] = "handshake",
    -- [2] undefined
    -- Harvester protocol (harvester <-> farmer)
    [3] = "harvester_handshake",
    -- [4] undefined
    [5] = "new_proof_of_space",
    [6] = "request_signatures",
    [7] = "respond_signatures",
    -- Farmer protocol (farmer <-> full_node)
    [8] = "new_signage_point",
    [9] = "declare_proof_of_space",
    [10] = "request_signed_values",
    [11] = "signed_values",
    [12] = "farming_info",
    -- Timelord protocol (timelord <-> full_node)
    [13] = "new_peak_timelord",
    [14] = "new_unfinished_block_timelord",
    [15] = "new_infusion_point_vdf",
    [16] = "new_signage_point_vdf",
    [17] = "new_end_of_sub_slot_vdf",
    [18] = "request_compact_proof_of_time",
    [19] = "respond_compact_proof_of_time",
    -- Full node protocol (full_node <-> full_node)
    [20] = "new_peak",
    [21] = "new_transaction",
    [22] = "request_transaction",
    [23] = "respond_transaction",
    [24] = "request_proof_of_weight",
    [25] = "respond_proof_of_weight",
    [26] = "request_block",
    [27] = "respond_block",
    [28] = "reject_block",
    [29] = "request_blocks",
    [30] = "respond_blocks",
    [31] = "reject_blocks",
    [32] = "new_unfinished_block",
    [33] = "request_unfinished_block",
    [34] = "respond_unfinished_block",
    [35] = "new_signage_point_or_end_of_sub_slot",
    [36] = "request_signage_point_or_end_of_sub_slot",
    [37] = "respond_signage_point",
    [38] = "respond_end_of_sub_slot",
    [39] = "request_mempool_transactions",
    [40] = "request_compact_vdf",
    [41] = "respond_compact_vdf",
    [42] = "new_compact_vdf",
    [43] = "request_peers",
    [44] = "respond_peers",
    -- Wallet protocol (wallet <-> full_node)
    [45] = "request_puzzle_solution",
    [46] = "respond_puzzle_solution",
    [47] = "reject_puzzle_solution",
    [48] = "send_transaction",
    [49] = "transaction_ack",
    [50] = "new_peak_wallet",
    [51] = "request_block_header",
    [52] = "respond_block_header",
    [53] = "reject_header_request",
    [54] = "request_removals",
    [55] = "respond_removals",
    [56] = "reject_removals_request",
    [57] = "request_additions",
    [58] = "respond_additions",
    [59] = "reject_additions_request",
    [60] = "request_header_blocks",
    [61] = "reject_header_blocks",
    [62] = "respond_header_blocks",
    -- Introducer protocol (introducer <-> full_node)
    [63] = "request_peers_introducer",
    [64] = "respond_peers_introducer",
    -- Simulator protocol
    [65] = "farm_new_block",
    -- New harvester protocol
    [66] = "new_signage_point_harvester",
    [67] = "request_plots",
    [68] = "respond_plots",
    -- More wallet protocol
    [69] = "coin_state_update",
    [70] = "register_for_ph_updates",
    [71] = "respond_to_ph_updates",
    [72] = "register_for_coin_updates",
    [73] = "respond_to_coin_updates",
    [74] = "request_children",
    [75] = "respond_children",
    [76] = "request_ses_hashes",
    [77] = "respond_ses_hashes",
    -- New harvester protocol
    [78] = "plot_sync_start",
    [79] = "plot_sync_loaded",
    [80] = "plot_sync_removed",
    [81] = "plot_sync_invalid",
    [82] = "plot_sync_keys_missing",
    [83] = "plot_sync_duplicates",
    [84] = "plot_sync_done",
    [85] = "plot_sync_response",
    -- More wallet protocol
    [86] = "request_block_headers",
    [87] = "reject_block_headers",
    [88] = "respond_block_headers",
    [89] = "request_fee_estimates",
    [90] = "respond_fee_estimates",
    -- Full node protocol
    [91] = "none_response", -- deprecated
    -- New Full node protocol messages
    [92] = "new_unfinished_block2",
    [93] = "request_unfinished_block2",
    -- New wallet sync protocol
    [94] = "request_remove_puzzle_subscriptions",
    [95] = "respond_remove_puzzle_subscriptions",
    [96] = "request_remove_coin_subscriptions",
    [97] = "respond_remove_coin_subscriptions",
    [98] = "request_puzzle_state",
    [99] = "respond_puzzle_state",
    [100] = "reject_puzzle_state",
    [101] = "request_coin_state",
    [102] = "respond_coin_state",
    [103] = "reject_coin_state",
    -- Wallet protocol mempool updates
    [104] = "mempool_items_added",
    [105] = "mempool_items_removed",
    [106] = "request_cost_info",
    [107] = "respond_cost_info",
    [255] = "error"
} -- chia_enum_ProtocolMessageTypes


local hexToBin = {
    ["0"] = "0000", ["1"] = "0001", ["2"] = "0010", ["3"] = "0011",
    ["4"] = "0100", ["5"] = "0101", ["6"] = "0110", ["7"] = "0111",
    ["8"] = "1000", ["9"] = "1001", ["A"] = "1010", ["B"] = "1011",
    ["C"] = "1100", ["D"] = "1101", ["E"] = "1110", ["F"] = "1111"
} -- hexToBin


--------------------------------------------------------------------------------
-- Functions to determine the size of embedded CLVM programs
--------------------------------------------------------------------------------

local function DecodeSize (tvb, offset, data_tree, parsed_byte)
    -- parse the bits of the first byte until you hit 0 to determine the number of length bytes
    local parsed_byte_binary = ""
    for i = 7, 0, -1 do
        local bit = math.floor(parsed_byte / 2^i) % 2
        parsed_byte_binary = parsed_byte_binary .. bit
        if bit == 0 then break end
    end

    -- parse the length_bytes
    local length_bits_end_pos = string.find(parsed_byte_binary, 0)
    local length_bytes = tostring(tvb:range(offset, length_bits_end_pos - 1))
    
    -- convert the length_bytes to binary
    local binary_lenght_bytes = ""
    for i = 1, #length_bytes, 2 do
        local hexByte = length_bytes:sub(i, i + 1):upper()
        local binStr = ""
        for j = 1, 2 do
            local hexChar = hexByte:sub(j, j)
            binStr = binStr .. hexToBin[hexChar]
        end
        binary_lenght_bytes = binary_lenght_bytes .. binStr
    end

    -- remove the length bits of the first byte from the start of the binary_length_bytes
    local truncated_binary = string.sub(binary_lenght_bytes, length_bits_end_pos + 1)

    -- convert the truncated binary_length_bytes to integer
    local decoded_size = 0
    local length = #truncated_binary
    for i = 1, length do
        local bit = tonumber(truncated_binary:sub(i, i))
        if bit then
            decoded_size = decoded_size + bit * 2^(length - i)
        end
    end

    -- return the number of length bits (1s) and the decoded_size
    return (length_bits_end_pos - 1), decoded_size
end -- DecodeSize


local function ParseSerializedProgramTrusted (tvb, offset, data_tree)
    -- this function returns the offset for the last byte of the serialized program
    local ops_counter = 1
    while ops_counter > 0 do
        ops_counter = ops_counter - 1

        local parsed_byte = tvb:range(offset, 1):uint()

        if parsed_byte == 255 then -- 0xff / cons
            ops_counter = ops_counter + 2
            offset = offset + 1
        elseif parsed_byte == 254 then -- 0xfe / back references
            offset = offset + 1
            local back_reference_byte = tvb:range(offset, 1):uint()  
            if back_reference_byte > 128 then -- BLOBS
                local size_bytes, path_size = DecodeSize(tvb, offset, data_tree, back_reference_byte)
                offset = offset + path_size
                offset = offset + 1
            elseif back_reference_byte == 128 then -- 0x80 / nil
            else -- <= 0x7f / small chars
                offset = offset + 1
            end          
        elseif parsed_byte == 128 then -- 0x80 / nil
            offset = offset + 1
        elseif parsed_byte > 128 then -- BLOBS
            local size_bytes, path_size = DecodeSize (tvb, offset, data_tree, parsed_byte)
            offset = offset + size_bytes + path_size
        elseif parsed_byte <= 127 then -- <= 0x7f small chars
            offset = offset + 1
        end
    end
    -- decrease offset by one to account for the last increment
    return offset - 1
end -- ParseSerializedProgramTrusted

--------------------------------------------------------------------------------
-- Functions that get called by various message type dissector functions
--------------------------------------------------------------------------------

local function VDFInfo (tvb, offset, data_tree)
    data_tree:add(pf.VDFInfo__challenge, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.VDFInfo__number_of_iterations, tvb:range(offset, 8))
    offset = offset + 8
    local output_tree = data_tree:add("output (ClassgroupElement)")
        output_tree:add(pf.ClassgroupElement__data, tvb:range(offset, 100))
        offset = offset + 100
    -- end of output_tree
    return offset
end -- VDFInfo


local function VDFProof (tvb, offset, data_tree)
    data_tree:add(pf.VDFProof__witness_type, tvb:range(offset, 1))
    offset = offset + 1
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.VDFProof__witness__length, tvb:range(offset, 4))
    end
    local witness_length = tvb:range(offset, 4):uint()
    offset = offset + 4

    data_tree:add(pf.VDFProof__witness, tvb:range(offset, witness_length))
    offset = offset + witness_length

    data_tree:add(pf.VDFProof__normalized_to_identity, tvb:range(offset, 1))
    offset = offset + 1
    return offset
end -- VDFProof


local function EndOfSubSlotBundle (tvb, offset, data_tree)
    -- challenge_chain
    local challenge_chain_tree = data_tree:add("challenge_chain (ChallengeChainSubSlot)")
        -- challenge_chain_end_of_slot_vdf
        local challenge_chain_end_of_slot_vdf_tree = 
                challenge_chain_tree:add("challenge_chain_end_of_slot_vdf (VDFInfo)")
            offset = VDFInfo(tvb, offset, challenge_chain_end_of_slot_vdf_tree)
        -- end of challenge_chain_end_of_slot_vdf_tree

        -- infused_challenge_chain_sub_slot_hash
        if SHOW_SERIAL_PROTO == true then
            challenge_chain_tree:add(
                pf.EndOfSubSlotBundle__challenge_chain__infused_challenge_chain_sub_slot_hash__option, 
                tvb:range(offset, 1))
        end
        local infused_challenge_chain_sub_slot_hash_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if infused_challenge_chain_sub_slot_hash_option == 0 then
        elseif infused_challenge_chain_sub_slot_hash_option == 1 then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__infused_challenge_chain_sub_slot_hash, 
                tvb:range(offset, 32))
            offset = offset + 32
        else
            challenge_chain_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- subepoch_summary_hash
        if SHOW_SERIAL_PROTO == true then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__subepoch_summary_hash__option, 
                tvb:range(offset, 1))
        end
        local subepoch_summary_hash_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if subepoch_summary_hash_option == 0 then
        elseif subepoch_summary_hash_option == 1 then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__subepoch_summary_hash, 
                tvb:range(offset, 32))
            offset = offset + 32
        else
            challenge_chain_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- new_sub_slot_iters
        if SHOW_SERIAL_PROTO == true then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__new_sub_slot_iters__option, 
                tvb:range(offset, 1))
        end
        local new_sub_slot_iters_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if new_sub_slot_iters_option == 0 then
        elseif new_sub_slot_iters_option == 1 then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__new_sub_slot_iters, 
                tvb:range(offset, 8))
            offset = offset + 8
        else
            challenge_chain_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- new_difficulty
        if SHOW_SERIAL_PROTO == true then
            challenge_chain_tree:add(pf.EndOfSubSlotBundle__challenge_chain__new_difficulty__option, 
                tvb:range(offset, 1))
        end
        local new_difficulty_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if new_difficulty_option == 0 then
        elseif new_difficulty_option == 1 then
            challenge_chain_tree:add( pf.EndOfSubSlotBundle__challenge_chain__new_difficulty, tvb:range(offset, 8))
            offset = offset + 8
        else
            challenge_chain_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end
    -- end of challenge_chain_tree

    -- infused_challenge_chain
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.EndOfSubSlotBundle__infused_challenge_chain__infused_challenge_chain_end_of_slot_vdf__option, 
            tvb:range(offset, 1))
    end
    local infused_challenge_chain_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if infused_challenge_chain_option == 0 then
    elseif infused_challenge_chain_option == 1 then
        local infused_challenge_chain_tree = data_tree:add("infused_challenge_chain (InfusedChallengeChainSubSlot)")
            local infused_challenge_chain_end_of_slot_vdf_tree = 
                    infused_challenge_chain_tree:add("infused_challenge_chain_end_of_slot_vdf: VDFInfo")
                offset = VDFInfo(tvb, offset, infused_challenge_chain_end_of_slot_vdf_tree)
            -- end of infused_challenge_chain_end_of_slot_vdf_tree
        -- end of infused_challenge_chain_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- reward_chain
    local reward_chain_tree = data_tree:add("reward_chain: RewardChainSubSlot")
        -- end_of_slot_vdf
        local end_of_slot_vdf_tree = reward_chain_tree:add("end_of_slot_vdf_tree (VDFInfo)")
            offset = VDFInfo(tvb, offset, end_of_slot_vdf_tree)
        -- end of end_of_slot_vdf_tree

        -- challenge_chain_sub_slot_hash
        reward_chain_tree:add(pf.EndOfSubSlotBundle__reward_chain__challenge_chain_sub_slot_hash, 
            tvb:range(offset, 32))
        offset = offset + 32

        -- infused_challenge_chain_sub_slot_hash
        if SHOW_SERIAL_PROTO == true then
            reward_chain_tree:add(pf.EndOfSubSlotBundle__reward_chain__infused_challenge_chain_sub_slot_hash__option, 
                tvb:range(offset, 1))
        end
        local infused_challenge_chain_sub_slot_hash__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if infused_challenge_chain_sub_slot_hash__option == 0 then
        elseif infused_challenge_chain_sub_slot_hash__option == 1 then
            reward_chain_tree:add(pf.EndOfSubSlotBundle__reward_chain__infused_challenge_chain_sub_slot_hash, 
                tvb:range(offset, 32))
            offset = offset + 32
        else
            reward_chain_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- deficit
        reward_chain_tree:add(pf.EndOfSubSlotBundle__reward_chain__deficit, tvb:range(offset, 1))
        offset = offset + 1
    -- end of reward_chain_tree

    -- proofs
    local proofs_tree = data_tree:add("proofs: SubSlotProofs")
        -- challenge_chain_slot_proof
        local challenge_chain_slot_proof_tree = proofs_tree:add("challenge_chain_slot_proof (VDFProof)")
            offset = VDFProof(tvb, offset, challenge_chain_slot_proof_tree)
        -- end of challenge_chain_slot_proof_tree

        -- infused_challenge_chain_slot_proof
        if SHOW_SERIAL_PROTO == true then
            proofs_tree:add(pf.EndOfSubSlotBundle__proofs__infused_challenge_chain_slot_proof__option, 
                tvb:range(offset, 1))
        end
        local infused_challenge_chain_slot_proof_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if infused_challenge_chain_slot_proof_option == 0 then
        elseif infused_challenge_chain_slot_proof_option == 1 then
            local infused_challenge_chain_slot_proof_tree =  
                    proofs_tree:add("infused_challenge_chain_slot_proof (VDFProof)")
                offset = VDFProof(tvb, offset, infused_challenge_chain_slot_proof_tree)
            -- end of infused_challenge_chain_slot_proof_tree
        else
            proofs_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- reward_chain_slot_proof
        local reward_chain_slot_proof_tree = proofs_tree:add("reward_chain_slot_proof (VDFProof)")
            offset = VDFProof(tvb, offset, proofs_tree)
        -- end of reward_chain_slot_proof_tree
    -- end of proofs_tree
    return offset
end -- EndOfSubSlotBundle


local function ProofOfSpace (tvb, offset, data_tree)
    local proof_of_space_tree = data_tree:add("proof_of_space (ProofOfSpace)")
        -- challenge
        proof_of_space_tree:add(pf.ProofOfSpace__challenge, tvb:range(offset, 32))
        offset = offset + 32

        -- pool_public_key
        if SHOW_SERIAL_PROTO == true then
            proof_of_space_tree:add(pf.ProofOfSpace__pool_public_key__option, tvb:range(offset, 1))
        end
        local pool_public_key_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if pool_public_key_option == 0 then
        elseif pool_public_key_option == 1 then
            proof_of_space_tree:add(pf.ProofOfSpace__pool_public_key, tvb:range(offset, 48))
            offset = offset + 48
        else
            proof_of_space_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- pool_contract_puzzle_hash
        if SHOW_SERIAL_PROTO == true then
            proof_of_space_tree:add(pf.ProofOfSpace__pool_contract_puzzle_hash__option, 
                tvb:range(offset, 1))
        end
        local pool_contract_puzzle_hash_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if pool_contract_puzzle_hash_option == 0 then
        elseif pool_contract_puzzle_hash_option == 1 then
            proof_of_space_tree:add(pf.ProofOfSpace__pool_contract_puzzle_hash, 
                tvb:range(offset, 32))
            offset = offset + 32
        else
            proof_of_space_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- plot_public_key
        proof_of_space_tree:add(pf.ProofOfSpace__plot_public_key, tvb:range(offset, 48))
        offset = offset + 48

        -- size
        proof_of_space_tree:add(pf.ProofOfSpace__size, tvb:range(offset, 1))
        offset = offset + 1

        -- proof
        if SHOW_SERIAL_PROTO == true then
            proof_of_space_tree:add(pf.ProofOfSpace__proof__length, tvb:range(offset, 4))
        end
        local reward_chain_block__proof_length = tvb:range(offset, 4):uint()
        offset = offset + 4
        proof_of_space_tree:add(
            pf.ProofOfSpace__proof, tvb:range(offset, reward_chain_block__proof_length))
        offset = offset + reward_chain_block__proof_length
    -- end of proof_of_space_tree
    return offset
end -- ProofOfSpace


local function RewardChainBlock (tvb, offset, data_tree, block_type)
    local reward_chain_block_tree = data_tree:add("reward_chain_block (RewardChainBlock)")
        if block_type ~= "UnfinishedBlock" then
            -- weight
            reward_chain_block_tree:add(pf.RewardChainBlock__weight, tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
            offset = offset + 16

            -- height
            reward_chain_block_tree:add(pf.RewardChainBlock__height, tvb:range(offset, 4))
            offset = offset + 4
        end

        -- total_iters
        reward_chain_block_tree:add(pf.RewardChainBlock__total_iters, tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
        offset = offset + 16

        -- signage_point_index
        reward_chain_block_tree:add(pf.RewardChainBlock__signage_point_index, tvb:range(offset, 1))
        offset = offset + 1

        -- pos_ss_cc_challenge_hash
        reward_chain_block_tree:add(pf.RewardChainBlock__pos_ss_cc_challenge_hash, tvb:range(offset, 32))
        offset = offset + 32

        -- proof_of_space
        offset = ProofOfSpace(tvb, offset, reward_chain_block_tree)

        -- challenge_chain_sp_vdf
        if SHOW_SERIAL_PROTO == true then
            reward_chain_block_tree:add(pf.RewardChainBlock__challenge_chain_sp_vdf__option, tvb:range(offset, 1))
        end
        local challenge_chain_sp_vdf_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if challenge_chain_sp_vdf_option == 0 then
        elseif challenge_chain_sp_vdf_option == 1 then
            local challenge_chain_sp_vdf_tree = reward_chain_block_tree:add("challenge_chain_sp_vdf (VDFInfo)")
                offset = VDFInfo(tvb, offset, challenge_chain_sp_vdf_tree)
            -- end of challenge_chain_sp_vdf_tree
        else
            reward_chain_block_tree:add(
                pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- challenge_chain_sp_signature
        reward_chain_block_tree:add(pf.RewardChainBlock__challenge_chain_sp_signature, tvb:range(offset, 96))
        offset = offset + 96
        
        -- challenge_chain_ip_vdf
        if block_type ~= "UnfinishedBlock" then
            local challenge_chain_ip_vdf_tree = reward_chain_block_tree:add("challenge_chain_ip_vdf (VDFInfo)")
                offset = VDFInfo(tvb, offset, challenge_chain_ip_vdf_tree)
            -- end of challenge_chain_ip_vdf_tree
        end

        -- reward_chain_sp_vdf
        if SHOW_SERIAL_PROTO == true then
            reward_chain_block_tree:add(
                pf.RewardChainBlock__reward_chain_sp_vdf__option, tvb:range(offset, 1))
        end
        local reward_chain_sp_vdf__challenge_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if reward_chain_sp_vdf__challenge_option == 0 then
        elseif reward_chain_sp_vdf__challenge_option == 1 then
            local reward_chain_sp_vdf_tree = reward_chain_block_tree:add("reward_chain_sp_vdf (VDFInfo)")
                offset = VDFInfo(tvb, offset, reward_chain_sp_vdf_tree)
            -- end of reward_chain_sp_vdf_tree
        else

            reward_chain_block_tree:add(pf.dissector__error, 
                "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- reward_chain_sp_signature
        reward_chain_block_tree:add(pf.RewardChainBlock__reward_chain_sp_signature, tvb:range(offset, 96))
        offset = offset + 96

        -- reward_chain_ip_vdf
        -- infused_challenge_chain_ip_vdf
        -- is_transaction_block
        if block_type ~= "UnfinishedBlock" then
            local reward_chain_ip_vdf_tree = reward_chain_block_tree:add("reward_chain_ip_vdf (VDFInfo)")
                offset = VDFInfo(tvb, offset, reward_chain_ip_vdf_tree)
            -- end of reward_chain_ip_vdf_tree

            -- infused_challenge_chain_ip_vdf
            if SHOW_SERIAL_PROTO == true then

                reward_chain_block_tree:add(pf.RewardChainBlock__infused_challenge_chain_ip_vdf__option, 
                    tvb:range(offset, 1))
            end
            local infused_challenge_chain_ip_vdf__challenge_option = tvb:range(offset, 1):uint()
            offset = offset + 1
            if infused_challenge_chain_ip_vdf__challenge_option == 0 then
            elseif infused_challenge_chain_ip_vdf__challenge_option == 1 then

                local infused_challenge_chain_ip_vdf_tree = 
                        reward_chain_block_tree:add("infused_challenge_chain_ip_vdf (VDFInfo)")

                    offset = VDFInfo(tvb, offset, infused_challenge_chain_ip_vdf_tree)
                -- end of infused_challenge_chain_ip_vdf
            else
                reward_chain_block_tree:add(pf.dissector__error, 
                    "Deserialization Error: value of type bool (0/1) expected!")
            return end

            -- is_transaction_block
            reward_chain_block_tree:add(pf.RewardChainBlock__is_transaction_block, tvb:range(offset, 1))
            offset = offset + 1
        end
    -- end of reward_chain_block_tree
    return offset
end -- RewardChainBlock


local function FoliageTransactionBlock (tvb, offset, data_tree)
    local foliage_transaction_block_tree = data_tree:add(
            "foliage_transaction_block (FoliageTransactionBlock)")
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__prev_transaction_block_hash, 
            tvb:range(offset, 32))
        offset = offset + 32
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__timestamp, tvb:range(offset, 8))
        offset = offset + 8
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__filter_hash, tvb:range(offset, 32))
        offset = offset + 32
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__additions_root, tvb:range(offset, 32))
        offset = offset + 32
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__removals_root, tvb:range(offset, 32))
        offset = offset + 32
        foliage_transaction_block_tree:add(pf.FoliageTransactionBlock__transactions_info_hash, tvb:range(offset, 32))
        offset = offset + 32
    -- end of foliage_transaction_block_tree
    return offset
end -- FoliageTransactionBlock


local function FoliageBlockData (tvb, offset, data_tree)
    local foilage_block_data_tree = data_tree:add("foilage_block_data (FoliageBlockData)")
        -- unfinished_reward_block_hash
        foilage_block_data_tree:add(pf.FoliageBlockData__unfinished_reward_block_hash, tvb:range(offset, 32))
        offset = offset + 32

        -- pool_target
        local pool_target_tree = foilage_block_data_tree:add("pool_target (PoolTarget)")
            pool_target_tree:add(pf.FoliageBlockData__pool_target__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
            pool_target_tree:add(pf.FoliageBlockData__pool_target__max_height, tvb:range(offset, 4))
            offset = offset + 4
        -- end of pool_target_tree

        -- pool_signature
        if SHOW_SERIAL_PROTO == true then
            foilage_block_data_tree:add(pf.FoliageBlockData__pool_signature__option, tvb:range(offset, 1))
        end
        local pool_signature__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if pool_signature__option == 0 then
        elseif pool_signature__option == 1 then
            foilage_block_data_tree:add(pf.FoliageBlockData__pool_signature, tvb:range(offset, 96))
            offset = offset + 96
        else
            data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- farmer_reward_puzzle_hash
        foilage_block_data_tree:add(pf.FoliageBlockData__farmer_reward_puzzle_hash, tvb:range(offset, 32))
        offset = offset + 32

        -- extension_data
        foilage_block_data_tree:add(pf.FoliageBlockData__extension_data, tvb:range(offset, 32))
        offset = offset + 32
    -- end of foilage_block_data_tree
    return offset
end -- FoliageBlockData


local function Foliage (tvb, offset, data_tree)
    data_tree:add(pf.Foliage__prev_block_hash, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.Foliage__reward_block_hash, tvb:range(offset, 32))
    offset = offset + 32

    offset = FoliageBlockData(tvb, offset, data_tree)

    data_tree:add(pf.Foliage__foliage_block_data_signature, tvb:range(offset, 96))
    offset = offset + 96

    -- foliage_transaction_block_hash
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Foliage__foliage_transaction_block_hash__option, tvb:range(offset, 1))
    end
    local foliage_transaction_block_hash_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if foliage_transaction_block_hash_option == 0 then
    elseif foliage_transaction_block_hash_option == 1 then
        data_tree:add(pf.Foliage__foliage_transaction_block_hash, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- foliage_transaction_block_signature
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Foliage__foliage_transaction_block_signature__option, tvb:range(offset, 1))
    end
    local foliage_transaction_block_signature_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if foliage_transaction_block_signature_option == 0 then
    elseif foliage_transaction_block_signature_option == 1 then
        data_tree:add(pf.Foliage__foliage_transaction_block_signature, tvb:range(offset, 96))
        offset = offset + 96
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    return offset
end -- Foliage


local function Coin (tvb, offset, data_tree)
    data_tree:add(pf.Coin__parent_coin_info, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.Coin__puzzle_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.Coin__amount, tvb:range(offset, 8))
    offset = offset + 8
    return offset
end -- Coin


local function SpendBundle (tvb, offset, data_tree)
    -- coin_spends
    data_tree:add(pf.SpendBundle__coin_spends__count, tvb:range(offset, 4))
    local coin_spends_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_spends_tree = data_tree:add("coin_spends (Vec<CoinSpend>)")
        for i=1, coin_spends_count do
            local coin_spend_tree = coin_spends_tree:add("CoinSpend")
                local coin_tree = coin_spend_tree:add("coin (Coin)")
                    offset = Coin(tvb, offset, coin_tree)
                -- end of coin_tree

                -- puzzle_reveal
                local puzzle_reveal_offset = ParseSerializedProgramTrusted (tvb, offset, coin_spend_tree)
                coin_spend_tree:add(pf.SpendBundle__puzzle_reveal, tvb:range(offset, (puzzle_reveal_offset - offset + 1)))
                offset = puzzle_reveal_offset + 1
               
                -- solution
                local solution_offset = ParseSerializedProgramTrusted (tvb, offset, coin_spend_tree)
                coin_spend_tree:add(pf.SpendBundle__solution, tvb:range(offset, (solution_offset - offset + 1)))
                offset = solution_offset + 1
            -- end of coin_spend_tree
        end
    -- end of coin_spends_tree

    -- aggregated_signature
    data_tree:add(pf.SpendBundle__aggregated_signature, tvb:range(offset, 96))
    offset = offset + 96

    return offset
end -- SpendBundle


-- block_type: FullBlock, UnfinishedBlock, HeaderBlock
local function Block (tvb, offset, data_tree, block_type)
    -- finished_sub_slots
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Block__finished_sub_slots__count, tvb:range(offset, 4))
    end
    local finished_sub_slots_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local finished_sub_slots_tree = data_tree:add("finished_sub_slots (Vec<EndOfSubSlotBundle>)")
        for i=1, finished_sub_slots_count do
            local end_of_sub_slot_bundle_tree = finished_sub_slots_tree:add("EndOfSubSlotBundle")
                offset = EndOfSubSlotBundle(tvb, offset, end_of_sub_slot_bundle_tree)
            -- end of end_of_sub_slot_bundle_tree
        end
    -- end of finished_sub_slots_tree
    

    -- reward_chain_block
    offset = RewardChainBlock(tvb, offset, data_tree, block_type)

    -- challenge_chain_sp_proof
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Block__challenge_chain_sp_proof__option, tvb:range(offset, 1))
    end
    local challenge_chain_sp_proof_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if challenge_chain_sp_proof_option == 0 then
    elseif challenge_chain_sp_proof_option == 1 then
        local challenge_chain_sp_proof_tree = data_tree:add("challenge_chain_sp_proof (VDFProof)")
            offset = VDFProof(tvb, offset, challenge_chain_sp_proof_tree)
        -- end of challenge_chain_sp_proof_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- challenge_chain_ip_proof
    if block_type ~= "UnfinishedBlock" then
        local challenge_chain_ip_proof_tree = data_tree:add("challenge_chain_ip_proof (VDFProof)")
            offset = VDFProof(tvb, offset, challenge_chain_ip_proof_tree)
        -- end of challenge_chain_ip_proof_tree
    end

    -- reward_chain_sp_proof
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Block__reward_chain_sp_proof__option, tvb:range(offset, 1))
    end
    local reward_chain_sp_proof__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if reward_chain_sp_proof__option == 0 then
    elseif reward_chain_sp_proof__option == 1 then
        local reward_chain_sp_proof_tree = data_tree:add("reward_chain_sp_proof (VDFProof)")
            offset = VDFProof(tvb, offset, reward_chain_sp_proof_tree)
        -- end of reward_chain_sp_proof_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- reward_chain_ip_proof
    -- infused_challenge_chain_ip_proof
    if block_type ~= "UnfinishedBlock" then
        local reward_chain_ip_proof_tree = data_tree:add("reward_chain_ip_proof (VDFProof)")
            offset = VDFProof(tvb, offset, reward_chain_ip_proof_tree)
        -- end of reward_chain_ip_proof_tree

        -- infused_challenge_chain_ip_proof
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.Block__infused_challenge_chain_ip_proof__option, tvb:range(offset, 1))
        end
        local infused_challenge_chain_ip_proof__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if infused_challenge_chain_ip_proof__option == 0 then
        elseif infused_challenge_chain_ip_proof__option == 1 then
            local infused_challenge_chain_ip_proof_tree = data_tree:add("infused_challenge_chain_ip_proofS (VDFProof)")
                offset = VDFProof(tvb, offset, infused_challenge_chain_ip_proof_tree)
            -- end of infused_challenge_chain_ip_proof_tree
        else
            data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end
    end -- Block

    -- foilage
    local foilage_tree = data_tree:add("foilage (Foliage)")
        offset = Foliage(tvb, offset, foilage_tree)
    -- end of foilage_tree

    -- foliage_transaction_block
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Block__foliage_transaction_block__option, tvb:range(offset, 1))
    end
    local foliage_transaction_block_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if foliage_transaction_block_option == 0 then
    elseif foliage_transaction_block_option == 1 then
        offset = FoliageTransactionBlock(tvb, offset, data_tree)
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- transactions_filter
    if block_type == "HeaderBlock" then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.HeaderBlock__transactions_filter__length, tvb:range(offset, 4))
        end
        local header_block__transactions_filter_length = tvb:range(offset, 4):uint()
        offset = offset + 4

        if header_block__transactions_filter_length > 0 then
            data_tree:add(pf.HeaderBlock__transactions_filter, 
                tvb:range(offset, header_block__transactions_filter_length))
            offset = offset + header_block__transactions_filter_length
        end
    end

    -- transactions_info
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.Block__transactions_info__option, tvb:range(offset, 1))
    end
    local transactions_info__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if transactions_info__option == 0 then
    elseif transactions_info__option == 1 then
        local transactions_info_tree = data_tree:add("transactions_info (TransactionsInfo)")
            transactions_info_tree:add(pf.Block__transactions_info__generator_root, tvb:range(offset, 32))
            offset = offset + 32
            transactions_info_tree:add(pf.Block__transactions_info__generator_refs_root, tvb:range(offset, 32))
            offset = offset + 32
            transactions_info_tree:add(pf.Block__transactions_info__aggregated_signature, tvb:range(offset, 96))
            offset = offset + 96
            transactions_info_tree:add(pf.Block__transactions_info__fees, tvb:range(offset, 8))
            offset = offset + 8
            transactions_info_tree:add(pf.Block__transactions_info__cost, tvb:range(offset, 8))
            offset = offset + 8

            if SHOW_SERIAL_PROTO == true then
                transactions_info_tree:add(pf.Block__transactions_info__reward_claims_incorporated__count, 
                    tvb:range(offset, 4))
            end
            local reward_claims_incorporated_count = tvb:range(offset, 4):uint()
            offset = offset + 4
            -- reward_claims_incorporated
            if reward_claims_incorporated_count > 0 then
                local reward_claims_incorporated_tree = 
                        transactions_info_tree:add("reward_claims_incorporated (Vec<Coin>)")
                    for i = 1, reward_claims_incorporated_count do
                        local coin_tree = reward_claims_incorporated_tree:add("coin (Coin)")
                            offset = Coin(tvb, offset, coin_tree)
                        -- end of coin_tree
                    end
                -- end of reward_claims_incorporated_tree
            else
                transactions_info_tree:add(pf.dissector__error, 
                    "Deserialization Error: value of type bool (0/1) expected!")
            return end
        -- end of transactions_info_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- transactions_generator
    -- transactions_generator_ref_list
    if block_type == "FullBlock" or block_type == "UnfinishedBlock" then
        -- transactions_generator
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.FullBlock__transactions_generator__option, tvb:range(offset, 1))
        end
        local transactions_generator__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if transactions_generator__option == 0 then
        elseif transactions_generator__option == 1 then
            program_offset = ParseSerializedProgramTrusted(tvb, offset, data_tree)
            data_tree:add(pf.Block__transaction_generator, tvb:range(offset, (program_offset - offset)))
            offset = program_offset + 1
        else
            data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        end

        -- transactions_generator_ref_list
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.FullBlock__transactions_generator_ref_list__count, tvb:range(offset, 4))
        end
        local ref_list_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        if ref_list_count > 0 then
            local transactions_generator_ref_list_tree = data_tree:add("transactions_generator_ref_list (Vec<u32>)")
                for i=1, ref_list_count do
                    transactions_generator_ref_list_tree:add(pf.FullBlock__transactions_generator_ref_list__block_height, 
                    tvb:range(offset, 4))
                    offset = offset + 4
                end
            -- end of transactions_generator_ref_list_tree
        end
    end

    return offset
end -- Block


local function SubEpochSummary (tvb, offset, data_tree)
    local sub_epoch_summary_tree = data_tree:add(
            "sub_epoch_summary (SubEpochSummary)")
        sub_epoch_summary_tree:add(pf.SubEpochSummary__prev_subepoch_summary_hash, tvb:range(offset, 32))
        offset = offset + 32
        sub_epoch_summary_tree:add(pf.SubEpochSummary__reward_chain_hash, tvb:range(offset, 32))
        offset = offset + 32
        sub_epoch_summary_tree:add(pf.SubEpochSummary__num_blocks_overflow, tvb:range(offset, 1))
        offset = offset + 1

        -- new_difficulty
        if SHOW_SERIAL_PROTO == true then
            sub_epoch_summary_tree:add(pf.SubEpochSummary__new_difficulty__option, tvb:range(offset, 1))
        end
        local new_difficulty_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if new_difficulty_option == 0 then
        elseif new_difficulty_option == 1 then
            sub_epoch_summary_tree:add(pf.SubEpochSummary__new_difficulty, tvb:range(offset, 8))
            offset = offset + 8
        else
            sub_epoch_summary_tree:add(pf.dissector__error, 
                "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- new_sub_slot_iters
        if SHOW_SERIAL_PROTO == true then
            sub_epoch_summary_tree:add(pf.SubEpochSummary__new_sub_slot_iters__option, tvb:range(offset, 1))
        end
        local new_sub_slot_iters_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if new_sub_slot_iters_option == 0 then
        elseif new_sub_slot_iters_option == 1 then
            sub_epoch_summary_tree:add(pf.SubEpochSummary__new_sub_slot_iters, tvb:range(offset, 8))
            offset = offset + 8
        else
            sub_epoch_summary_tree:add(pf.dissector__error, 
                "Deserialization Error: value of type bool (0/1) expected!")
        return end
    -- end of sub_epoch_summary_tree   
    return offset
end -- SubEpochSummary


local function TimestampedPeerInfo (tvb, offset, data_tree)
    local TimestampedPeerInfo_tree = data_tree:add(
            "peer_list (TimestampedPeerInfo)")
        if SHOW_SERIAL_PROTO == true then
            TimestampedPeerInfo_tree:add(pf.TimestampedPeerInfo__host__length, tvb:range(offset, 4))
        end
        local host_length = tvb:range(offset, 4):uint()
        offset = offset + 4
        TimestampedPeerInfo_tree:add(pf.TimestampedPeerInfo__host, tvb:range(offset, host_length))
        offset = offset + host_length
        TimestampedPeerInfo_tree:add(pf.TimestampedPeerInfo__port, tvb:range(offset, 2))
        offset = offset + 2
        TimestampedPeerInfo_tree:add(pf.TimestampedPeerInfo__timestamp, tvb:range(offset, 8))
        offset = offset + 8
    -- end of TimestampedPeerInfo_tree
    return offset
end -- TimestampedPeerInfo


local function Plot (tvb, offset, data_tree)
    local plot_tree = data_tree:add("plot (Plot)")
        -- filename
        if SHOW_SERIAL_PROTO == true then
            plot_tree:add(pf.Plot__filename__length, tvb:range(offset, 4))
        end
        local filename_length = tvb:range(offset, 4):uint()
        offset = offset + 4
        plot_tree:add(pf.Plot__filename, tvb:range(offset, filename_length))
        offset = offset + filename_length

        -- size
        plot_tree:add(pf.Plot__size, tvb:range(offset, 1))
        offset = offset + 1

        -- plot_id
        plot_tree:add(pf.Plot__plot_id, tvb:range(offset, 32))
        offset = offset + 32

        -- pool_public_key
        if SHOW_SERIAL_PROTO == true then
            plot_tree:add(pf.Plot__pool_public_key__option, tvb:range(offset, 1))
        end
        local public_key_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if public_key_option == 0 then
        elseif public_key_option == 1 then
            plot_tree:add(pf.Plot__pool_public_key, tvb:range(offset, 48))
            offset = offset + 48
        else
            plot_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- pool_contract_puzzle_hash
        if SHOW_SERIAL_PROTO == true then
            plot_tree:add(pf.Plot__pool_contract_puzzle_hash__option, tvb:range(offset, 1))
        end
        local pool_contract_puzzle_hash_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if pool_contract_puzzle_hash_option == 0 then
        elseif pool_contract_puzzle_hash_option == 1 then
            plot_tree:add(pf.Plot__pool_contract_puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
        else
            plot_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- plot_public_key
        plot_tree:add(pf.Plot__plot_public_key, tvb:range(offset, 48))
        offset = offset + 48

        -- file_size
        plot_tree:add(pf.Plot__file_size, tvb:range(offset, 8))
        offset = offset + 8

        -- time_modified
        plot_tree:add(pf.Plot__time_modified, tvb:range(offset, 8))
        offset = offset + 8

        -- compression_level
        if SHOW_SERIAL_PROTO == true then
            plot_tree:add(pf.Plot__compression_level__option, tvb:range(offset, 1))
        end
        local compression_level_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if compression_level_option == 0 then
        elseif compression_level_option == 1 then
            plot_tree:add(pf.Plot__compression_level, tvb:range(offset, 1))
            offset = offset + 1
        else
            plot_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end
    -- end of plot_tree
    return offset
end -- Plot


local function CoinState (tvb, offset, data_tree)
    local coin_state_tree = data_tree:add("coin_state (CoinState)")
        local coin_tree = coin_state_tree:add("coin (Coin)")offset = Coin(tvb, offset, coin_tree)
        -- end of coin_tree

        -- spent_height
        if SHOW_SERIAL_PROTO == true then
            coin_state_tree:add(pf.CoinState__spent_height__option, tvb:range(offset, 1))
        end
        local spent_height__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if spent_height__option == 0 then
        elseif spent_height__option == 1 then
            coin_state_tree:add(pf.CoinState__spent_height, tvb:range(offset, 4))
            offset = offset + 4
        else
            coin_state_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- created_height
        if SHOW_SERIAL_PROTO == true then
            coin_state_tree:add(pf.CoinState__created_height__option, tvb:range(offset, 1))
        end
        local created_height__option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if created_height__option == 0 then
        elseif created_height__option == 1 then
            coin_state_tree:add(pf.CoinState__created_height, tvb:range(offset, 4))
            offset = offset + 4
        else
            coin_state_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end
    -- end of coin_state_tree
    return offset
end -- CoinState


local function PlotSyncIdentifier (tvb, offset, data_tree)
    local identifier_tree = data_tree:add("identifier (PlotSyncIdentifier)")
        identifier_tree:add(pf.PlotSyncIdentifier__identifier__timestamp, tvb:range(offset, 8))
        offset = offset + 8

        identifier_tree:add(pf.PlotSyncIdentifier__identifier__sync_id, tvb:range(offset, 8))
        offset = offset + 8

        identifier_tree:add(pf.PlotSyncIdentifier__identifier__message_id, tvb:range(offset, 8))
        offset = offset + 8
    -- end of identifier_tree
    return offset
end -- PlotSyncIdentifier


local function PlotSyncPathList (tvb, offset, data_tree)
    -- identifier
    offset = PlotSyncIdentifier(tvb, offset, data_tree)
    
    -- data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.PlotSyncPathList__data__count, tvb:range(offset, 4))
    end
    local data_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local plot_data_tree = data_tree:add("data (list[str])")
        for i=1, data_count do
            if SHOW_SERIAL_PROTO == true then
                plot_data_tree:add(pf.PlotSyncPathList__data__length, tvb:range(offset, 4))
            end
            local data_length = tvb:range(offset, 4):uint()
            offset = offset + 4

            plot_data_tree:add(pf.PlotSyncPathList__data, tvb:range(offset, data_length))
            offset = offset + data_length
        end
    -- end of plot_data_tree

    -- final
    data_tree:add(pf.PlotSyncPathList__final, tvb:range(offset, 1))
    offset = offset + 1

    return offset
end -- PlotSyncPathList

--------------------------------------------------------------------------------
-- Functions to dissect the data of specific message types
--------------------------------------------------------------------------------

-- 1 Handshake
local function handshake (tvb, offset, data_tree)
    local len_network_id = tvb:range(offset, 4):uint()
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.handshake__network_id__length, tvb:range(offset, 4))
    end
    offset = offset + 4

    data_tree:add(pf.handshake__network_id, tvb:range(offset, len_network_id))
    offset = offset + len_network_id

    local len_protocol_version = tvb:range(offset, 4):uint()
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.handshake__protocol_version__length, tvb:range(offset, 4))
    end
    offset = offset + 4

    data_tree:add(pf.handshake__protocol_version, tvb:range(offset, len_protocol_version))
    offset = offset + len_protocol_version

    local len_software_version = tvb:range(offset, 4):uint()
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.handshake__software_version__length, tvb:range(offset, 4))
    end
    offset = offset + 4

    data_tree:add(pf.handshake__software_version, tvb:range(offset, len_software_version))
    offset = offset + len_software_version

    data_tree:add(pf.handshake__server_port, tvb:range(offset, 2))
    offset = offset + 2

    data_tree:add(pf.handshake__node_type, tvb:range(offset, 1))
    data_tree:add(pf.handshake__node_type__enum, chia_enum_node_type[tvb:range(offset, 1):uint()]):set_generated()
    offset = offset + 1

    -- capabilities
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.handshake__capabilities__count, tvb:range(offset, 4))
    end
    local capabilities_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local capabilities_tree = data_tree:add("capabilities (list[tuple[uint16, str]])")
        -- capability_item_tree
        for i = 1, capabilities_count do
            local len_capability_item_str_length = tvb:range(offset+2, 4):uint()
            local capability_item_tree = capabilities_tree:add("capability (tuple[uint16, str])")

                capability_item_tree:add(pf.handshake__capability__enum, 
                    chia_enum_capabilities[tvb:range(offset, 2):uint()]):set_generated()

                capability_item_tree:add(pf.handshake__capability__uint16, tvb:range(offset, 2))

                offset = offset + 2
                local len_capability_str = tvb:range(offset, 4):uint()
                if SHOW_SERIAL_PROTO == true then
                    capability_item_tree:add(pf.handshake__capability__str__length, tvb:range(offset, 4))
                end
                offset = offset + 4
                capability_item_tree:add(pf.handshake__capability__str, tvb:range(offset, len_capability_str))
                offset = offset + len_capability_str
            -- end of capability_item_tree
        end
    -- end of capabilities_tree
end -- 1 handshake


-- 3 HarvesterHandshake
local function harvester_handshake (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.harvester_handshake__farmer_public_keys__count, tvb:range(offset, 4))
    end
    local farmer_public_keys_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local farmer_public_keys_tree = data_tree:add("farmer_public_keys (list[G1Element])")
        for i=1, farmer_public_keys_count do
            farmer_public_keys_tree:add(pf.harvester_handshake__farmer_public_key, tvb:range(offset, 48))
            offset = offset + 48
        end
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.harvester_handshake__pool_public_keys__count, tvb:range(offset, 4))
    end
    local pool_public_keys_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local pool_public_keys_tree = data_tree:add("pool_public_keys (list[G1Element])")
        for i=1, pool_public_keys_count do
            farmer_public_keys_tree:add(pf.harvester_handshake__pool_public_key, tvb:range(offset, 48))
            offset = offset + 48
        end
end -- 3 harvester_handshake


-- 5 NewProofOfSpace
local function new_proof_of_space (tvb, offset, data_tree)
    data_tree:add(pf.new_proof_of_space__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.new_proof_of_space__sp_hash, tvb:range(offset, 32))
    offset = offset + 32

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_proof_of_space__plot_identifier__length, tvb:range(offset, 4))
    end
    local plot_identifier_length = tvb:range(offset, 4):uint()
    offset = offset + 4

    data_tree:add(pf.new_proof_of_space__plot_identifier, tvb:range(offset, plot_identifier_length))
    offset = offset + plot_identifier_length

    local proof_tree = data_tree:add("proof (ProofOfSpace)")
        offset = ProofOfSpace(tvb, offset, proof_tree)

    data_tree:add(pf.new_proof_of_space__signage_point_index, tvb:range(offset, 1))
    offset = offset + 1

    data_tree:add(pf.new_proof_of_space__include_source_signature_data, tvb:range(offset, 1))
    offset = offset + 1

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_proof_of_space__farmer_reward_address_override__option, tvb:range(offset, 1))
    end
    local farmer_reward_address_override_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if farmer_reward_address_override_option == 0 then
    elseif farmer_reward_address_override_option == 1 then
        data_tree:add(pf.new_proof_of_space__farmer_reward_address_override, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_proof_of_space__fee_info__option, tvb:range(offset, 1))
    end
    local fee_info_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if fee_info_option == 0 then
    elseif fee_info_option == 1 then
        data_tree:add(pf.new_proof_of_space__fee_info__applied_fee_threshold, tvb:range(offset, 4))
        offset = offset + 4
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 5 new_proof_of_space


-- 6 RequestSignatures
local function request_signatures (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signatures__plot_identifier__length, tvb:range(offset, 4))
    end
    local plot_identifier__length = tvb:range(offset, 4):uint()
    offset = offset + 4
    data_tree:add(pf.request_signatures__plot_identifier, tvb:range(offset, plot_identifier__length))
    offset = offset + plot_identifier__length
    data_tree:add(pf.request_signatures__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_signatures__sp_hash, tvb:range(offset, 32))
    offset = offset + 32
    -- messages
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signatures__messages__count, tvb:range(offset, 4))
    end
    local messages_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local messages_tree = data_tree:add("messages (list[bytes32])")
        for i=1, messages_count do
            messages_tree:add(pf.request_signatures__message, tvb:range(offset, 32))
            offset = offset + 32
        end
    --_message_data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signatures__message_data__option, tvb:range(offset, 1))
    end
    local message_data_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if message_data_option == 0 then
    elseif message_data_option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.request_signatures__message_data__count, tvb:range(offset, 4))
        end
        local message_data_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local message_data_tree = data_tree:add("message_data (Optional[list[Optional[SignatureRequestSourceData]]])")
            for i=1, message_data_count do
                if SHOW_SERIAL_PROTO == true then
                    message_data_tree:add(pf.request_signatures__message_data__SignatureRequestSourceData__option, 
                        tvb:range(offset, 1))
                end
                local SignatureRequestSourceData_option = tvb:range(offset, 1):uint()
                offset = offset + 1
                if SignatureRequestSourceData_option == 0 then
                elseif SignatureRequestSourceData_option == 1 then
                    local SignatureRequestSourceData_tree = message_data_tree:add("SignatureRequestSourceData ((uint8, bytes))")
                        SignatureRequestSourceData_tree:add(
                            pf.request_signatures__message_data__SignatureRequestSourceData__kind, 
                            tvb:range(offset, 1))
                        offset = offset + 1
                        if SHOW_SERIAL_PROTO == true then
                            SignatureRequestSourceData_tree:add(
                                pf.request_signatures__message_data__SignatureRequestSourceData__data__length, 
                                tvb:range(offset, 4))
                        end
                        local data_length = tvb:range(offset, 4):uint()
                        offset = offset + 4
                        SignatureRequestSourceData_tree:add(
                            pf.request_signatures__message_data__SignatureRequestSourceData__data, 
                            tvb:range(offset, data_length))
                        offset = offset + data_length
                    -- end of SignatureRequestSourceData_tree
                else
                    message_data_tree:add(pf.dissector__error, 
                        "Deserialization Error: value of type bool (0/1) expected!")
                return end
            end
        -- end of message_data_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
    -- rc_block_unfinished
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signatures__rc_block_unfinished__option, tvb:range(offset, 1))
    end
    local rc_block_unfinished_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if rc_block_unfinished_option == 0 then
    elseif rc_block_unfinished_option == 1 then
        offset = RewardChainBlock(tvb, offset, data_tree, "UnfinishedBlock")
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 6 request_signatures


-- 7 RespondSignatures
local function respond_signatures (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_signatures__plot_identifier__length, tvb:range(offset, 4))
    end
    local plot_identifier_length = tvb:range(offset, 4):uint()
    offset = offset + 4
    data_tree:add(pf.respond_signatures__plot_identifier, tvb:range(offset, plot_identifier_length))
    offset = offset + plot_identifier_length
    data_tree:add(pf.respond_signatures__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.respond_signatures__sp_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.respond_signatures__local_pk, tvb:range(offset, 48))
    offset = offset + 48
    data_tree:add(pf.respond_signatures__farmer_pk, tvb:range(offset, 48))
    offset = offset + 48
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_signatures__message_signatures__count, tvb:range(offset, 4))
    end
    local message_signatures_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local message_signatures_list_tree = data_tree:add("message_signatures")
        for i=1, message_signatures_count do
            local message_signatures_tuples_tree = message_signatures_list_tree:add("message_signature_tuple")
                message_signatures_tuples_tree:add(pf.respond_signatures__message_signature__bytes32, 
                    tvb:range(offset, 32))
                offset = offset + 32
                message_signatures_tuples_tree:add(pf.respond_signatures__message_signature__signature, 
                    tvb:range(offset, 96))
                offset = offset + 96
            -- end of message_signatures_tuples_tree
        end
    -- end of message_signatures_list_tree
    
    data_tree:add(pf.respond_signatures__include_source_signature_data, tvb:range(offset, 1))
    offset = offset + 1
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_signatures__farmer_reward_address_override__option, tvb:range(offset, 1))
    end
    local farmer_reward_address_override_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if farmer_reward_address_override_option == 0 then
    elseif farmer_reward_address_override_option == 1 then
        data_tree:add(pf.respond_signatures__farmer_reward_address_override, tvb:range(offset, 32))
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 7 respond_signatures


-- 8 NewSignagePoint
local function new_signage_point (tvb, offset, data_tree)
    data_tree:add(pf.new_signage_point__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_signage_point__challenge_chain_sp, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_signage_point__reward_chain_sp, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_signage_point__difficulty, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_signage_point__sub_slot_iters, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_signage_point__signage_point_index, tvb:range(offset, 1))
    offset = offset + 1
    data_tree:add(pf.new_signage_point__peak_height, tvb:range(offset, 4))
    offset = offset + 4
    -- sp_source_data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_signage_point__sp_source_data__option, tvb:range(offset, 1))
    end
    local sp_source_data_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if sp_source_data_option == 0 then
    elseif sp_source_data_option == 1 then
        local sp_source_data_tree = data_tree:add("sp_source_data")
            -- SignagePointSourceData
            if SHOW_SERIAL_PROTO == true then
                sp_source_data_tree:add(pf.new_signage_point__sp_source_data__sub_slot_data__option, 
                    tvb:range(offset, 1))
            end
            local sub_slot_data_option = tvb:range(offset, 1):uint()
            offset = offset + 1
            if sub_slot_data_option == 0 then
            elseif sub_slot_data_option == 1 then
                local sub_slot_data_tree = sp_source_data_tree:add("SPSubSlotSourceData")
                    -- ChallengeChainSubSlot
                    local cc_sub_slot_tree = sub_slot_data_tree:add("ChallengeChainSubSlot")
                        local challenge_chain_end_of_slot_vdf_tree = 
                                sp_source_data_tree:add("challenge_chain_end_of_slot_vdf")
                            offset = VDFInfo(tvb, offset, sp_source_data_tree)
                        -- end of challenge_chain_end_of_slot_vdf_tree

                        -- infused_challenge_chain_sub_slot_hash
                        if SHOW_SERIAL_PROTO == true then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__infused_challenge_chain_sub_slot_hash__option, 
                                tvb:range(offset, 1))
                        end
                        local infused_challenge_chain_sub_slot_hash_option = tvb:range(offset, 1):uint()
                        offset = offset + 1
                        if infused_challenge_chain_sub_slot_hash_option == 0 then
                        elseif infused_challenge_chain_sub_slot_hash_option == 1 then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__infused_challenge_chain_sub_slot_hash, 
                                tvb:range(offset, 32))
                            offset = offset + 32
                        else
                            cc_sub_slot_tree:add(pf.dissector__error, 
                                "Deserialization Error: value of type bool (0/1) expected!")
                        return end

                        -- subepoch_summary_hash
                        if SHOW_SERIAL_PROTO == true then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__subepoch_summary_hash__option, 
                                tvb:range(offset, 1))
                        end
                        local subepoch_summary_hash_option = tvb:range(offset, 1):uint()
                        offset = offset + 1
                        if subepoch_summary_hash_option == 0 then
                        elseif subepoch_summary_hash_option == 1 then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__subepoch_summary_hash, 
                                tvb:range(offset, 32))
                            offset = offset + 32
                        else
                            cc_sub_slot_tree:add(pf.dissector__error, 
                                "Deserialization Error: value of type bool (0/1) expected!")
                        return end
                        
                        -- new_sub_slot_iters
                        if SHOW_SERIAL_PROTO == true then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_sub_slot_iters__option, 
                                tvb:range(offset, 1))
                        end
                        local new_sub_slot_iters_option = tvb:range(offset, 1):uint()
                        offset = offset + 1
                        if new_sub_slot_iters_option == 0 then
                        elseif new_sub_slot_iters_option == 1 then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_sub_slot_iters, 
                                tvb:range(offset, 8))
                            offset = offset + 8
                        else
                            cc_sub_slot_tree:add(pf.dissector__error, 
                                "Deserialization Error: value of type bool (0/1) expected!")
                        return end

                        -- new_difficulty
                        if SHOW_SERIAL_PROTO == true then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_difficulty__option, 
                                tvb:range(offset, 1))
                        end
                        local new_difficulty_option = tvb:range(offset, 1):uint()
                        offset = offset + 1
                        if new_difficulty_option == 0 then
                        elseif new_difficulty_option == 1 then
                            cc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__cc_sub_slot__new_difficulty, 
                                tvb:range(offset, 8))
                            offset = offset + 8
                        else
                            cc_sub_slot_tree:add(pf.dissector__error, 
                                "Deserialization Error: value of type bool (0/1) expected!")
                        return end
                    -- end of cc_sub_slot_tree    

                    -- RewardChainSubSlot
                    local rc_sub_slot_tree = 
                            sp_source_data_tree:add("RewardChainSubSlot")
                        -- end_of_slot_vdf
                        offset = VDFInfo(tvb, offset, sp_source_data_tree)

                        -- challenge_chain_sub_slot_hash
                        rc_sub_slot_tree:add(
                            pf.new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__challenge_chain_sub_slot_hash, 
                            tvb:range(offset, 32))
                        offset = offset + 32

                        -- infused_challenge_chain_sub_slot_hash
                        if SHOW_SERIAL_PROTO == true then
                            rc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__infused_challenge_chain_sub_slot_hash__option, 
                                tvb:range(offset, 1))
                        end
                        local infused_challenge_chain_sub_slot_hash_option = tvb:range(offset, 1):uint()
                        offset = offset + 1
                        if infused_challenge_chain_sub_slot_hash_option == 0 then
                        elseif infused_challenge_chain_sub_slot_hash_option == 1 then
                            rc_sub_slot_tree:add(
                                pf.new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__infused_challenge_chain_sub_slot_hash, 
                                tvb:range(offset, 32))
                            offset = offset + 32
                        else
                            rc_sub_slot_tree:add(pf.dissector__error, 
                                "Deserialization Error: value of type bool (0/1) expected!")
                        return end

                        -- deficit
                        rc_sub_slot_tree:add(
                            pf.new_signage_point__sp_source_data__sub_slot_data__rc_sub_slot__deficit, 
                            tvb:range(offset, 1))
                        offset = offset + 1
                    -- end of rc_sub_slot_tree
                -- end of sub_slot_data_tree

                -- vdf_data
                local vdf_data_tree = sp_source_data_tree:add("SPVDFSourceData")
                    if SHOW_SERIAL_PROTO == true then
                        rc_sub_slot_tree:add(pf.new_signage_point__sp_source_data__vdf_data__option, 
                            tvb:range(offset, 1))
                    end
                    local vdf_data_option = tvb:range(offset, 1):uint()
                    offset = offset + 1
                    if vdf_data_option == 0 then
                    elseif vdf_data_option == 1 then
                        rc_sub_slot_tree:add(
                            pf.new_signage_point__sp_source_data__vdf_data__cc_vdf__ClassgroupElement__data, 
                            tvb:range(offset, 100))
                        offset = offset + 100
                        rc_sub_slot_tree:add(
                            pf.new_signage_point__sp_source_data__vdf_data__rc_vdf__ClassgroupElement__data, 
                            tvb:range(offset, 100))
                        offset = offset + 100
                    else
                        rc_sub_slot_tree:add(pf.dissector__error, 
                            "Deserialization Error: value of type bool (0/1) expected!")
                    return end
                -- end of vdf_data_tree
            else
                sp_source_data_tree:add(pf.dissector__error, 
                    "Deserialization Error: value of type bool (0/1) expected!")
            return end
        -- end of sp_source_data_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 8 new_signage_point


-- 9 DeclareProofOfSpace
local function declare_proof_of_space (tvb, offset, data_tree)
    data_tree:add(pf.declare_proof_of_space__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.declare_proof_of_space__challenge_chain_sp, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.declare_proof_of_space__signage_point_index, tvb:range(offset, 1))
    offset = offset + 1
    data_tree:add(pf.declare_proof_of_space__reward_chain_sp, tvb:range(offset, 32))
    offset = offset + 32
    offset = ProofOfSpace(tvb, offset, data_tree)
    data_tree:add(pf.declare_proof_of_space__challenge_chain_sp_signature, tvb:range(offset, 96))
    offset = offset + 96
    data_tree:add(pf.declare_proof_of_space__reward_chain_sp_signature, tvb:range(offset, 96))
    offset = offset + 96
    data_tree:add(pf.declare_proof_of_space__farmer_puzzle_hash, tvb:range(offset, 32))
    offset = offset + 32
    -- pool_target
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.declare_proof_of_space__pool_target__option, tvb:range(offset, 1))
    end
    local pool_target_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if pool_target_option == 0 then
    elseif pool_target_option == 1 then
        local pool_target_tree = data_tree:add("PoolTarget")
            data_tree:add(pf.declare_proof_of_space__pool_target__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
            data_tree:add(pf.declare_proof_of_space__pool_target__height, tvb:range(offset, 4))
            offset = offset + 4
        -- end of pool_target_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
    -- pool_signature
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.declare_proof_of_space__pool_signature__option, tvb:range(offset, 1))
    end
    local pool_signature_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if pool_signature_option == 0 then
    elseif pool_signature_option == 1 then
            data_tree:add(pf.declare_proof_of_space__pool_signature, tvb:range(offset, 96))
            offset = offset + 96
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
    -- include_signature_source_data
    data_tree:add(pf.declare_proof_of_space__include_signature_source_data, tvb:range(offset, 1))
    offset = offset + 1
end -- 9 declare_proof_of_space


-- 10 RequestSignedValues
local function request_signed_values (tvb, offset, data_tree)
    data_tree:add(pf.request_signed_values__quality_string, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_signed_values__foliage_block_data_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_signed_values__foliage_transaction_block_hash, tvb:range(offset, 32))
    offset = offset + 32
    -- foliage_block_data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signed_values__foliage_block_data__option, tvb:range(offset, 1))
    end
    local foliage_block_data_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if foliage_block_data_option == 0 then
    elseif foliage_block_data_option == 1 then
        offset = FoliageBlockData(tvb, offset, data_tree)
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- foliage_transaction_block_data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signed_values__foliage_transaction_block_data__option, tvb:range(offset, 1))
    end
    local foliage_transaction_block_data_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if foliage_transaction_block_data_option == 0 then
    elseif foliage_transaction_block_data_option == 1 then
        offset = FoliageTransactionBlock(tvb, offset, data_tree)
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- rc_block_unfinished
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_signed_values__rc_block_unfinished__option, tvb:range(offset, 1))
    end
    local rc_block_unfinished_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if rc_block_unfinished_option == 0 then
    elseif rc_block_unfinished_option == 1 then
        offset = RewardChainBlock(tvb, offset, data_tree, "UnfinishedBlock")
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 10 request_signed_values


-- 11 SignedValues
local function signed_values (tvb, offset, data_tree)
    data_tree:add(pf.signed_values__quality_string, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.signed_values__foliage_block_data_signature, tvb:range(offset, 96))
    offset = offset + 96
    data_tree:add(pf.signed_values__foliage_transaction_block_signature, tvb:range(offset, 96))
    offset = offset + 96
end -- 11 signed_values


-- 12 FarmingInfo
local function farming_info (tvb, offset, data_tree)
    data_tree:add(pf.farming_info__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.farming_info__sp_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.farming_info__timestamp, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.farming_info__passed, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.farming_info__proofs, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.farming_info__total_plots, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.farming_info__lookup_time, tvb:range(offset, 8))
    offset = offset + 8
end -- 12 farming_info


-- 13 NewPeakTimelord
local function new_peak_timelord (tvb, offset, data_tree)
    -- reward_chain_block
    offset = RewardChainBlock(tvb, offset, data_tree, "FinishedBlock")

    data_tree:add(pf.new_peak_timelord__difficulty, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_peak_timelord__deficit, tvb:range(offset, 1))
    offset = offset + 1
    data_tree:add(pf.new_peak_timelord__sub_slot_iters, tvb:range(offset, 8))
    offset = offset + 8

    -- sub_epoch_summary
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_peak_timelord__sub_epoch_summary__option, tvb:range(offset, 1))
    end
    local sub_epoch_summary_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if sub_epoch_summary_option == 0 then
    elseif sub_epoch_summary_option == 1 then
        offset = SubEpochSummary(tvb, offset, data_tree)  
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- previous_reward_challenges
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_peak_timelord__previous_reward_challenges__count, tvb:range(offset, 4))
    end
    local previous_reward_challenges_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    for i=1, previous_reward_challenges_count do
        local previous_reward_challenges_tree = data_tree:add("previous_reward_challenges")
            local tuples_tree = 
                    previous_reward_challenges_tree:add("tuple "..i)
                tuples_tree:add(pf.new_peak_timelord__previous_reward_challenges__tuples__bytes32, 
                    tvb:range(offset, 4))
                offset = offset + 4
                tuples_tree:add(pf.new_peak_timelord__previous_reward_challenges__tuples__uint128, 
                    tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
                offset = offset + 16
            -- end of tuples_tree
        -- end of previous_reward_challenges_tree
    end

    data_tree:add(
        pf.new_peak_timelord__last_challenge_sb_or_eos_total_iters, 
        tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
    offset = offset + 16

    data_tree:add(
        pf.new_peak_timelord__passes_ses_height_but_not_yet_included, tvb:range(offset, 1))
    offset = offset + 1
end -- 13 new_peak_timelord


-- 14 NewUnfinishedBlockTimelord
local function new_unfinished_block_timelord (tvb, offset, data_tree)

    offset = RewardChainBlock(tvb, offset, data_tree, "UnfinishedBlock")

    data_tree:add(pf.new_unfinished_block_timelord__difficulty, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_unfinished_block_timelord__sub_slot_iters, tvb:range(offset, 8))
    offset = offset + 8

    offset = Foliage(tvb, offset, data_tree)

    -- sub_epoch_summary
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_unfinished_block_timelord__sub_epoch_summary__option, tvb:range(offset, 1))
    end
    local sub_epoch_summary_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if sub_epoch_summary_option == 0 then
    elseif sub_epoch_summary_option == 1 then
        offset = SubEpochSummary(tvb, offset, data_tree)  
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    data_tree:add(pf.new_unfinished_block_timelord__rc_prev, tvb:range(offset, 4))
    offset = offset + 4
end -- 14 new_unfinished_block_timelord


-- 15 NewInfusionPointVDF
local function new_infusion_point_vdf (tvb, offset, data_tree)
    data_tree:add(pf.new_infusion_point_vdf__unfinished_reward_hash, tvb:range(offset, 4))
    offset = offset + 4

    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)
    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)

    -- infused_challenge_chain_ip_vdf
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_infusion_point_vdf__infused_challenge_chain_ip_vdf__option, tvb:range(offset, 1))
    end
    local infused_challenge_chain_ip_vdf_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if infused_challenge_chain_ip_vdf_option == 0 then
    elseif infused_challenge_chain_ip_vdf_option == 1 then
        offset = VDFInfo(tvb, offset, data_tree)
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- infused_challenge_chain_ip_proof
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_infusion_point_vdf__infused_challenge_chain_ip_proof__option, tvb:range(offset, 1))
    end
    local infused_challenge_chain_ip_proof_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if infused_challenge_chain_ip_proof_option == 0 then
    elseif infused_challenge_chain_ip_proof_option == 1 then
        offset = VDFProof(tvb, offset, data_tree)
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 15 new_infusion_point_vdf


-- 16 NewSignagePointVDF
local function new_signage_point_vdf (tvb, offset, data_tree)
    data_tree:add(pf.new_signage_point_vdf__index_from_challenge, tvb:range(offset, 1))
    offset = offset + 1
    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)
    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)
end -- 16 new_signage_point_vdf


-- 17 NewEndOfSubSlotVDF
local function new_end_of_sub_slot_vdf (tvb, offset, data_tree)
    offset = EndOfSubSlotBundle(tvb, offset, data_tree)
end -- 17 new_end_of_sub_slot_vdf


-- 18 RequestCompactProofOfTime
local function request_compact_proof_of_time (tvb, offset, data_tree)

    offset = VDFInfo(tvb, offset, data_tree)

    data_tree:add(pf.request_compact_proof_of_time__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_compact_proof_of_time__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_compact_proof_of_time__field_vdf, tvb:range(offset, 1))
    offset = offset + 1
end -- 18 request_compact_proof_of_time


-- 19 RespondCompactProofOfTime
local function respond_compact_proof_of_time (tvb, offset, data_tree)

    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)

    data_tree:add(pf.respond_compact_proof_of_time__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.respond_compact_proof_of_time__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.respond_compact_proof_of_time__field_vdf, tvb:range(offset, 1))
    offset = offset + 1
end -- 19 respond_compact_proof_of_time


-- 20 NewPeak
local function new_peak (tvb, offset, data_tree)
    data_tree:add(pf.new_peak__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.new_peak__height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.new_peak__weight, tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
    offset = offset + 16

    data_tree:add(pf.new_peak__fork_point_with_previous_peak, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.new_peak__unfinished_reward_block_hash, tvb:range(offset, 32))
    offset = offset + 32
end -- 20 new_peak


-- 21 NewTransaction
local function new_transaction (tvb, offset, data_tree)
    data_tree:add(pf.new_transaction__transaction_id, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.new_transaction__cost, tvb:range(offset, 8))
    offset = offset + 8

    data_tree:add(pf.new_transaction__fees, tvb:range(offset, 8))
    offset = offset + 8
end -- 21 new_transaction


-- 22 RequestTransaction
local function request_transaction (tvb, offset, data_tree)
    data_tree:add(pf.request_transaction__transaction_id, tvb:range(offset, 32))
    offset = offset + 32
end -- 22 request_transaction


-- 23 RespondTransaction
local function respond_transaction (tvb, offset, data_tree)
    offset = SpendBundle(tvb, offset, data_tree)
end -- 23 respond_transaction


-- 24 RequestProofOfWeight
local function request_proof_of_weight (tvb, offset, data_tree)
    data_tree:add(pf.request_proof_of_weight__total_number_of_blocks, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_proof_of_weight__tip, tvb:range(offset, 32))
    offset = offset + 32
end -- 24 request_proof_of_weight


-- 25 RespondProofOfWeight
local function respond_proof_of_weight (tvb, offset, data_tree)
    -- wp
    local wp_tree = data_tree:add("wp (WeightProof)")
        if SHOW_SERIAL_PROTO == true then
            wp_tree:add(pf.respond_proof_of_weight__wp__sub_epochs__count, tvb:range(offset, 4))
        end
        local sub_epochs_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local sub_epochs_tree = wp_tree:add("sub_epochs (Vec<SubEpochData>)")
            for i=1, sub_epochs_count do
                local sub_epoch_data_tree = sub_epochs_tree:add("SubEpochData")
                    sub_epoch_data_tree:add(pf.respond_proof_of_weight__wp__sub_epochs__reward_chain_hash, 
                        tvb:range(offset, 32))
                    offset = offset + 32

                    sub_epoch_data_tree:add(
                        pf.respond_proof_of_weight__wp__sub_epochs__num_blocks_overflow, tvb:range(offset, 1))
                    offset = offset + 1

                    if SHOW_SERIAL_PROTO == true then
                        sub_epoch_data_tree:add(pf.respond_proof_of_weight__wp__sub_epochs__new_sub_slot_iters__option, tvb:range(offset, 1))
                    end
                    local new_sub_slot_iters__option = tvb:range(offset, 1):uint()
                    offset = offset + 1
                    if new_sub_slot_iters__option == 0 then
                    elseif new_sub_slot_iters__option == 1 then
                        sub_epoch_data_tree:add(pf.respond_proof_of_weight__wp__sub_epochs__new_sub_slot_iters, 
                            tvb:range(offset, 8))
                        offset = offset + 8
                    else
                        sub_epoch_data_tree:add(pf.dissector__error, 
                            "Deserialization Error: value of type bool (0/1) expected!")
                    return end

                    if SHOW_SERIAL_PROTO == true then
                        sub_epoch_data_tree:add(pf.respond_proof_of_weight__wp__sub_epochs__new_difficulty__option, 
                            tvb:range(offset, 1))
                    end
                    local new_difficulty__option = tvb:range(offset, 1):uint()
                    offset = offset + 1
                    if new_difficulty__option == 0 then
                    elseif new_difficulty__option == 1 then
                        sub_epoch_data_tree:add(
                            pf.respond_proof_of_weight__wp__sub_epochs__new_difficulty, tvb:range(offset, 8))
                        offset = offset + 8
                    else
                        sub_epoch_data_tree:add(pf.dissector__error, 
                            "Deserialization Error: value of type bool (0/1) expected!")
                    return end
                -- end of sub_epoch_data_tree
            end
        -- end of sub_epochs_tree

        if SHOW_SERIAL_PROTO == true then
            wp_tree:add(pf.respond_proof_of_weight__wp__sub_epoch_segments__count, tvb:range(offset, 4))
        end
        local sub_epoch_segments_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local sub_epoch_segments_tree = wp_tree:add("sub_epoch_segments (Vec<SubEpochChallengeSegment>])")
            for i=1, sub_epoch_segments_count do
                local sub_epoch_challenge_segment_tree = sub_epoch_segments_tree:add("SubEpochChallengeSegment")
                    sub_epoch_challenge_segment_tree:add(
                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_epoch_n, tvb:range(offset, 4))
                    offset = offset + 4

                    if SHOW_SERIAL_PROTO == true then
                        sub_epoch_challenge_segment_tree:add(
                            pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__count, tvb:range(offset, 4))
                    end
                    local sub_slots_count = tvb:range(offset, 4):uint()
                    offset = offset + 4
                    local sub_slots_tree = sub_epoch_challenge_segment_tree:add("sub_slots (Vec<SubSlotData>)")
                        for i=1, sub_slots_count do
                            local sub_slot_tree = sub_slots_tree:add("SubSlotData")
                                -- proof_of_space
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__proof_of_space__option, 
                                        tvb:range(offset, 1))
                                end
                                local proof_of_space__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if proof_of_space__option == 0 then
                                elseif proof_of_space__option == 1 then
                                    offset = ProofOfSpace(tvb, offset, sub_slot_tree)
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_signage_point
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_signage_point__option, 
                                        tvb:range(offset, 1))
                                end
                                local cc_signage_point__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_signage_point__option == 0 then
                                elseif cc_signage_point__option == 1 then
                                    local cc_signage_point_tree = sub_slot_tree:add("cc_signage_point (VDFProof)")
                                        offset = VDFProof(tvb, offset, cc_signage_point_tree)
                                    -- end of cc_signage_point_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_infusion_point
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_infusion_point__option, 
                                        tvb:range(offset, 1))
                                end
                                local cc_infusion_point__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_infusion_point__option == 0 then
                                elseif cc_infusion_point__option == 1 then
                                    local cc_infusion_point_tree = sub_slot_tree:add("cc_infusion_point (VDFProof)")
                                        offset = VDFProof(tvb, offset, cc_infusion_point_tree)
                                    -- end of cc_infusion_point_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- icc_infusion_point
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_infusion_point__option, tvb:range(offset, 1))
                                end
                                local icc_infusion_point__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if icc_infusion_point__option == 0 then
                                elseif icc_infusion_point__option == 1 then
                                    local icc_infusion_point_tree = sub_slot_tree:add("icc_infusion_point (VDFProof)")
                                        offset = VDFProof(tvb, offset, icc_infusion_point_tree)
                                    -- end of icc_infusion_point_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_sp_vdf_info
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_sp_vdf_info__option, 
                                        tvb:range(offset, 1))
                                end
                                local cc_sp_vdf_info__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_sp_vdf_info__option == 0 then
                                elseif cc_sp_vdf_info__option == 1 then
                                    local cc_sp_vdf_info_tree = sub_slot_tree:add("cc_sp_vdf_info (VDFInfo)")
                                        offset = VDFInfo(tvb, offset, cc_sp_vdf_info_tree)
                                    -- end of cc_sp_vdf_info_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- signage_point_index
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__signage_point_index__option, 
                                        tvb:range(offset, 1))
                                end
                                local signage_point_index__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if signage_point_index__option == 0 then
                                elseif signage_point_index__option == 1 then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__signage_point_index, 
                                        tvb:range(offset, 1))
                                    offset = offset + 1
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_slot_end
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_slot_end__option, 
                                        tvb:range(offset, 1))
                                end
                                local cc_slot_end__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_slot_end__option == 0 then
                                elseif cc_slot_end__option == 1 then
                                    local cc_slot_end_tree = sub_slot_tree:add("cc_slot_end (VDFProof)")
                                        offset = VDFProof(tvb, offset, cc_slot_end_tree)
                                    -- end of cc_slot_end_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- icc_slot_end
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_slot_end__option, 
                                    tvb:range(offset, 1))
                                end
                                local icc_slot_end__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if icc_slot_end__option == 0 then
                                elseif icc_slot_end__option == 1 then
                                    local icc_slot_end_tree = sub_slot_tree:add("icc_slot_end (VDFProof)")
                                        offset = VDFProof(tvb, offset, icc_slot_end_tree)
                                    -- end of icc_slot_end_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_slot_end_info
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_slot_end_info__option, 
                                        tvb:range(offset, 1))
                                end
                                local cc_slot_end_info__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_slot_end_info__option == 0 then
                                elseif cc_slot_end_info__option == 1 then
                                    local cc_slot_end_info_tree = sub_slot_tree:add("cc_slot_end_info (VDFInfo)")
                                        offset = VDFInfo(tvb, offset, cc_slot_end_info_tree)
                                    -- end of cc_slot_end_info_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- icc_slot_end_info
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_slot_end_info__option, 
                                        tvb:range(offset, 1))
                                end
                                local icc_slot_end_info__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if icc_slot_end_info__option == 0 then
                                elseif icc_slot_end_info__option == 1 then
                                    local icc_slot_end_info_tree = sub_slot_tree:add("icc_slot_end_info (VDFInfo)")
                                        offset = VDFInfo(tvb, offset, icc_slot_end_info_tree)
                                    -- end of icc_slot_end_info_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- cc_ip_vdf_info
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__cc_ip_vdf_info__option, 
                                    tvb:range(offset, 1))
                                end
                                local cc_ip_vdf_info__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if cc_ip_vdf_info__option == 0 then
                                elseif cc_ip_vdf_info__option == 1 then
                                    local cc_ip_vdf_info_tree = sub_slot_tree:add("cc_ip_vdf_info (VDFInfo)")
                                        offset = VDFInfo(tvb, offset, cc_ip_vdf_info_tree)
                                    -- end of cc_ip_vdf_info_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- icc_ip_vdf_info
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__icc_ip_vdf_info__option, 
                                        tvb:range(offset, 1))
                                end
                                local icc_ip_vdf_info__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if icc_ip_vdf_info__option == 0 then
                                elseif icc_ip_vdf_info__option == 1 then
                                    local icc_ip_vdf_info_tree = sub_slot_tree:add("icc_ip_vdf_info (VDFInfo)")
                                        offset = VDFInfo(tvb, offset, icc_ip_vdf_info_tree)
                                    -- end of icc_ip_vdf_info_tree
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end

                                -- total_iters
                                if SHOW_SERIAL_PROTO == true then
                                    sub_slot_tree:add(
                                        pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__total_iters__option, 
                                        tvb:range(offset, 1))
                                end
                                local total_iters__option = tvb:range(offset, 1):uint()
                                offset = offset + 1
                                if total_iters__option == 0 then
                                elseif total_iters__option == 1 then
                                    sub_slot_tree:add(
                                            pf.respond_proof_of_weight__wp__sub_epoch_segments__sub_slots__total_iters, 
                                            tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
                                    offset = offset + 16
                                else
                                    sub_slot_tree:add(pf.dissector__error, 
                                        "Deserialization Error: value of type bool (0/1) expected!")
                                return end
                            -- end of sub_slot_tree
                        end
                    -- end of sub_slots_tree

                    -- rc_slot_end_info
                    if SHOW_SERIAL_PROTO == true then
                        sub_epoch_challenge_segment_tree:add(pf.respond_proof_of_weight__wp__sub_epoch_segments__rc_slot_end_info__option, 
                        tvb:range(offset, 1))
                    end
                    local rc_slot_end_info__option = tvb:range(offset, 1):uint()
                    offset = offset + 1
                    if rc_slot_end_info__option == 0 then
                    elseif rc_slot_end_info__option == 1 then
                        local rc_slot_end_info_tree = sub_epoch_challenge_segment_tree:add("rc_slot_end_info (VDFInfo)")
                            offset = VDFInfo(tvb, offset, rc_slot_end_info_tree)
                        -- end of rc_slot_end_info_tree
                    else
                        sub_epoch_challenge_segment_tree:add(pf.dissector__error, 
                            "Deserialization Error: value of type bool (0/1) expected!")
                    return end
                -- end of sub_epoch_challenge_segment_tree
            end
        -- end of sub_epoch_segments_tree

        -- recent_chain_data
        if SHOW_SERIAL_PROTO == true then
            wp_tree:add(pf.respond_proof_of_weight__wp__recent_chain_data__count, 
                tvb:range(offset, 4))
        end
        local recent_chain_data_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local recent_chain_data_tree = wp_tree:add("recent_chain_data (Vec<HeaderBlock>)")
            for i=1, recent_chain_data_count do
                local header_block_tree = recent_chain_data_tree:add("HeaderBlock")
                    offset = Block(tvb, offset, header_block_tree, "HeaderBlock")
            end
        -- end of recent_chain_data_tree
    -- end of wp_tree

    -- tip
    data_tree:add(pf.respond_proof_of_weight__tip, tvb:range(offset, 32))
end -- 25 respond_proof_of_weight


-- 26 RequestBlock
local function request_block (tvb, offset, data_tree)
    data_tree:add(pf.request_block__height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.request_block__include_transaction_block, tvb:range(offset, 1))
    offset = offset + 1
end -- 26 request_block


-- 27 RespondBlock
local function respond_block (tvb, offset, data_tree)
    offset = Block(tvb, offset, data_tree, "FullBlock")
end -- 27 respond_block


-- 28 RejectBlock
local function reject_block (tvb, offset, data_tree)
    data_tree:add(pf.reject_block__height, tvb:range(offset, 4))
    offset = offset + 4
end -- 28 reject_block


-- 29 RequestBlocks
local function request_blocks (tvb, offset, data_tree)
    data_tree:add(pf.request_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.request_blocks__end_height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.request_blocks__include_transaction_block, tvb:range(offset, 1))
    offset = offset + 1
end -- 29 request_blocks


-- 30 RespondBlocks
local function respond_blocks (tvb, offset, data_tree)
    data_tree:add(pf.respond_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.respond_blocks__end_height, tvb:range(offset, 4))
    offset = offset + 4

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_blocks__blocks__count, tvb:range(offset, 4))
    end
    local blocks_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local blocks_tree = data_tree:add("FullBlocks")
    for i=1, blocks_count do
        local fullblock_tree = blocks_tree:add("FullBlock")
            offset = Block(tvb, offset, fullblock_tree, "FullBlock")
        -- end of fullblock_tree
    end
end -- 30 respond_blocks


-- 31 RejectBlocks
local function reject_blocks (tvb, offset, data_tree)
    data_tree:add(pf.reject_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.reject_blocks__end_height, tvb:range(offset, 4))
end -- 31 reject_blocks


-- 32 NewUnfinishedBlock
local function new_unfinished_block (tvb, offset, data_tree)
    data_tree:add(pf.new_unfinished_block__unfinished_reward_hash, tvb:range(offset, 32))
end -- 32 new_unfinished_block


-- 33 RequestUnfinishedBlock
local function request_unfinished_block (tvb, offset, data_tree)
    data_tree:add(pf.request_unfinished_block__unfinished_reward_hash, tvb:range(offset, 32))
end -- 33 request_unfinished_block


-- 34 RespondUnfinishedBlock
local function respond_unfinished_block (tvb, offset, data_tree)
    local unfinished_block_tree = data_tree:add("unfinished_block (UnfinishedBlock)")
        offset = Block(tvb, offset, unfinished_block_tree, "UnfinishedBlock")
    -- end of unfinished_block_tree
end -- 34 respond_unfinished_block


-- 35 NewSignagePointOrEndOfSubSlot
local function new_signage_point_or_end_of_sub_slot (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_signage_point_or_end_of_sub_slot__prev_challenge_hash__option, tvb:range(offset, 1))
    end
    local prev_challenge_hash__option = tvb:range(offset, 1):uint()
    offset = offset + 1

    if prev_challenge_hash__option == 0 then
    elseif prev_challenge_hash__option == 1 then
        data_tree:add(pf.new_signage_point_or_end_of_sub_slot__prev_challenge_hash, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    data_tree:add(pf.new_signage_point_or_end_of_sub_slot__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.new_signage_point_or_end_of_sub_slot__index_from_challenge, tvb:range(offset, 1))
    offset = offset + 1

    data_tree:add(pf.new_signage_point_or_end_of_sub_slot__last_rc_infusion, tvb:range(offset, 32))
    offset = offset + 32
end -- 35 new_signage_point_or_end_of_sub_slot


-- 36 RequestSignagePointOrEndOfSubSlot
local function request_signage_point_or_end_of_sub_slot (tvb, offset, data_tree)
    data_tree:add(pf.request_signage_point_or_end_of_sub_slot__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32

    data_tree:add(pf.request_signage_point_or_end_of_sub_slot__index_from_challenge, tvb:range(offset, 1))
    offset = offset + 1

    data_tree:add(pf.request_signage_point_or_end_of_sub_slot__last_rc_infusion, tvb:range(offset, 32))
    offset = offset + 32
end -- 36 request_signage_point_or_end_of_sub_slot


-- 37 RespondSignagePoint
local function respond_signage_point (tvb, offset, data_tree)
    data_tree:add(pf.respond_signage_point__index_from_challenge, tvb:range(offset, 1))
    offset = offset + 1
    -- challenge_chain_vdf
    offset = VDFInfo(tvb, offset, data_tree)
    -- challenge_chain_proof
    offset = VDFProof(tvb, offset, data_tree)
    -- reward_chain_vdf
    offset = VDFInfo(tvb, offset, data_tree)
    -- reward_chain_proof
    offset = VDFProof(tvb, offset, data_tree)
end -- 37 respond_signage_point


-- 38 RespondEndOfSubSlot
local function respond_end_of_sub_slot (tvb, offset, data_tree)
    offset = EndOfSubSlotBundle(tvb, offset, data_tree)
end -- 38 respond_end_of_sub_slot


-- 39 RequestMempoolTransactions
local function request_mempool_transactions (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_mempool_transactions__filter__length, tvb:range(offset, 4))
    end
    local filter__length = tvb:range(offset, 4):uint()
    offset = offset + 4

    data_tree:add(pf.request_mempool_transactions__filter, tvb:range(offset, filter__length))
    offset = offset + filter__length
end -- 39 request_mempool_transactions


-- 40 RequestCompactVDF
local function request_compact_vdf (tvb, offset, data_tree)
    data_tree:add(pf.request_compact_vdf__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_compact_vdf__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_compact_vdf__field_vdf, tvb:range(offset, 1))
    offset = offset + 1
    
    offset = VDFInfo(tvb, offset, data_tree)
end -- 40 request_compact_vdf


-- 41 RespondCompactVDF
local function respond_compact_vdf (tvb, offset, data_tree)
    data_tree:add(pf.respond_compact_vdf__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.respond_compact_vdf__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.respond_compact_vdf__field_vdf, tvb:range(offset, 1))
    offset = offset + 1
    
    offset = VDFInfo(tvb, offset, data_tree)
    offset = VDFProof(tvb, offset, data_tree)
end -- 41 respond_compact_vdf


-- 42 NewCompactVDF
local function new_compact_vdf (tvb, offset, data_tree)
    data_tree:add(pf.respond_compact_vdf__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.new_compact_vdf__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_compact_vdf__field_vdf, tvb:range(offset, 1))
    offset = offset + 1
    
    offset = VDFInfo(tvb, offset, data_tree)
end -- 42 new_compact_vdf


-- 43 RequestPeers / request_peers


-- 44 RespondPeers
local function respond_peers(tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_peers__peer_list__count, tvb:range(offset, 4))
    end
    local peer_list_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local peer_list_tree = data_tree:add("peer_list")
        for i=1, peer_list_count do
            offset = TimestampedPeerInfo(tvb, offset, peer_list_tree)
        end
end -- 44 respond_peers


-- 45 RequestPuzzleSolution
local function request_puzzle_solution (tvb, offset, data_tree)
    data_tree:add(pf.request_puzzle_solution__coin_name, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.request_puzzle_solution__height, tvb:range(offset, 4))
end -- 45 request_puzzle_solution


-- 46 RespondPuzzleSolution
local function respond_puzzle_solution (tvb, offset, data_tree)
    data_tree:add(pf.respond_puzzle_solution__coin_name, tvb:range(offset+5,32))
    offset = offset + 32
    data_tree:add(pf.respond_puzzle_solution__height, tvb:range(offset, 4))
    offset = offset + 4
    local puzzle_offset = ParseSerializedProgramTrusted(tvb,offset, data_tree)
    data_tree:add(pf.respond_puzzle_solution__puzzle, tvb:range(offset, (puzzle_offset - offset)))
    offset = puzzle_offset + 1
    local solution_offset = ParseSerializedProgramTrusted(tvb,offset, data_tree)
    data_tree:add(pf.respond_puzzle_solution__solution, tvb:range(offset, (solution_offset - offset)))
end -- 46 respond_puzzle_solution


-- 47 RejectPuzzleSolution
local function reject_puzzle_solution (tvb, offset, data_tree)
    data_tree:add(pf.reject_puzzle_solution__coin_name, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.reject_puzzle_solution__height, tvb:range(offset, 4))
end -- 47 reject_puzzle_solution


-- 48 SendTransaction
local function send_transaction (tvb, offset, data_tree)
    offset = SpendBundle(tvb, offset, data_tree)
end -- 48 send_transaction


-- 49 TransactionAck
local function transaction_ack (tvb, offset, data_tree)
    data_tree:add(pf.transaction_ack__txid, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.transaction_ack__status, tvb:range(offset, 1))
    local status_enum = chia_enum_MempoolInclusionStatus[tvb:range(offset, 1):uint()]
    offset = offset + 1
    data_tree:add(pf.transaction_ack__status__enum, status_enum):set_generated()
    -- eror
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.transaction_ack__error__option, tvb:range(offset, 1))
    end
    local error_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if error_option == 0 then
    elseif error_option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.transaction_ack__error__length, tvb:range(offset, 4))
        end
        local error_length = tvb:range(offset, 4):uint()
        offset = offset + 4
        data_tree:add(pf.transaction_ack__error, tvb:range(offset, error_length))
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 49 transaction_ack


-- 50 NewPeakWallet
local function new_peak_wallet (tvb, offset, data_tree)
    data_tree:add(pf.new_peak_wallet__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_peak_wallet__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.new_peak_wallet__weight, tonumber(tostring(tvb:range(offset, 16):bytes()), 16))
    offset = offset + 16
    data_tree:add(pf.new_peak_wallet__fork_point_with_previous_peak, tvb:range(offset, 4))
end -- 50 new_peak_wallet


-- 51 RequestBlockHeader
local function request_block_header (tvb, offset, data_tree)
    data_tree:add(pf.request_block_header__height, tvb:range(offset, 4))
end -- 51 request_block_header


-- 52 RespondBlockHeader
local function respond_block_header (tvb, offset, data_tree)
    local header_block_tree = data_tree:add("header_block (HeaderBlock)")
        Block(tvb, offset, header_block_tree, "HeaderBlock")
    -- end of header_block_tree
end -- 52 respond_block_header


-- 53 RejectHeaderRequest
local function reject_header_request (tvb, offset, data_tree)
    data_tree:add(pf.reject_header_request__height, tvb:range(offset, 4))
end -- 53 reject_header_request


-- 54 RequestRemovals
local function request_removals (tvb, offset, data_tree)
    data_tree:add(pf.request_removals__height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.request_removals__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_removals__coin_names__option, tvb:range(offset, 1))
    end
    local coin_names__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if coin_names__option == 0 then
    elseif coin_names__option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.request_removals__coin_names__count, tvb:range(offset, 4))
        end
        local coin_names_count = tvb:range(offset, 4):uint()
        offset = offset + 4

        local coin_names_tree = data_tree:add("coin_names")
            for i=1, coin_names_count do
                coin_names_tree:add(pf.request_removals__coin_names__coin_name, tvb:range(offset, 32))
                offset = offset + 32
            end
        -- end of coin_names_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 54 request_removals


-- 55 RespondRemovals
local function respond_removals (tvb, offset, data_tree)
    data_tree:add(pf.respond_removals__height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.respond_removals__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    local coins_tree = data_tree:add("coins")
        if SHOW_SERIAL_PROTO == true then
            coins_tree:add(pf.respond_removals__coins__coin_tuple__count, tvb:range(offset, 4))
        end
        local coins__coin_count = tvb:range(offset, 4):uint()
        offset = offset + 4

        local coin_tuple_tree = coins_tree:add("coin_tuple")
            for i=1, coins__coin_count do
                coin_tuple_tree:add(pf.respond_removals__coins__coin_tuple__bytes32, tvb:range(offset, 32))
                offset = offset + 32

                if SHOW_SERIAL_PROTO == true then
                    coin_tuple_tree:add(pf.respond_removals__coins__coin_tuple__coin__option, tvb:range(offset, 1))
                end
                local coin_tuple__coin__option = tvb:range(offset, 1):uint()
                offset = offset + 1

                if coin_tuple__coin__option == 0 then
                elseif coin_tuple__coin__option == 1 then
                    local coin_tree = coin_tuple_tree:add("coin")
                        offset = Coin(tvb, offset, coin_tree)
                    -- end of coin_tree
                else
                    coin_tuple_tree:add(pf.dissector__error, 
                        "Deserialization Error: value of type bool (0/1) expected!")
                return end
            end
        -- end of coin_tuple
    -- end of coins_tree

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_removals__proofs__option, tvb:range(offset, 1))
    end
    local proofs_option = tvb:range(offset, 1):uint()
    offset = offset + 1

    if proofs_option == 0 then
    elseif proofs_option == 1 then
        local proofs_tree = data_tree:add("proofs")
            if SHOW_SERIAL_PROTO == true then
                proofs_tree:add(pf.respond_removals__proofs__count, tvb:range(offset, 4))
            end
            local proofs_count = tvb:range(offset, 4):uint()
            offset = offset + 4

            for i=1, proofs_count do
                local proof_tuple_tree = proofs_tree:add("proof_tuple")
                    proof_tuple_tree:add(pf.respond_removals__proofs__proof_tuple__bytes32, tvb:range(offset, 32))
                    offset = offset + 32

                    if SHOW_SERIAL_PROTO == true then
                        proof_tuple_tree:add(pf.respond_removals__proofs__proof_tuple__bytes__length, 
                            tvb:range(offset, 4))
                    end
                    local proof_tuple__bytes__length = tvb:range(offset, 4):uint()
                    offset = offset + 4

                    proof_tuple_tree:add(pf.respond_removals__proofs__proof_tuple__bytes, 
                        tvb:range(offset, proof_tuple__bytes__length))
                    offset = offset + proof_tuple__bytes__length
                -- end of proof_tuple_tree
            end
        -- end of proofs_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 55 respond_removals


-- 56 RejectRemovalsRequest
local function reject_removals_request (tvb, offset, data_tree)
    data_tree:add(pf.reject_removals_request__height, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.reject_removals_request__header_hash, tvb:range(offset, 4))
end


-- 57 RequestAdditions
local function request_additions (tvb, offset, data_tree)
    data_tree:add(pf.request_additions__height, tvb:range(offset, 4))
    offset = offset + 4

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_additions__header_hash__option, tvb:range(offset, 1))
    end
    local header_hash__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if header_hash__option == 0 then
    elseif header_hash__option == 1 then
        data_tree:add(pf.request_additions__header_hash, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_additions__puzzle_hashes__option, tvb:range(offset, 1))
    end
    local puzzle_hashes__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        data_tree:add(pf.request_additions__puzzle_hashes__count, tvb:range(offset, 4))
        local puzzle_hashes_count = tvb:range(offset, 4):uint()
        offset = offset + 4

        local puzzle_hash_tree = data_tree:add("puzzle_hashes")
            for i=1, puzzle_hashes_count do
                puzzle_hash_tree:add(pf.request_additions__puzzle_hash, tvb:range(offset, 32))
                offset = offset + 32
            end
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 57 request_additions


-- 58 RespondAdditions
local function respond_additions (tvb, offset, data_tree)
    data_tree:add(pf.respond_additions__height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.respond_additions__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_additions__coins__count, tvb:range(offset, 4))
    end
    local coins_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local coins_tree = data_tree:add("coins (list[tuple[bytes32, list[Coin]]])")
        for i=1, coins_count do
            local coin_tuple_tree = coins_tree:add("(tuple[bytes32, list[Coin]])")
                coin_tuple_tree:add(pf.respond_additions__coins__bytes32, tvb:range(offset, 32))
                offset = offset + 32

                if SHOW_SERIAL_PROTO == true then
                    coin_tuple_tree:add(pf.respond_additions__coins__coin__count, tvb:range(offset, 4))
                end
                local coin_count = tvb:range(offset, 4):uint()
                offset = offset + 4

                local coins_tree = coin_tuple_tree:add("(list[Coin])")
                for i=1, coin_count do
                    local coin_tree = coins_tree:add("(Coin)")
                        offset = Coin(tvb, offset, coin_tree)
                    -- end of coin_tree
                end
            -- end of coin_tuple_tree
        end
    -- end of coins_tree

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_additions__proofs__option, tvb:range(offset, 1))
    end
    local proofs__option = tvb:range(offset, 1):uint()
    offset = offset + 1

    if proofs__option == 0 then
    elseif proofs__option == 1 then
        local proofs_tree = data_tree:add("proofs (list[tuple[bytes32, bytes, Optional[bytes]]])")
            if SHOW_SERIAL_PROTO == true then
                proofs_tree:add(pf.respond_additions__proofs__count, tvb:range(offset, 4))
            end
            offset = offset + 4

            local proofs_tuple_tree = proofs_tree:add("(tuple[bytes32, bytes, Optional[bytes]])")
                proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes32, tvb:range(offset, 32))
                offset = offset + 32

                if SHOW_SERIAL_PROTO == true then
                    proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes__length, 
                        tvb:range(offset, 4))
                end
                local proof_tuple__bytes__length = tvb:range(offset, 4):uint()
                offset = offset + 4

                proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes, 
                    tvb:range(offset, proof_tuple__bytes__length))
                offset = offset + proof_tuple__bytes__length

                proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes2__option, tvb:range(offset, 1))
                local proof_tuple__bytes2__option = tvb:range(offset, 1):uint()
                offset = offset + 1

                if proof_tuple__bytes2__option == 0 then
                elseif proof_tuple__bytes2__option == 1 then
                    if SHOW_SERIAL_PROTO == true then
                        proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes2__length, 
                            tvb:range(offset, 4))
                    end
                    local proof_tuple__bytes2__length = tvb:range(offset, 4):uint()
                    offset = offset + 4

                    proofs_tuple_tree:add(pf.respond_additions__proofs__proof_tuple__bytes2, 
                        tvb:range(offset, proof_tuple__bytes2__length))
                    offset = offset + proof_tuple__bytes2__length
                else
                    proofs_tuple_tree:add(pf.dissector__error, 
                        "Deserialization Error: value of type bool (0/1) expected!")
                return end
            -- endo of proofs_tuple_tree
        -- end of proofs_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 58 respond_additions


-- 59 RejectAdditionsRequest
local function reject_additions_request (tvb, offset, data_tree)
    data_tree:add(pf.reject_additions_request__height, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.reject_additions_request__header_hash, tvb:range(offset, 4))
end -- 59 reject_additions_request


-- 60 RequestHeaderBlocks
local function request_header_blocks (tvb, offset, data_tree)
    data_tree:add(pf.request_header_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_header_blocks__end_height, tvb:range(offset, 4))
end -- 60 request_header_blocks


-- 61 RejectHeaderBlocks
local function reject_header_blocks (tvb, offset, data_tree)
    data_tree:add(pf.reject_header_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.reject_header_blocks__end_height, tvb:range(offset, 4))
end -- 61 reject_header_blocks


-- 62 RespondHeaderBlocks
local function respond_header_blocks (tvb, offset, data_tree)
    data_tree:add(pf.respond_header_blocks__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.respond_header_blocks__end_height, tvb:range(offset, 4))
    offset = offset + 4
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_header_blocks__header_blocks__count, tvb:range(offset, 4))
    end
    local header_blocks_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local header_blocks_tree = data_tree:add("header_blocks (list[HeaderBlock])")
        for i=1, header_blocks_count do
            local header_block_tree = header_blocks_tree:add("HeaderBlock")
                offset = Block(tvb, offset, header_block_tree, "HeaderBlock")
            -- end of header_block_tree
        end
    -- end of header_blocks_tree
end -- 62 respond_header_blocks


-- 63 RequestPeersIntroducer / request_peers_introducer


-- 64 RespondPeersIntroducer
local function respond_peers_introducer (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_peers_introducer__peer_list__count, tvb:range(offset, 4))
    end
    local peer_list_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local peer_list_tree = data_tree:add("peer_list (list[TimestampedPeerInfo])")
        for i=1, peer_list_count do
            offset = TimestampedPeerInfo(tvb, offset, peer_list_tree)
        end
    -- end of peer_list_tree
end -- 64 respond_peers_introducer


-- 65 FarmNewBlockProtocol
local function farm_new_block (tvb, offset, data_tree)
    data_tree:add(pf.farm_new_block__puzzle_hash, tvb:range(offset, 32))
end -- 65 farm_new_block


-- 66 NewSignagePointHarvester
local function new_signage_point_harvester (tvb, offset, data_tree)
    data_tree:add(pf.new_signage_point_harvester__challenge_hash, tvb:range(offset, 32))
    offset = offset + 32
    data_tree:add(pf.new_signage_point_harvester__difficulty, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_signage_point_harvester__sub_slot_iters, tvb:range(offset, 8))
    offset = offset + 8
    data_tree:add(pf.new_signage_point_harvester__signage_point_index, tvb:range(offset, 1))
    offset = offset + 1
    data_tree:add(pf.new_signage_point_harvester__sp_hash, tvb:range(offset, 32))
    offset = offset + 32
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_signage_point_harvester__pool_difficulties__count, tvb:range(offset, 4))
    end
    local pool_difficulties_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local pool_difficulties_tree = data_tree:add("pool_difficulties (list[PoolDifficulty])")
        for i=1, pool_difficulties_count do
            local pool_difficulty_tree = pool_difficulties_tree:add("PoolDifficulty")
                pool_difficulty_tree:add(pf.new_signage_point_harvester__PoolDifficulty__difficulty, tvb:range(offset, 8))
                offset = offset + 8
                pool_difficulty_tree:add(pf.new_signage_point_harvester__PoolDifficulty__sub_slot_iters, tvb:range(offset, 8))
                offset = offset + 8
                pool_difficulty_tree:add(pf.new_signage_point_harvester__PoolDifficulty__pool_contract_puzzle_hash, 
                    tvb:range(offset, 32))
                offset = offset + 32
            -- end of pool_difficulty_tree
        end
    -- end of pool_difficulties_tree

    data_tree:add(pf.new_signage_point_harvester__filter_prefix_bits, tvb:range(offset, 1))
end -- 66 new_signage_point_harvester


-- 67 RequestPlots / request_plots


-- 68 RespondPlots
local function respond_plots (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_plots__plots__count, tvb:range(offset, 4))
    end
    local plots_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local plots_tree = data_tree:add("plots")
        for i=1, plots_count do
            offset = Plot(tvb, offset, plots_tree)
        end
    -- end of plots_tree

    -- failed_to_open_filenames
    local failed_to_open_filenames_tree = data_tree:add("failed_to_open_filenames")
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.respond_plots__failed_to_open_filenames__count, tvb:range(offset, 4))
        end
        local failed_to_open_filenames_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        for i=1, failed_to_open_filenames_count do
            if SHOW_SERIAL_PROTO == true then
                data_tree:add(pf.respond_plots__failed_to_open_filenames__filename__length, tvb:range(offset, 4))
            end
            local filename_length = tvb:range(offset, 4):uint()
            offset = offset + 4
            data_tree:add(pf.respond_plots__failed_to_open_filenames__filename, tvb:range(offset, filename_length))
            offset = offset + filename_length
        end
    -- end of failed_to_open_filenames_tree
    -- no_key_filenames
    local no_key_filenames_tree = data_tree:add("no_key_filenames")
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.respond_plots__no_key_filenames__count, tvb:range(offset, 4))
        end
        local no_key_filenames_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        for i=1, no_key_filenames_count do
            if SHOW_SERIAL_PROTO == true then
                data_tree:add(pf.respond_plots__no_key_filenames__filename__length, tvb:range(offset, 4))
            end
            local filename_length = tvb:range(offset, 4):uint()
            offset = offset + 4
            data_tree:add(pf.respond_plots__no_key_filenames__filename, tvb:range(offset, filename_length))
            offset = offset + filename_length
        end
    -- end of no_key_filenames_tree
end -- 68 respond_plots


-- 69 CoinStateUpdate
local function coin_state_update (tvb, offset, data_tree)
    data_tree:add(pf.coin_state_update__height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.coin_state_update__fork_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.coin_state_update__peak_hash, tvb:range(offset, 32))
    offset = offset + 32
    local items_tree = data_tree:add("items")
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.coin_state_update__items__count, tvb:range(offset, 4))
        end
        local items_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local coin_states_tree = data_tree:add("coin_states")
            for i=1, items_count do
                offset = CoinState(tvb, offset, coin_states_tree)
            end
        -- end of coin_states_tree
    -- end of items_tree
end -- 69 coin_state_update


-- 70 RegisterForPhUpdates
local function register_for_ph_updates (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.register_for_ph_updates__puzzle_hashes__count, tvb:range(offset, 4))
    end
    local puzzle_hashes_list_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
        for i = 1, puzzle_hashes_list_count do
            puzzle_hashes_tree:add(pf.register_for_ph_updates__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
        end
    data_tree:add(pf.register_for_ph_updates__min_height, tvb:range(offset, 4))
end -- 70 register_for_ph_updates


-- 71 RespondToPhUpdates
local function respond_to_ph_updates (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_to_ph_updates__puzzle_hashes__count, tvb:range(offset, 4))
    end
    local puzzle_hashes_list_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
        for i = 1, puzzle_hashes_list_count do
            puzzle_hashes_tree:add(pf.respond_to_ph_updates__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
        end

    data_tree:add(pf.respond_to_ph_updates__min_height, tvb:range(offset, 4))
    offset = offset + 4

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_to_ph_updates__coin_states__count, tvb:range(offset, 4))
    end
    local coin_states_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    if coin_states_count == 0 then return end
    local coin_states_tree = data_tree:add("coin_states")
        for i = 1, coin_states_count do
            offset = CoinState(tvb, offset, coin_states_tree)
        end
    -- end of coin_states_tree
end -- 71 respond_to_ph_updates


-- 72 RegisterForCoinUpdates
local function register_for_coin_updates (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.register_for_coin_updates__coin_ids__count, tvb:range(offset, 4))
    end
    local coin_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local coin_ids_tree = data_tree:add("coin_ids: list")
    for i=1, coin_ids_count do
        coin_ids_tree:add(pf.register_for_coin_updates__coin_ids__coin_id, tvb:range(offset, 32))
        offset = offset + 32
    end

    data_tree:add(pf.register_for_coin_updates__min_height, tvb:range(offset, 4))
end -- 72 register_for_coin_updates


-- 73 RespondToCoinUpdates
local function respond_to_coin_updates (tvb, offset, data_tree)
    -- coin_ids
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_to_coin_updates__coin_ids__count, tvb:range(offset, 4))
    end
    local coin_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_ids_tree = data_tree:add("coin_ids: list")
        for i=1, coin_ids_count do
            coin_ids_tree:add(pf.respond_to_coin_updates__coin_ids__coin_id, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of coin_ids_tree

    -- min_height
    data_tree:add(pf.respond_to_coin_updates__min_height, tvb:range(offset, 4))
    offset = offset + 4

    -- coin_states
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_to_coin_updates__coin_states__count, tvb:range(offset, 4))
    end
    local coin_states_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_states_tree = data_tree:add("coin_states: list")
        for i=1, coin_states_count do
            offset = CoinState(tvb, offset, coin_states_tree)
        end
    -- end of coin_states_tree
end -- 73 respond_to_coin_updates


-- 74 RequestChildren
local function request_children (tvb, offset, data_tree)
    data_tree:add(pf.request_children__coin_name, tvb:range(offset, 32))
end -- 74 request_children


-- 75 RespondChildren
local function respond_children (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_children__coin_states__count, tvb:range(offset, 4))
    end
    local coin_states_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_states_tree = data_tree:add("coin_states: list")
        for i=1, coin_states_count do
            offset = CoinState(tvb, offset, coin_states_tree)
        end
    -- end of coin_states_tree
end -- 75 respond_children


-- 76 RequestSESInfo
local function request_ses_hashes (tvb, offset, data_tree)
    data_tree:add(pf.request_ses_hashes__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_ses_hashes__end_height, tvb:range(offset, 4))
end -- 76 request_ses_hashes


-- 77 RespondSESInfo
local function respond_ses_hashes (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_ses_hashes__reward_chain_hash__count, tvb:range(offset, 4))
    end
    local reward_chain_hash_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local reward_chain_hash_tree = data_tree:add("reward_chain_hash")
    for i=1, reward_chain_hash_count do
        data_tree:add(pf.respond_ses_hashes__reward_chain_hash, tvb:range(offset, 32))
        offset = offset + 32
    end

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_ses_hashes__heights__count, tvb:range(offset, 4))
    end
    local heights_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local heights_tree = data_tree:add("heights")
        for i=1, heights_count do

            if SHOW_SERIAL_PROTO == true then
                heights_tree:add(pf.respond_ses_hashes__heights__heights_list__count, tvb:range(offset, 4))
            end
            local heights_list_count = tvb:range(offset, 4):uint()
            offset = offset + 4

            for i=1, heights_list_count do
                local heights_tree_tree = heights_tree:add("height_list")
                    heights_tree_tree:add(pf.respond_ses_hashes__heights__heights_list__height)
                    offset = offset + 4
                -- end of heights_tree_tree
            end
            -- end of heights_tree_tree
        end
    -- end of heights_tree
end -- 77 respond_ses_hashes


-- 78 PlotSyncStart
local function plot_sync_start (tvb, offset, data_tree)
    offset = PlotSyncIdentifier(tvb, offset, data_tree)

    data_tree:add(pf.plot_sync_start__initial, tvb:range(offset, 1))
    offset = offset + 1

    data_tree:add(pf.plot_sync_start__last_sync_id, tvb:range(offset, 8))
    offset = offset + 8

    data_tree:add(pf.plot_sync_start__plot_file_count, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.plot_sync_start__harvesting_mode, tvb:range(offset, 1))
    local harvesting_mode_enum = chia_enum_HarvestingMode[tvb:range(offset, 1):uint()]
    offset = offset + 1

    data_tree:add(pf.plot_sync_start__harvesting_mode__enum, harvesting_mode_enum):set_generated()
end -- 78 plot_sync_start


-- 79 PlotSyncPlotList
local function plot_sync_loaded (tvb, offset, data_tree)
    -- identifier
    offset = PlotSyncIdentifier(tvb, offset, data_tree)
    
    -- data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.plot_sync_loaded__data__count, tvb:range(offset, 4))
    end
    local data_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local data_subtree = data_tree:add("data (list[Plot])")
        for i=1, data_count do
            Plot(tvb, offset, data_subtree)
        end
    -- end of data_count

    -- final
    data_tree:add(pf.plot_sync_loaded__final, tvb:range(offset, 1))
    offset = offset + 1


end -- 79 plot_sync_loaded


-- 80 PlotSyncPathtList
local function plot_sync_removed (tvb, offset, data_tree)
    offset = PlotSyncPathList(tvb, offset, data_tree)
end -- 80 plot_sync_removed


-- 81 PlotSyncPathtList
local function plot_sync_invalid (tvb, offset, data_tree)
    offset = PlotSyncPathList(tvb, offset, data_tree)
end -- 81 plot_sync_invalid


-- 82 PlotSyncPathtList
local function plot_sync_keys_missing (tvb, offset, data_tree)
    offset = PlotSyncPathList(tvb, offset, data_tree)
end -- 82 plot_sync_keys_missing


-- 83 PlotSyncPathtList
local function plot_sync_duplicates(tvb, offset, data_tree)
    offset = PlotSyncPathList(tvb, offset, data_tree)
end -- 83 plot_sync_duplicates


-- 84 PlotSyncDone
local function plot_sync_done (tvb, offset, data_tree)
    offset = PlotSyncIdentifier(tvb, offset, data_tree)

    data_tree:add(pf.plot_sync_done__duration, tvb:range(offset, 8))
    offset = offset + 8
end -- 84 plot_sync_done


-- 85 PlotSyncResponse
local function plot_sync_response (tvb, offset, data_tree)
    offset = PlotSyncIdentifier(tvb, offset, data_tree)

    data_tree:add(pf.plot_sync_response__message_type, tvb:range(offset, 2))
    offset = offset + 2

    -- PlotSyncError
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.plot_sync_response__error__option, tvb:range(offset, 1))
    end
    local error_option = tvb:range(offset, 1):uint()
    if error_option == 0 then
    elseif error_option == 1 then
        local error_tree = data_tree:add("error")
            error_tree:add(pf.plot_sync_response__error__code, tvb:range(offset, 2))
            local error_code_enum = chia_enum_ErrorCodes[tvb:range(offset, 2):int()]
            offset = offset + 2

            error_tree:add(pf.plot_sync_response__error__code__enum, error_code_enum):set_generated()

            if SHOW_SERIAL_PROTO == true then
                error_tree:add(pf.plot_sync_response__error__message__length, tvb:range(offset, 4))
            end
            local message_length = tvb:range(offset, 2):uint()
            offset = offset + 4

            error_tree:add(pf.plot_sync_response__error__message, tvb:range(offset, message_length))
            offset = offset + message_length

            if SHOW_SERIAL_PROTO == true then
                error_tree:add(pf.plot_sync_response__error__expected_identifier__option, tvb:range(offset, 1))
            end
            local expected_identifier_option = tvb:range(offset, 1):uint()
            offset = offset + 1

            local expected_identifier_tree = error_tree:add("expected_identifier")
                PlotSyncIdentifier(tvb, offset, expected_identifier_tree)
            -- end of expected_identifier_tree
        -- end of error_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 85 plot_sync_response


-- 86 RequestBlockHeaders
local function request_block_headers (tvb, offset, data_tree)
    data_tree:add(pf.request_block_headers__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_block_headers__end_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.request_block_headers__return_filter, tvb:range(offset, -1))
end -- 86 request_block_headers


-- 87 RejectBlockHeaders
local function reject_block_headers (tvb, offset, data_tree)
    data_tree:add(pf.reject_block_headers__start_height, tvb:range(offset, 4))
    offset = offset + 4
    data_tree:add(pf.reject_block_headers__end_height, tvb:range(offset, 4))
end -- 87 reject_block_headers


-- 88 RespondBlockHeaders
local function respond_block_headers (tvb, offset, data_tree)
    data_tree:add(pf.respond_block_headers__start_height, tvb:range(offset, 4))
    offset = offset + 4

    data_tree:add(pf.respond_block_headers__end_height, tvb:range(offset, 4))
    offset = offset + 4

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_block_headers__header_blocks__count, tvb:range(offset, 4))
    end
    local header_blocks_count = tvb:range(offset, 4):uint()
    offset = offset + 4

    local header_blocks_tree = data_tree:add("header_blocks (list[HeaderBlock])")
        for i=1, header_blocks_count do
            local header_block_tree = header_blocks_tree:add("HeaderBlock")
                offset = Block(tvb, offset, header_block_tree, "HeaderBlock")
            -- end of header_block_tree
        end
    -- end of header_blocks_tree
end -- 88 respond_block_headers


-- 89 RequestFeeEstimates
local function request_fee_estimates (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_fee_estimates__time_targets__count, tvb:range(offset, 4))
    end
    local time_targets_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local time_targets_tree = data_tree:add("time_targets")
        for i=1, time_targets_count do
            time_targets_tree:add(pf.request_fee_estimates__time_targets__time_target, tvb:range(offset, 8))
            offset = offset + 8
        end
    -- end of time_targets_tree
end -- 89 request_fee_estimates


-- 90 RespondFeeEstimates
local function respond_fee_estimates (tvb, offset, data_tree)
    local estimates_group_tree = data_tree:add("estimates")
        -- error
        if SHOW_SERIAL_PROTO == true then
            estimates_group_tree:add(pf.respond_fee_estimates__error__option, tvb:range(offset, 1))
        end
        local error_option = tvb:range(offset, 1):uint()
        offset = offset + 1
        if error_option == 0 then
        elseif error_option == 1 then
            if SHOW_SERIAL_PROTO == true then
                estimates_group_tree:add(pf.respond_fee_estimates__error__length, tvb:range(offset, 4))
            end
            local error_length = tvb:range(offset, 4):uint()
            offset = offset + 4
            estimates_group_tree:add(pf.respond_fee_estimates__error, tvb:range(offset, error_length))
            offset = offset + error_length
        else
            estimates_group_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
        return end

        -- estimates
        if SHOW_SERIAL_PROTO == true then
            estimates_group_tree:add(pf.respond_fee_estimates__estimates__count, tvb:range(offset, 4))
        end
        local estimates_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local fee_estimate_tree = estimates_group_tree:add("estimates")
            for i=1, estimates_count do
                -- error
                if SHOW_SERIAL_PROTO == true then
                    fee_estimate_tree:add(pf.respond_fee_estimates__estimates__error__option, tvb:range(offset, 1))
                end
                local error_option = tvb:range(offset, 1):uint()
                offset = offset + 1
                if error_option == 0 then
                elseif error_option == 1 then
                    if SHOW_SERIAL_PROTO == true then
                        fee_estimate_tree:add(pf.respond_fee_estimates__estimates__error__length, tvb:range(offset, 4))
                    end
                    local estimates_error_length = tvb:range(offset, 4):uint()
                    offset = offset + 4
                    fee_estimate_tree:add(pf.respond_fee_estimates__estimates__error, 
                        tvb:range(offset, estimates_error_length))
                    offset = offset + estimates_error_length
                else
                    fee_estimate_tree:add(pf.dissector__error, 
                        "Deserialization Error: value of type bool (0/1) expected!")
                return end

                -- time_target
                fee_estimate_tree:add(pf.respond_fee_estimates__estimates__time_target, tvb:range(offset, 8))
                offset = offset + 8

                -- estimated_fee_rate
                local estimated_fee_rate_tree = fee_estimate_tree:add("estimated_fee_rate")
                    -- mojos_per_clvm_cost
                    estimated_fee_rate_tree:add(
                        pf.respond_fee_estimates__estimates__estimated_fee_rate__mojos_per_clvm_cost, 
                        tvb:range(offset, 8))
                    offset = offset + 8
                -- end of estimated_fee_rate_tree
            end
        -- end of fee_estimate_tree
    -- end of estimates_tree
end -- 90 respond_fee_estimates


-- 91 none_response (deprecated message type)


-- 92 NewUnfinishedBlock2
local function new_unfinished_block2 (tvb, offset, data_tree)
    data_tree:add(pf.new_unfinished_block2__unfinished_reward_hash, tvb:range(offset, 32))
    offset = offset + 32

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.new_unfinished_block2__foliage_hash__option, tvb:range(offset, 1))
    end
    local foliage_hash_option = tvb:range(offset, 1):uint()
    offset = offset + 1

    if foliage_hash_option == 0 then
    elseif foliage_hash_option == 1 then
        data_tree:add(pf.new_unfinished_block2__foliage_hash, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 92 new_unfinished_block2


-- 93 RequestUnfinishedBlock2
local function request_unfinished_block2 (tvb, offset, data_tree)
    data_tree:add(pf.request_unfinished_block2__unfinished_reward_hash, tvb:range(offset, 32))
    offset = offset + 32

    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_unfinished_block2__foliage_hash__option, tvb:range(offset, 1))
    end
    local foliage_hash_option = tvb:range(offset, 1):uint()
    offset = offset + 1

    if foliage_hash_option == 0 then
    elseif foliage_hash_option == 1 then
        data_tree:add(pf.request_unfinished_block2__foliage_hash, tvb:range(offset, 32))
        offset = offset + 32
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 93 request_unfinished_block2


-- 94 RequestRemovePuzzleSubscriptions
local function request_remove_puzzle_subscriptions (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_remove_puzzle_subscriptions__puzzle_hashes__option, tvb:range(offset, 1))
    end
    local puzzle_hashes__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.request_remove_puzzle_subscriptions__puzzle_hashes__count, tvb:range(offset, 4))
        end
        local puzzle_hashes_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
            for i=1, puzzle_hashes_count do
                puzzle_hashes_tree:add(pf.request_remove_puzzle_subscriptions__puzzle_hashes__puzzle_hash, 
                    tvb:range(offset, 32))
                offset = offset + 32
            end
        -- end of puzzle_hashes_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 94 request_remove_puzzle_subscriptions


-- 95 RespondRemovePuzzleSubscriptions
local function respond_remove_puzzle_subscriptions (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_remove_puzzle_subscriptions__puzzle_hashes__option, tvb:range(offset, 1))
    end
    local puzzle_hashes__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.respond_remove_puzzle_subscriptions__puzzle_hashes__count, tvb:range(offset, 4))
        end
        local puzzle_hashes_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
            for i=1, puzzle_hashes_count do
                puzzle_hashes_tree:add(pf.respond_remove_puzzle_subscriptions__puzzle_hashes__puzzle_hash, 
                    tvb:range(offset, 32))
                offset = offset + 32
            end
        -- end of puzzle_hashes_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 95 respond_remove_puzzle_subscriptions


-- 96 RequestRemoveCoinSubscriptions
local function request_remove_coin_subscriptions (tvb, offset, data_tree)
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_remove_coin_subscriptions__puzzle_hashes__option, tvb:range(offset, 1))
    end
    local puzzle_hashes__option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.request_remove_coin_subscriptions__puzzle_hashes__count, tvb:range(offset, 4))
        end
        local puzzle_hashes_count = tvb:range(offset, 4):uint()
        offset = offset + 4
        local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
            for i=1, puzzle_hashes_count do
                puzzle_hashes_tree:add(pf.request_remove_coin_subscriptions__puzzle_hashes__puzzle_hash, 
                    tvb:range(offset, 32))
                offset = offset + 32
            end
        -- end of puzzle_hashes_tree
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 96 request_remove_coin_subscriptions


-- 97 RespondRemoveCoinSubscriptions
local function respond_remove_coin_subscriptions (tvb, offset, data_tree)
    -- coin_ids
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_remove_coin_subscriptions__coin_ids__count, tvb:range(offset, 4))
    end
    local coin_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_ids_tree = data_tree:add("coin_ids")
        for i=1, coin_ids_count do
            coin_ids_tree:add(pf.respond_remove_coin_subscriptions__coin_ids__coin_id, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of coin_ids_tree
end -- 97 respond_remove_coin_subscriptions


-- 98 RequestPuzzleState
local function request_puzzle_state (tvb, offset, data_tree)
    -- puzzle_hashes
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_puzzle_state__puzzle_hashes__count, tvb:range(offset, 4))
    end
    local puzzle_hashes_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
        for i=1, puzzle_hashes_count do
            puzzle_hashes_tree:add(pf.request_puzzle_state__puzzle_hashes__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of puzzle_hashes_tree

    -- previous_height
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_puzzle_state__previous_height__option, tvb:range(offset, 1))
    end
    local previous_height_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        data_tree:add(pf.request_puzzle_state__previous_height, tvb:range(offset, 4))
        offset = offset + 4
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- header_hash
    data_tree:add(pf.request_puzzle_state__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    -- filters
    local filters_tree = data_tree:add("filters")
        filters_tree:add(pf.request_puzzle_state__filters__include_spent, tvb:range(offset, 1))
        offset = offset + 1
        filters_tree:add(pf.request_puzzle_state__filters__include_unspent, tvb:range(offset, 1))
        offset = offset + 1
        filters_tree:add(pf.request_puzzle_state__filters__include_hinted, tvb:range(offset, 1))
        offset = offset + 1
        filters_tree:add(pf.request_puzzle_state__filters__min_amount, tvb:range(offset, 8))
        offset = offset + 8
    -- end of filters_tree

    -- subscribe_when_finished
    filters_tree:add(pf.request_puzzle_state__subscribe_when_finished, tvb:range(offset, 1))
    offset = offset + 1
end -- 98 request_puzzle_state


-- 99 RespondPuzzleState
local function respond_puzzle_state (tvb, offset, data_tree)
    -- puzzle_hashes
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_puzzle_state__puzzle_hashes__count, tvb:range(offset, 4))
    end
    local puzzle_hashes_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local puzzle_hashes_tree = data_tree:add("puzzle_hashes")
        for i=1, puzzle_hashes_count do
            puzzle_hashes_tree:add(pf.respond_puzzle_state__puzzle_hashes__puzzle_hash, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of puzzle_hashes_tree

    -- height
    data_tree:add(pf.respond_puzzle_state__height, tvb:range(offset, 4))
    offset = offset + 4

    -- header_hash
    data_tree:add(pf.respond_puzzle_state__header_hash, tvb:range(offset, 32))
    offset = offset + 32

    -- is_finished
    data_tree:add(pf.respond_puzzle_state__is_finished, tvb:range(offset, 1))
    offset = offset + 1

    -- coin_states
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_puzzle_state__coin_states__count, tvb:range(offset, 4))
    end
    local coin_states_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_states_tree = data_tree:add("coin_states")
        for i=1, coin_states_count do
            offset = CoinState(tvb, offset, coin_states_tree)
        end
    -- end of coin_states_tree
end -- 99 respond_puzzle_state


-- 100 RejectPuzzleState
local function reject_puzzle_state (tvb, offset, data_tree)
    data_tree:add(pf.reject_puzzle_state__reason, tvb:range(offset, 1))
    local reason_enum = chia_enum_RejectStateReason[tvb:range(offset, 1):uint()]
    data_tree:add(pf.reject_puzzle_state__reason__enum, reason_enum):set_generated()
end -- 100 reject_puzzle_state


-- 101 RequestCoinState
local function request_coin_state (tvb, offset, data_tree)
    -- coin_ids
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_coin_state__coin_ids__count, tvb:range(offset, 4))
    end
    local coin_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_ids_tree = data_tree:add("coin_ids")
        for i=1, coin_ids_count do
            puzzle_hashes_tree:add(pf.request_coin_state__coin_ids__coin_id, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of coin_ids_tree

    -- previous_height
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.request_coin_state__previous_height__option, tvb:range(offset, 1))
    end
    local previous_height_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if puzzle_hashes__option == 0 then
    elseif puzzle_hashes__option == 1 then
        data_tree:add(pf.request_coin_state__previous_height, tvb:range(offset, 4))
        offset = offset + 4
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    -- header_hash
    data_tree:add(pf.request_coin_state__header_hash, tvb:range(offset, 32))
    offset = offset + 32
    
    -- subscribe
    data_tree:add(pf.request_coin_state__subscribe, tvb:range(offset, 1))
    offset = offset + 1
end -- 101 request_coin_state


-- 102 RespondCoinState
local function respond_coin_state (tvb, offset, data_tree)
    -- coin_ids
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_coin_state__coin_ids__count, tvb:range(offset, 4))
    end
    local coin_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_ids_tree = data_tree:add("coin_ids")
        for i=1, coin_ids_count do
            puzzle_hashes_tree:add(pf.respond_coin_state__coin_ids__coin_id, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of coin_ids_tree

    -- coin_states
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.respond_coin_state__coin_states__count, tvb:range(offset, 4))
    end
    local coin_states_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local coin_states_tree = data_tree:add("coin_states")
        for i=1, coin_states_count do
            offset = CoinState(tvb, offset, coin_states_tree)
        end
    -- end of coin_states_tree
end -- 102 respond_coin_state


-- 103 RejectCoinState
local function reject_coin_state (tvb, offset, data_tree)
    filters_tree:add(pf.reject_coin_state__reason, tvb:range(offset, 1))
    local reason_enum = chia_enum_RejectStateReason[tvb:range(offset, 1):uint()]
    data_tree:add(pf.reject_coin_state__reason__enum, reason_enum):set_generated()
end -- 103 reject_coin_state


-- 104 MempoolItemsAdded
local function mempool_items_added (tvb, offset, data_tree)
    -- transaction_ids
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.mempool_items_added__transaction_ids__count, tvb:range(offset, 4))
    end
    local transaction_ids_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local transaction_ids_tree = data_tree:add("transaction_ids")
        for i=1, transaction_ids_count do
            transaction_ids_tree:add(pf.mempool_items_added__transaction_ids__transaction_id, tvb:range(offset, 32))
            offset = offset + 32
        end
    -- end of transaction_ids_tree
end -- 104 mempool_items_added


-- 105 MempoolItemsRemoved
local function mempool_items_removed (tvb, offset, data_tree)
    -- removed_items
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.mempool_items_removed__removed_items__count, tvb:range(offset, 4))
    end
    local removed_items_count = tvb:range(offset, 4):uint()
    offset = offset + 4
    local removed_items_tree = data_tree:add("removed_items")
        for i=1, removed_items_count do
            removed_items_tree:add(pf.mempool_items_removed__removed_items__transaction_id, tvb:range(offset, 32))
            offset = offset + 32
            removed_items_tree:add(pf.mempool_items_removed__removed_items__reason, tvb:range(offset, 1))
            local reason_enum = chia_enum_MempoolRemoveReason[tvb:range(offset, 1):uint()]
            offset = offset + 1

            removed_items_tree:add(pf.mempool_items_removed__removed_items__reason__enum, reason_enum):set_generated()
        end
    -- end of removed_items_tree
end -- 105 mempool_items_removed


-- 106 RequestCostInfo / request_cost_info


-- 107 RespondCostInfo
local function respond_cost_info (tvb, offset, data_tree)
    data_tree:add(pf.respond_cost_info__max_transaction_cost, tvb:range(offset, 8))
    offset = offset + 4
    data_tree:add(pf.respond_cost_info__max_block_cost, tvb:range(offset, 8))
    offset = offset + 4
    data_tree:add(pf.respond_cost_info__max_mempool_cost, tvb:range(offset, 8))
    offset = offset + 4
    data_tree:add(pf.respond_cost_info__mempool_cost, tvb:range(offset, 8))
    offset = offset + 4
    data_tree:add(pf.respond_cost_info__mempool_fee, tvb:range(offset, 8))
    offset = offset + 4
    data_tree:add(pf.respond_cost_info__bump_fee_per_cost, tvb:range(offset, 1))
    offset = offset + 1
end -- 107 respond_cost_info

-- 255 Error
local function error (tvb, offset, data_range, data_tree)
    -- error
    data_tree:add(pf.error__code, tvb:range(offset,  2))
    offset = offset + 2

    -- message
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.error__message__length, tvb:range(offset,  4))
    end
    local message_length = tvb:range(offset,  4):uint()
    offset = offset + 4
    data_tree:add(pf.error__message, tvb:range(offset,  message_length))
    offset = offset + message_length

    -- data
    if SHOW_SERIAL_PROTO == true then
        data_tree:add(pf.error__data__option, tvb:range(offset,  1))
    end
    local data_option = tvb:range(offset,  1):uint()
    offset = offset + 1
    if data_option == 0 then
    elseif data_option == 1 then
        if SHOW_SERIAL_PROTO == true then
            data_tree:add(pf.error__data__length, tvb:range(offset,  4))
        end
        local data_length = tvb:range(offset,  4):uint()
        offset = offset + 4
        data_tree:add(pf.error__data, tvb:range(offset, data_length))
        offset = offset + data_length
    else
        data_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end
end -- 255 error


----------------------------------------------------------------------------------
-- Dissector 
----------------------------------------------------------------------------------

function p_chia.dissector (tvb, pktinfo, root)

    if tvb:len() == 0 then return end
    pktinfo.cols.protocol = p_chia.name

    local msg_tree = root:add(p_chia, tvb:range(0, tvb:reported_length_remaining()))
    local offset = 0


    --------------------------------------------------------------------------------
    -- Deserialize the Message header 
    --------------------------------------------------------------------------------

    local msg_type = tvb:range(offset, 1):uint()
    offset = offset + 1

    local msg_type_enum = chia_enum_ProtocolMessageTypes[msg_type]

     -- handle unknown message types
    if msg_type_enum == nil then
        msg_tree:add(pf.dissector__unknown_message_type, tvb:range(offset, -1))
        pktinfo.cols.info = "unknown_chia_message_type: "..msg_type
        return
    elseif msg_type_enum == "none_response" then
        msg_tree:add(pf.dissector__deprecated_message_type, tvb:range(offset, -1))
        pktinfo.cols.info = "deprecated_chia_message_type: none_response (91)"
    return end

    -- type.enum
    msg_tree:add(pf.msg__type__enum, msg_type_enum):set_generated()
    -- show type.enum in wireshark's info column
    pktinfo.cols.info = msg_type_enum

    -- type
    msg_tree:add(pf.msg__type, msg_type)
    -- append type to wireshark's info column
    pktinfo.cols.info:append(" (" .. msg_type .. ")  ")

    -- id
    if SHOW_SERIAL_PROTO == true then
        msg_tree:add(pf.msg__id__option, tvb:range(offset, 1))
    end
    local id_option = tvb:range(offset, 1):uint()
    offset = offset + 1
    if id_option == 0 then        
    elseif id_option == 1 then
        msg_tree:add(pf.msg__id, tvb:range(offset, 2))
        offset = offset + 2
    else
        msg_tree:add(pf.dissector__error, "Deserialization Error: value of type bool (0/1) expected!")
    return end

    --------------------------------------------------------------------------------
    -- Deserialize the message data payload
    --------------------------------------------------------------------------------
    
    if SHOW_SERIAL_PROTO == true then
        msg_tree:add(pf.msg__data__length, tvb:range(offset, 4))
    end
    local data_length = tvb:range(offset, 4):uint()
    offset = offset + 4

    if data_length > 0 then
        local data_tree = msg_tree:add(pf.msg__data, tvb:range(offset, -1))

        if msg_type == 1 then
            handshake(tvb, offset, data_tree)
        elseif msg_type == 3 then
            harvester_handshake(tvb, offset, data_tree)
        elseif msg_type == 5 then
            new_proof_of_space(tvb, offset, data_tree)
        elseif msg_type == 6 then
            request_signatures(tvb, offset, data_tree)
        elseif msg_type == 7 then
            respond_signatures(tvb, offset, data_tree)
        elseif msg_type == 8 then
            new_signage_point(tvb, offset, data_tree)
        elseif msg_type == 9 then
            declare_proof_of_space(tvb, offset, data_tree)
        elseif msg_type == 10 then
            request_signed_values(tvb, offset, data_tree)
        elseif msg_type == 11 then
            signed_values(tvb, offset, data_tree)
        elseif msg_type == 12 then
            farming_info(tvb, offset, data_tree)
        elseif msg_type == 13 then
            new_peak_timelord(tvb, offset, data_tree)
        elseif msg_type == 14 then
            new_unfinished_block_timelord(tvb, offset, data_tree)
        elseif msg_type == 15 then
            new_infusion_point_vdf(tvb, offset, data_tree)
        elseif msg_type == 16 then
            new_signage_point_vdf(tvb, offset, data_tree)
        elseif msg_type == 17 then
            new_end_of_sub_slot_vdf(tvb, offset, data_tree)
        elseif msg_type == 18 then
            request_compact_proof_of_time(tvb, offset, data_tree)
        elseif msg_type == 19 then
            respond_compact_proof_of_time(tvb, offset, data_tree)
        elseif msg_type == 20 then
            new_peak(tvb, offset, data_tree)
        elseif msg_type == 21 then
            new_transaction(tvb, offset, data_tree)
        elseif msg_type == 22 then
            request_transaction(tvb, offset, data_tree)
        elseif msg_type == 23 then
            respond_transaction(tvb, offset, data_tree)
        elseif msg_type == 24 then
            request_proof_of_weight(tvb, offset, data_tree)
        elseif msg_type == 25 then
            respond_proof_of_weight (tvb, offset, data_tree)
        elseif msg_type == 26 then
            request_block(tvb, offset, data_tree)
        elseif msg_type == 27 then
            respond_block(tvb, offset, data_tree)
        elseif msg_type == 28 then
            reject_block(tvb, offset, data_tree)
        elseif msg_type == 29 then
            request_blocks(tvb, offset, data_tree)
        elseif msg_type == 30 then
            respond_blocks(tvb, offset, data_tree)
        elseif msg_type == 31 then
            reject_blocks(tvb, offset, data_tree)
        elseif msg_type == 32 then
            new_unfinished_block(tvb, offset, data_tree)
        elseif msg_type == 33 then
            request_unfinished_block(tvb, offset, data_tree)
        elseif msg_type == 34 then
            respond_unfinished_block(tvb, offset, data_tree)
        elseif msg_type == 35 then
            new_signage_point_or_end_of_sub_slot(tvb, offset, data_tree)
        elseif msg_type == 36 then
            request_signage_point_or_end_of_sub_slot(tvb, offset, data_tree)
        elseif msg_type == 37  then
            respond_signage_point(tvb, offset, data_tree)
        elseif msg_type == 38 then
            respond_end_of_sub_slot(tvb, offset, data_tree)
        elseif msg_type == 39 then
            request_mempool_transactions(tvb, offset, data_tree)
        elseif msg_type == 40 then
            request_compact_vdf(tvb, offset, data_tree)
        elseif msg_type == 41 then
            respond_compact_vdf(tvb, offset, data_tree)
        elseif msg_type == 42 then
            new_compact_vdf(tvb, offset, data_tree)
        elseif msg_type == 43 then -- 43 request_peers is without data payload
        elseif msg_type == 44 then
            respond_peers(tvb, offset, data_tree)
        elseif msg_type == 45 then
            request_puzzle_solution(tvb, offset, data_tree)
        elseif msg_type == 46 then
            respond_puzzle_solution(tvb, offset, data_tree)
        elseif msg_type == 47 then 
            reject_puzzle_solution(tvb, offset, data_tree)
        elseif msg_type == 48 then
            send_transaction(tvb, offset, data_tree)
        elseif msg_type == 49 then
            transaction_ack(tvb, offset, data_tree)
        elseif msg_type == 50 then
            new_peak_wallet(tvb, offset, data_tree)
        elseif msg_type == 51 then
            request_block_header(tvb, offset, data_tree)
        elseif msg_type == 52 then
            respond_block_header(tvb, offset, data_tree)
        elseif msg_type == 53 then
            reject_header_request(tvb, offset, data_tree)
        elseif msg_type == 54 then
            request_removals(tvb, offset, data_tree)
        elseif msg_type == 55 then
            respond_removals(tvb, offset, data_tree)
        elseif msg_type == 56 then
            reject_removals_request(tvb, offset, data_tree)
        elseif msg_type == 57 then
            request_additions(tvb, offset, data_tree)
        elseif msg_type == 58 then
            respond_additions(tvb, offset, data_tree)
        elseif msg_type == 59 then
            reject_additions_request(tvb, offset, data_tree)
        elseif msg_type == 60 then
            request_header_blocks(tvb, offset, data_tree)
        elseif msg_type == 61 then
            reject_header_blocks(tvb, offset, data_tree)
        elseif msg_type == 62 then
            respond_header_blocks(tvb, offset, data_tree)
        elseif msg_type == 63 then -- 63 request_peers_introducer is without data payload
        elseif msg_type == 64 then
            respond_peers_introducer(tvb, offset, data_tree)
        elseif msg_type == 65 then
            farm_new_block(tvb, offset, data_tree)
        elseif msg_type == 66 then
            new_signage_point_harvester(tvb, offset, data_tree)
        elseif msg_type == 67 then -- 67 request_peers_introducer is without data payload
        elseif msg_type == 68 then
            respond_plots(tvb, offset, data_tree)
        elseif msg_type == 69 then
            coin_state_update(tvb, offset, data_tree)
        elseif msg_type == 70 then
            register_for_ph_updates(tvb, offset, data_tree)
        elseif msg_type == 71 then
            respond_to_ph_updates(tvb, offset, data_tree)
        elseif msg_type == 72 then
            register_for_coin_updates(tvb, offset, data_tree)
        elseif msg_type == 73 then
            respond_to_coin_updates(tvb, offset, data_tree)
        elseif msg_type == 74 then
            request_children(tvb, offset, data_tree)
        elseif msg_type == 75 then
            respond_children(tvb, offset, data_tree)
        elseif msg_type == 76 then
            request_ses_hashes(tvb, offset, data_tree)
        elseif msg_type == 77 then
            respond_ses_hashes(tvb, offset, data_tree)
        elseif msg_type == 78 then
            plot_sync_start(tvb, offset, data_tree)
        elseif msg_type == 79 then
            plot_sync_loaded(tvb, offset, data_tree)
        elseif msg_type == 80 then
            plot_sync_removed(tvb, offset, data_tree)
        elseif msg_type == 81 then
            plot_sync_invalid(tvb, offset, data_tree)
        elseif msg_type == 82 then
            plot_sync_keys_missing(tvb, offset, data_tree)
        elseif msg_type == 83 then
            plot_sync_duplicates(tvb, offset, data_tree)
        elseif msg_type == 84 then
            plot_sync_done(tvb, offset, data_tree)
        elseif msg_type == 85 then
            plot_sync_response(tvb, offset, data_tree)
        elseif msg_type == 86 then
            request_block_headers(tvb, offset, data_tree)
        elseif msg_type == 87 then
            reject_block_headers(tvb, offset, data_tree)
        elseif msg_type == 88 then
            respond_block_headers(tvb, offset, data_tree)
        elseif msg_type == 89 then
            request_fee_estimates(tvb, offset, data_tree)
        elseif msg_type == 90 then
            respond_fee_estimates(tvb, offset, data_tree)
        elseif msg_type == 92 then
            new_unfinished_block2(tvb, offset, data_tree)
        elseif msg_type == 93 then
            request_unfinished_block2(tvb, offset, data_tree)
        elseif msg_type == 94 then
            request_remove_puzzle_subscriptions(tvb, offset, data_tree)
        elseif msg_type == 95 then
            respond_remove_puzzle_subscriptions(tvb, offset, data_tree)
        elseif msg_type == 96 then
            request_remove_coin_subscriptions(tvb, offset, data_tree)
        elseif msg_type == 97 then
            respond_remove_coin_subscriptions(tvb, offset, data_tree)
        elseif msg_type == 98 then
            request_puzzle_state(tvb, offset, data_tree)
        elseif msg_type == 99 then
            respond_puzzle_state(tvb, offset, data_tree)
        elseif msg_type == 100 then
            reject_puzzle_state(tvb, offset, data_tree)
        elseif msg_type == 101 then
            request_coin_state(tvb, offset, data_tree)
        elseif msg_type == 102 then
            respond_coin_state(tvb, offset, data_tree)
        elseif msg_type == 103 then
            reject_coin_state(tvb, offset, data_tree)
        elseif msg_type == 104 then
            mempool_items_added(tvb, offset, data_tree)
        elseif msg_type == 105 then
            mempool_items_removed(tvb, offset, data_tree)
        elseif msg_type == 106 then -- 106 request_peers_introducer is without data payload
        elseif msg_type == 107 then
            respond_cost_info(tvb, offset, data_tree)
        elseif msg_type == 255 then
            error(tvb, offset, data_tree)
        else
            msg_tree:add(pf.dissector__error, "!Unknown message type snug in: " .. msg_type)
        return end
    end
    return tvb:len()
end

--------------------------------------------------------------------------------
-- Dissector Initilization
--------------------------------------------------------------------------------

function p_chia.init ()
    local ws_dissector_table = DissectorTable.get("ws.port")
    local dissector = ws_dissector_table:get_dissector(CHIA_PORTS[1])
    for i=1, #CHIA_PORTS do
        ws_dissector_table:add(CHIA_PORTS[i], p_chia)
    end
end

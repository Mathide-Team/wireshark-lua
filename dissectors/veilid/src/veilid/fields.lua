-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/fields.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- All ProtoField / ProtoExpert definitions for the Veilid dissector.
--
-- This module only *builds* field tables; it does not create the Proto and
-- does not attach anything. veilid.lua owns the Proto and calls build().
-- Keeping construction behind a function is what makes this file safe to be
-- auto-loaded standalone by Wireshark's recursive plugin scan.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

local M = {}

-- Field name conventions:
--   veilid.asm.*  UDP AssemblyBuffer framing (fragmentation layer)
--   veilid.tcp.*  TCP "VL" length-prefix framing
--   veilid.*      the message itself (envelope or receipt)
--
-- Version-bearing values (version, crypto_kind) are exposed as strings rather
-- than enums with a value_string, so a future ENV1/VLD1 displays its real
-- FourCC instead of "Unknown (0x...)". `family` and `version_num` are broken
-- out so filters can be written without naming a version at all:
--   veilid.family == "ENV" && veilid.version_num >= 1

--- Build the field table.
-- @return table fields, table experts
function M.build()
  local f = {}

  ---------------------------------------------------------------------------
  -- UDP AssemblyBuffer framing
  ---------------------------------------------------------------------------
  f.asm_version = ProtoField.uint8("veilid.asm.version", "Assembly Version", base.DEC)
  f.asm_flags = ProtoField.uint8("veilid.asm.flags", "Assembly Flags", base.HEX)
  f.asm_seq = ProtoField.uint16("veilid.asm.seq", "Sequence", base.DEC)
  f.asm_offset = ProtoField.uint16("veilid.asm.offset", "Fragment Offset", base.DEC)
  f.asm_total_len = ProtoField.uint16("veilid.asm.total_len", "Total Message Length", base.DEC)
  f.asm_frag_len = ProtoField.uint32("veilid.asm.frag_len", "Fragment Length", base.DEC)
  f.asm_fragmented = ProtoField.bool("veilid.asm.fragmented", "Fragmented")
  f.asm_fragment = ProtoField.framenum("veilid.asm.fragment", "Message Fragment")
  f.asm_fragment_count = ProtoField.uint32("veilid.asm.fragment_count", "Fragment Count", base.DEC)
  f.asm_reassembled_in = ProtoField.framenum("veilid.asm.reassembled_in", "Reassembled In")
  f.asm_reassembled_len = ProtoField.uint32("veilid.asm.reassembled_len", "Reassembled Length", base.DEC)

  f.hole_punch = ProtoField.bool("veilid.hole_punch", "NAT Hole Punch")

  ---------------------------------------------------------------------------
  -- TCP "VL" framing
  ---------------------------------------------------------------------------
  f.tcp_magic = ProtoField.string("veilid.tcp.magic", "Frame Magic")
  f.tcp_len = ProtoField.uint16("veilid.tcp.len", "Frame Length", base.DEC)

  ---------------------------------------------------------------------------
  -- Message header (the only version-independent part: bytes 0x00..0x04)
  ---------------------------------------------------------------------------
  f.version = ProtoField.string("veilid.version", "Version")
  f.family = ProtoField.string("veilid.family", "Family")
  f.version_num = ProtoField.uint32("veilid.version_num", "Version Number", base.DEC)
  f.transport = ProtoField.string("veilid.transport", "Transport")

  ---------------------------------------------------------------------------
  -- Envelope / receipt body (layout supplied by the version registry)
  ---------------------------------------------------------------------------
  f.crypto_kind = ProtoField.string("veilid.crypto_kind", "Crypto Kind")
  f.size = ProtoField.uint16("veilid.size", "Size", base.DEC)
  f.timestamp = ProtoField.absolute_time("veilid.timestamp", "Timestamp", base.UTC)
  f.skew = ProtoField.double("veilid.skew", "Clock Skew vs Capture (s)")
  f.nonce = ProtoField.bytes("veilid.nonce", "Nonce")

  f.sender = ProtoField.bytes("veilid.sender", "Sender ID")
  f.sender_str = ProtoField.string("veilid.sender_str", "Sender")
  f.recipient = ProtoField.bytes("veilid.recipient", "Recipient ID")
  f.recipient_str = ProtoField.string("veilid.recipient_str", "Recipient")
  -- Set once per endpoint so `veilid.node == "VLD0:..."` matches traffic in
  -- both directions without an || of sender/recipient.
  f.node = ProtoField.string("veilid.node", "Node")
  f.direction = ProtoField.string("veilid.direction", "Direction")

  f.body = ProtoField.bytes("veilid.body", "Encrypted Operations")
  f.body_len = ProtoField.uint32("veilid.body_len", "Operations Length", base.DEC)
  f.signature = ProtoField.bytes("veilid.signature", "Signature")

  -- Receipts carry plaintext extra data instead of an encrypted body.
  f.extra_data = ProtoField.bytes("veilid.extra_data", "Extra Data")
  f.extra_data_len = ProtoField.uint32("veilid.extra_data_len", "Extra Data Length", base.DEC)

  -- Known family, unrecognized version: everything past the FourCC.
  f.unsupported_body = ProtoField.bytes("veilid.unsupported_body", "Unsupported Version Body")

  -- Phase 6.
  f.decrypted = ProtoField.bool("veilid.decrypted", "Operations Decrypted")
  f.operations = ProtoField.bytes("veilid.operations", "Decrypted Operations")

  return f
end

--- Build the expert-info table.
--
-- Severity choices matter here. An unrecognized *version* is a NOTE, not an
-- error: the capture is still valid Veilid and the dissector is simply older
-- than the node. Reserve ERROR for things that mean the bytes are actually
-- malformed.
-- @param prefix lowercase filter prefix, e.g. "veilid".
--   Do NOT pass proto.name here: wslua returns the *short* name, which is
--   uppercased ("VEILID"), and display filters are case-sensitive. Deriving
--   the prefix from it would register experts as VEILID.*.expert while every
--   other field lives under veilid.*, so filters would silently never match.
function M.build_experts(prefix)
  local e = {}
  local name = prefix

  e.unsupported_version = ProtoExpert.new(
    name .. ".unsupported_version.expert",
    "Unsupported Veilid version -- dissector may need updating",
    expert.group.UNDECODED, expert.severity.NOTE)

  e.unknown_crypto_kind = ProtoExpert.new(
    name .. ".unknown_crypto_kind.expert",
    "Unknown crypto kind",
    expert.group.UNDECODED, expert.severity.NOTE)

  e.size_mismatch = ProtoExpert.new(
    name .. ".size_mismatch.expert",
    "Size field does not match message length",
    expert.group.MALFORMED, expert.severity.ERROR)

  e.too_small = ProtoExpert.new(
    name .. ".too_small.expert",
    "Message shorter than the minimum for its version",
    expert.group.MALFORMED, expert.severity.ERROR)

  e.same_id = ProtoExpert.new(
    name .. ".same_id.expert",
    "Sender and recipient IDs are identical",
    expert.group.PROTOCOL, expert.severity.ERROR)

  e.stale = ProtoExpert.new(
    name .. ".stale.expert",
    "Envelope timestamp outside the 10s replay window",
    expert.group.SEQUENCE, expert.severity.WARN)

  e.fragment_conflict = ProtoExpert.new(
    name .. ".fragment_conflict.expert",
    "Overlapping fragments disagree",
    expert.group.MALFORMED, expert.severity.WARN)

  e.fragment_incomplete = ProtoExpert.new(
    name .. ".fragment_incomplete.expert",
    "Message never fully reassembled in this capture",
    expert.group.REASSEMBLE, expert.severity.NOTE)

  e.network_key_short = ProtoExpert.new(
    name .. ".network_key_short.expert",
    "Configured network key is shorter than the field it must mask",
    expert.group.PROTOCOL, expert.severity.WARN)

  return e
end

return M

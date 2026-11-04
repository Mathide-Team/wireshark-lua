-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/envelope.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Envelope family (FourCC prefix "ENV").
--
-- Registers the ENV0 layout into the version registry. Nothing outside this
-- file's registry entry knows the string "ENV0"; dispatch happens generically
-- in versions.classify(). To add ENV1, add a second register_envelope() call
-- with its own dissect function -- do not branch inside this one.
--
-- The only load-time effect is that registry insertion, which is the module's
-- entire purpose and is reached only when required through veilid.lua (the
-- guard below short-circuits Wireshark's standalone auto-load pass).

if not package.searchpath("veilid.util", package.path) then return {} end

local util = require "veilid.util"
local versions = require "veilid.versions"

local M = {}

-- veilid-core crypto/envelope/mod.rs. Only offset 0x00..0x04 is shared with
-- other versions; everything below belongs to ENV0 specifically.
local ENV0 = {
  OFF_CRYPTO_KIND = 0x04,
  OFF_SIZE = 0x08,
  OFF_TIMESTAMP = 0x0A,
  OFF_NONCE = 0x12,
  OFF_SENDER = 0x2A,
  OFF_RECIPIENT = 0x4A,
  OFF_BODY = 0x6A,
  NONCE_LEN = 24, -- ENV0_NONCE_LENGTH
  KEY_LEN = 32,   -- HASH_COORDINATE_LENGTH
  SIG_LEN = 64,   -- ENV0_SIGNATURE_LENGTH
}

-- Messages older than this are dropped by veilid-core as replays.
local REPLAY_WINDOW_SECS = 10.0

--- Read a typed key, applying the private-network mask if one is configured.
-- Returns raw bytes plus the "VLD0:<base64url>" display form.
local function typed_key(ctx, raw, crypto_fourcc)
  local masked, shortfall = raw, 0
  if ctx.network_key and #ctx.network_key > 0 then
    masked, shortfall = util.xor_prefix(raw, ctx.network_key)
  end
  return masked, crypto_fourcc .. ":" .. util.base64url(masked), shortfall
end

--- Dissect an ENV0 message.
-- @param ctx dissector context (fields, experts, prefs, helpers)
-- @param tvb  tvb covering exactly one whole message
-- @param pinfo
-- @param tree the message subtree
-- @return table summary for the info column / taps, or nil on hard failure
local function dissect_env0(ctx, tvb, pinfo, tree)
  local f, e = ctx.fields, ctx.experts
  local len = tvb:len()

  local min_size = ENV0.OFF_BODY + ENV0.SIG_LEN -- ENV0_MIN_ENVELOPE_SIZE = 170
  if len < min_size then
    tree:add_proto_expert_info(e.too_small,
      ("ENV0 envelope is %d bytes, minimum is %d"):format(len, min_size))
    return nil
  end

  local summary = { family = "ENV", version = "ENV0" }

  -- Crypto kind ------------------------------------------------------------
  local ck_range = tvb(ENV0.OFF_CRYPTO_KIND, versions.FOURCC_LEN)
  local ck_fourcc = ck_range:raw()
  local ck_display = util.printable_fourcc(ck_fourcc)
  local crypto = versions.lookup_crypto(ck_fourcc)
  local ck_item = tree:add(f.crypto_kind, ck_range, ck_display)
  if crypto then
    ck_item:append_text(" (" .. crypto.description .. ")")
  else
    ck_item:add_proto_expert_info(e.unknown_crypto_kind,
      ("Unknown crypto kind %q; key material shown raw"):format(ck_display))
  end
  summary.crypto_kind = ck_display

  -- Size -------------------------------------------------------------------
  local size = tvb(ENV0.OFF_SIZE, 2):le_uint()
  local size_item = tree:add_le(f.size, tvb(ENV0.OFF_SIZE, 2))
  if size ~= len then
    size_item:add_proto_expert_info(e.size_mismatch,
      ("size field is %d but the message is %d bytes"):format(size, len))
  end
  summary.size = size

  -- Timestamp --------------------------------------------------------------
  -- u64 LE microseconds since the UNIX epoch; NSTime wants (secs, nsecs).
  local ts_range = tvb(ENV0.OFF_TIMESTAMP, 8)
  local ts_us = util.u64_exact(ts_range:le_uint64())
  local ts_secs = ts_us // 1000000
  local ts_nsecs = (ts_us % 1000000) * 1000
  tree:add(f.timestamp, ts_range, NSTime.new(ts_secs, ts_nsecs))

  local capture_secs = pinfo.abs_ts
  local skew = (ts_us / 1e6) - capture_secs
  local skew_item = tree:add(f.skew, ts_range, skew)
  skew_item:set_generated()
  skew_item:set_text(("Clock skew vs capture: %+.6f s"):format(skew))
  if math.abs(skew) > REPLAY_WINDOW_SECS then
    skew_item:add_proto_expert_info(e.stale,
      ("envelope timestamp is %.3f s from the capture time; veilid-core drops "
        .. "envelopes older than %d s"):format(skew, REPLAY_WINDOW_SECS))
  end
  summary.skew = skew
  summary.timestamp_us = ts_us

  -- Nonce ------------------------------------------------------------------
  local nonce_range = tvb(ENV0.OFF_NONCE, ENV0.NONCE_LEN)
  local nonce_raw = nonce_range:raw()
  local nonce_shortfall = 0
  if ctx.network_key and #ctx.network_key > 0 then
    nonce_raw, nonce_shortfall = util.xor_prefix(nonce_raw, ctx.network_key)
  end
  local nonce_item = tree:add(f.nonce, nonce_range, nonce_raw)
  if ctx.network_key and #ctx.network_key > 0 then
    nonce_item:append_text(" (network key applied)")
  end
  summary.nonce = nonce_raw

  -- Sender / recipient -----------------------------------------------------
  local sender_range = tvb(ENV0.OFF_SENDER, ENV0.KEY_LEN)
  local recipient_range = tvb(ENV0.OFF_RECIPIENT, ENV0.KEY_LEN)

  local sender_raw, sender_str, sk_short = typed_key(ctx, sender_range:raw(), ck_display)
  local recipient_raw, recipient_str, rk_short = typed_key(ctx, recipient_range:raw(), ck_display)

  tree:add(f.sender, sender_range, sender_raw)
  local si = tree:add(f.sender_str, sender_range, sender_str)
  si:set_generated()
  tree:add(f.recipient, recipient_range, recipient_raw)
  local ri = tree:add(f.recipient_str, recipient_range, recipient_str)
  ri:set_generated()

  -- One `veilid.node` entry per endpoint so a single filter catches both
  -- directions of a peer's traffic.
  tree:add(f.node, sender_range, sender_str):set_generated()
  tree:add(f.node, recipient_range, recipient_str):set_generated()

  if math.max(sk_short, rk_short, nonce_shortfall) > 0 then
    tree:add_proto_expert_info(e.network_key_short,
      ("network key is %d bytes; %d bytes of masked fields left unmasked")
        :format(#ctx.network_key, math.max(sk_short, rk_short, nonce_shortfall)))
  end

  if sender_raw == recipient_raw then
    tree:add_proto_expert_info(e.same_id,
      "veilid-core rejects envelopes whose sender and recipient IDs match")
  end

  summary.sender = sender_str
  summary.recipient = recipient_str
  summary.sender_raw = sender_raw
  summary.recipient_raw = recipient_raw

  -- Body + signature -------------------------------------------------------
  -- Trust the actual buffer length rather than the size field: if they
  -- disagree we have already flagged it, and slicing by a bogus size would
  -- throw instead of showing the user what is there.
  local sig_off = len - ENV0.SIG_LEN
  local body_len = sig_off - ENV0.OFF_BODY

  if body_len > 0 then
    local body_range = tvb(ENV0.OFF_BODY, body_len)
    local body_item = tree:add(f.body, body_range)
    body_item:append_text((" (%d bytes, %s)"):format(
      body_len,
      crypto and crypto.cipher ~= "none" and "encrypted" or "not encrypted"))
    tree:add(f.body_len, body_range, body_len):set_generated()

    summary.body_range = body_range
    summary.body_len = body_len

    -- Phase 6 hands the plaintext back if a shared secret is available.
    if ctx.decrypt_body then
      ctx.decrypt_body(ctx, {
        tree = body_item,
        pinfo = pinfo,
        body = body_range,
        nonce = nonce_raw,
        crypto = crypto,
        crypto_kind = ck_display,
        sender = sender_str,
        recipient = recipient_str,
      })
    end
  else
    summary.body_len = 0
  end

  tree:add(f.signature, tvb(sig_off, ENV0.SIG_LEN))

  return summary
end

versions.register_envelope("ENV0", {
  name = "Envelope v0",
  min_size = ENV0.OFF_BODY + ENV0.SIG_LEN, -- 170
  max_size = 65507,                        -- ENV0_MAX_ENVELOPE_SIZE
  nonce_len = ENV0.NONCE_LEN,
  signature_len = ENV0.SIG_LEN,
  -- Offset of the u16 LE size field, used by heuristics for a structural
  -- cross-check. Registry-scoped because a future version may move it.
  size_field_offset = ENV0.OFF_SIZE,
  dissect = dissect_env0,
})

M.ENV0 = ENV0
M.REPLAY_WINDOW_SECS = REPLAY_WINDOW_SECS

return M

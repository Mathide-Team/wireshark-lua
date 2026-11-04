-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/receipt.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Receipt family (FourCC prefix "RCP").
--
-- Out-of-band receipts are sent directly over a transport rather than inside
-- an envelope, and are versioned on the same scheme as envelopes. Unlike an
-- envelope body, `extra_data` is NOT encrypted (veilid-core: "arbitrary extra
-- data, not encrypted by receipt itself"), so it is dissected as plain bytes.
--
-- The reference capture contains no receipts; this layout comes from
-- veilid-core crypto/receipt/mod.rs and is exercised by a synthetic fixture in
-- test/run.sh.
--
-- Registry-only load effect -- see envelope.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local util = require "veilid.util"
local versions = require "veilid.versions"

local M = {}

local RCP0 = {
  OFF_CRYPTO_KIND = 0x04,
  OFF_SIZE = 0x08,
  OFF_NONCE = 0x0A,
  OFF_SENDER = 0x22,
  OFF_EXTRA = 0x42,
  NONCE_LEN = 24, -- RCP0_NONCE_LENGTH
  KEY_LEN = 32,
  SIG_LEN = 64,   -- RCP0_SIGNATURE_LENGTH
  MAX_SIZE = 1380, -- RCP0_MAX_RECEIPT_SIZE
}

local function dissect_rcp0(ctx, tvb, pinfo, tree)
  local f, e = ctx.fields, ctx.experts
  local len = tvb:len()

  local min_size = RCP0.OFF_EXTRA + RCP0.SIG_LEN -- RCP0_MIN_RECEIPT_SIZE = 130
  if len < min_size then
    tree:add_proto_expert_info(e.too_small,
      ("RCP0 receipt is %d bytes, minimum is %d"):format(len, min_size))
    return nil
  end

  local summary = { family = "RCP", version = "RCP0" }

  local ck_range = tvb(RCP0.OFF_CRYPTO_KIND, versions.FOURCC_LEN)
  local ck_display = util.printable_fourcc(ck_range:raw())
  local crypto = versions.lookup_crypto(ck_range:raw())
  local ck_item = tree:add(f.crypto_kind, ck_range, ck_display)
  if crypto then
    ck_item:append_text(" (" .. crypto.description .. ")")
  else
    ck_item:add_proto_expert_info(e.unknown_crypto_kind,
      ("Unknown crypto kind %q; key material shown raw"):format(ck_display))
  end
  summary.crypto_kind = ck_display

  local size = tvb(RCP0.OFF_SIZE, 2):le_uint()
  local size_item = tree:add_le(f.size, tvb(RCP0.OFF_SIZE, 2))
  if size ~= len then
    size_item:add_proto_expert_info(e.size_mismatch,
      ("size field is %d but the receipt is %d bytes"):format(size, len))
  end
  summary.size = size

  local nonce_range = tvb(RCP0.OFF_NONCE, RCP0.NONCE_LEN)
  local nonce_raw = nonce_range:raw()
  if ctx.network_key and #ctx.network_key > 0 then
    nonce_raw = util.xor_prefix(nonce_raw, ctx.network_key)
  end
  tree:add(f.nonce, nonce_range, nonce_raw)

  local sender_range = tvb(RCP0.OFF_SENDER, RCP0.KEY_LEN)
  local sender_raw = sender_range:raw()
  if ctx.network_key and #ctx.network_key > 0 then
    sender_raw = util.xor_prefix(sender_raw, ctx.network_key)
  end
  local sender_str = ck_display .. ":" .. util.base64url(sender_raw)
  tree:add(f.sender, sender_range, sender_raw)
  tree:add(f.sender_str, sender_range, sender_str):set_generated()
  tree:add(f.node, sender_range, sender_str):set_generated()
  summary.sender = sender_str

  -- Receipts carry no recipient: they are addressed by the flow they arrive on.
  local sig_off = len - RCP0.SIG_LEN
  local extra_len = sig_off - RCP0.OFF_EXTRA
  if extra_len > 0 then
    tree:add(f.extra_data, tvb(RCP0.OFF_EXTRA, extra_len))
    tree:add(f.extra_data_len, tvb(RCP0.OFF_EXTRA, extra_len), extra_len):set_generated()
  end
  summary.extra_data_len = extra_len

  tree:add(f.signature, tvb(sig_off, RCP0.SIG_LEN))

  return summary
end

versions.register_receipt("RCP0", {
  name = "Receipt v0",
  min_size = RCP0.OFF_EXTRA + RCP0.SIG_LEN, -- 130
  max_size = RCP0.MAX_SIZE,
  nonce_len = RCP0.NONCE_LEN,
  signature_len = RCP0.SIG_LEN,
  size_field_offset = RCP0.OFF_SIZE,
  dissect = dissect_rcp0,
})

M.RCP0 = RCP0

return M

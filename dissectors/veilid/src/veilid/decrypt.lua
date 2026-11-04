-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/decrypt.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Envelope body decryption.
--
-- Installed as ctx.decrypt_body and called by a version's dissect function
-- once it has located the encrypted operations. Silent when no secret is
-- available -- most users have no keys, and an expert warning on every packet
-- would be noise rather than information.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local chacha = require "veilid.chacha"
local secrets = require "veilid.secrets"

local M = {}

-- frame number -> plaintext, so scrolling around in the GUI does not redo the
-- keystream. Cleared per capture from proto.init.
local cache = {}

function M.reset()
  cache = {}
end

--- Attempt to decrypt an envelope body and attach the result to the tree.
-- @param ctx dissector context
-- @param a table { tree, pinfo, body (TvbRange), nonce, crypto, crypto_kind,
--                  sender, recipient }
function M.decrypt_body(ctx, a)
  local crypto = a.crypto
  if not crypto then return end

  -- The cipher comes from the crypto-kind registry, never assumed. An
  -- unrecognized kind means we genuinely do not know how the body is
  -- protected, so leave it alone.
  if crypto.cipher == "none" then
    a.tree:append_text(" [crypto kind declares no encryption]")
    return
  end
  if crypto.cipher ~= "xchacha20" then return end

  local plaintext = cache[a.pinfo.number]
  local matched

  if not plaintext then
    local secret
    secret, matched = secrets.lookup(a.crypto_kind, a.sender, a.recipient)
    if not secret then return end

    if #secret ~= crypto.shared_secret_len then
      a.tree:append_text((" [shared secret is %d bytes, %s expects %d]")
        :format(#secret, a.crypto_kind, crypto.shared_secret_len))
      return
    end
    if #a.nonce ~= crypto.nonce_len then
      a.tree:append_text((" [nonce is %d bytes, %s expects %d]")
        :format(#a.nonce, a.crypto_kind, crypto.nonce_len))
      return
    end

    local ok, result = pcall(chacha.xchacha20_xor, secret, a.nonce, a.body:raw())
    if not ok then
      a.tree:append_text(" [decryption failed: " .. tostring(result) .. "]")
      return
    end
    plaintext = result
    if not a.pinfo.visited then cache[a.pinfo.number] = plaintext end
  end

  -- The stream cipher is unauthenticated, so a wrong key yields plausible
  -- garbage rather than an error. Say so instead of implying the plaintext is
  -- trustworthy: the envelope's Ed25519 signature is what actually
  -- authenticates this data, and we cannot verify it here.
  local sub = a.tree:add(ctx.proto, a.body)
  sub:set_text(("Decrypted Operations (%d bytes, unauthenticated)"):format(#plaintext))
  sub:set_generated()

  local ptvb = ByteArray.new(plaintext, true):tvb("Decrypted Veilid Operations")
  sub:add(ctx.fields.operations, ptvb(0, #plaintext))
  sub:add(ctx.fields.decrypted, a.body, true):set_generated()
  if matched then
    sub:append_text((" using the secret for %s"):format(matched))
  end

  -- The plaintext is a Cap'n Proto `Operation` (proto/veilid.capnp). Decoding
  -- it is out of scope here; the bytes are exposed for external tooling.
end

return M

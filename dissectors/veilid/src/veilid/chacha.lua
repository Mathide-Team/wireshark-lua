-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/chacha.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- XChaCha20 keystream, pure Lua 5.4.
--
-- Veilid encrypts the envelope operations body with
--   <XChaCha20 as KeyIvInit>::new(&shared_secret, &nonce).apply_keystream(body)
-- (crypto_system/vld0/mod.rs). That is the raw stream cipher, NOT the AEAD:
-- unauthenticated, no tag, no padding, and the block counter starts at 0.
-- So plaintext length == ciphertext length and decryption is a plain XOR
-- against the keystream.
--
-- Wireshark's Lua has no crypto bindings, but XChaCha20 is only 32-bit adds,
-- XORs and rotates -- which Lua 5.4 has natively. The X25519 + BLAKE3 half of
-- the key agreement is NOT feasible here; that happens out of band in
-- tools/veilid-secrets.py, which hands us the finished shared secret.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

local M = {}

local MASK = 0xFFFFFFFF

-- "expand 32-byte k"
local C0, C1, C2, C3 = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

local function rotl32(x, n)
  x = x & MASK
  return ((x << n) | (x >> (32 - n))) & MASK
end

--- Read `n` little-endian 32-bit words starting at 1-based byte index `off`.
local function le_words(s, off, n)
  local w = {}
  for i = 0, n - 1 do
    local a, b, c, d = s:byte(off + i * 4, off + i * 4 + 3)
    w[i + 1] = (a | (b << 8) | (c << 16) | (d << 24)) & MASK
  end
  return w
end

--- 20 rounds (10 column/diagonal double rounds) over a 16-word state, in place.
local function rounds20(s)
  for _ = 1, 10 do
    -- column rounds
    local a, b, c, d
    a, b, c, d = 1, 5, 9, 13
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 2, 6, 10, 14
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 3, 7, 11, 15
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 4, 8, 12, 16
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    -- diagonal rounds
    a, b, c, d = 1, 6, 11, 16
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 2, 7, 12, 13
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 3, 8, 9, 14
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
    a, b, c, d = 4, 5, 10, 15
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = rotl32(s[d] ~ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = rotl32(s[b] ~ s[c], 7)
  end
end

--- HChaCha20 key derivation.
-- @param key 32 raw bytes
-- @param nonce16 16 raw bytes
-- @return 32 raw bytes of subkey
function M.hchacha20(key, nonce16)
  assert(#key == 32, "hchacha20 key must be 32 bytes")
  assert(#nonce16 == 16, "hchacha20 nonce must be 16 bytes")

  local k = le_words(key, 1, 8)
  local n = le_words(nonce16, 1, 4)
  local s = {
    C0, C1, C2, C3,
    k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8],
    n[1], n[2], n[3], n[4],
  }

  rounds20(s)

  -- HChaCha20 output is words 0..3 and 12..15 WITHOUT the feed-forward add
  -- that the ChaCha20 block function performs.
  local out = {}
  local idx = 0
  for _, i in ipairs { 1, 2, 3, 4, 13, 14, 15, 16 } do
    local w = s[i]
    out[idx + 1] = string.char(w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF)
    idx = idx + 1
  end
  return table.concat(out)
end

--- Generate one 64-byte ChaCha20 keystream block into `dst` as 4-byte strings.
local function chacha20_block(k, n, counter, dst)
  local s = {
    C0, C1, C2, C3,
    k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8],
    counter & MASK, n[1], n[2], n[3],
  }
  local init = { table.unpack(s) }
  rounds20(s)
  for i = 1, 16 do
    local w = (s[i] + init[i]) & MASK
    dst[i] = string.char(w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF)
  end
end

--- XOR `data` with the ChaCha20 keystream (RFC 8439, 12-byte nonce).
--
-- Symmetric: the same call encrypts and decrypts.
-- @param key 32 raw bytes
-- @param nonce12 12 raw bytes
-- @param data raw bytes
-- @param counter0 starting block counter (RFC 8439 AEAD uses 1; the bare
--        stream cipher, and therefore Veilid, uses 0)
-- @return raw bytes of the same length
function M.chacha20_xor(key, nonce12, data, counter0)
  assert(#key == 32, "chacha20 key must be 32 bytes")
  assert(#nonce12 == 12, "chacha20 nonce must be 12 bytes")

  local k = le_words(key, 1, 8)
  local n = le_words(nonce12, 1, 3)

  local counter = counter0 or 0
  local out = {}
  local block = {}
  local len = #data
  local pos = 1

  while pos <= len do
    chacha20_block(k, n, counter, block)
    local ks = table.concat(block)
    local chunk_len = math.min(64, len - pos + 1)
    local chunk = data:sub(pos, pos + chunk_len - 1)
    local piece = {}
    for i = 1, chunk_len do
      piece[i] = string.char(chunk:byte(i) ~ ks:byte(i))
    end
    out[#out + 1] = table.concat(piece)
    pos = pos + chunk_len
    counter = counter + 1
  end

  return table.concat(out)
end

--- XOR `data` with the XChaCha20 keystream.
--
-- Symmetric: the same call encrypts and decrypts. This is the entry point the
-- dissector uses -- Veilid's envelope body is exactly this construction.
-- @param key 32 raw bytes (the Veilid shared secret)
-- @param nonce24 24 raw bytes (the envelope nonce)
-- @param data raw bytes
-- @param counter0 optional starting block counter; defaults to 0, matching
--        RustCrypto's XChaCha20 stream cipher as used by veilid-core
-- @return raw bytes of the same length
function M.xchacha20_xor(key, nonce24, data, counter0)
  assert(#key == 32, "xchacha20 key must be 32 bytes")
  assert(#nonce24 == 24, "xchacha20 nonce must be 24 bytes")

  -- Derive a subkey from the first 16 nonce bytes, then run ChaCha20 with a
  -- 12-byte nonce of four zero bytes followed by the remaining 8.
  local subkey = M.hchacha20(key, nonce24:sub(1, 16))
  local chacha_nonce = "\0\0\0\0" .. nonce24:sub(17, 24)
  return M.chacha20_xor(subkey, chacha_nonce, data, counter0 or 0)
end

return M

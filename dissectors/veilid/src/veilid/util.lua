-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/util.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Pure helpers for the Veilid dissector.
--
-- NO SIDE EFFECTS AT LOAD TIME. Wireshark recursively auto-loads every .lua
-- file under the plugin directory, so this file gets executed standalone in
-- addition to being require()d. Define and return; register nothing.

local M = {}

local B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local B64URL_REVERSE = {}
for i = 1, #B64URL_ALPHABET do
  B64URL_REVERSE[B64URL_ALPHABET:sub(i, i)] = i - 1
end
-- Accept standard-alphabet input too, so a key pasted from a non-Veilid tool
-- still decodes.
B64URL_REVERSE["+"] = 62
B64URL_REVERSE["/"] = 63

local function sixbit(v, shift)
  local idx = (v >> shift) & 0x3F
  return B64URL_ALPHABET:sub(idx + 1, idx + 1)
end

--- Encode raw bytes as unpadded base64url.
-- Matches data_encoding::BASE64URL_NOPAD, which veilid-core uses for every
-- key/nonce/signature it prints (crypto/types/byte_array_types.rs).
-- @param s string of raw bytes
-- @return string
function M.base64url(s)
  if not s then return "" end
  local out, n, i = {}, #s, 1
  while i + 2 <= n do
    local a, b, c = s:byte(i, i + 2)
    local v = (a << 16) | (b << 8) | c
    out[#out + 1] = sixbit(v, 18) .. sixbit(v, 12) .. sixbit(v, 6) .. sixbit(v, 0)
    i = i + 3
  end
  local rem = n - i + 1
  if rem == 1 then
    local v = s:byte(i) << 16
    out[#out + 1] = sixbit(v, 18) .. sixbit(v, 12)
  elseif rem == 2 then
    local a, b = s:byte(i, i + 1)
    local v = (a << 16) | (b << 8)
    out[#out + 1] = sixbit(v, 18) .. sixbit(v, 12) .. sixbit(v, 6)
  end
  return table.concat(out)
end

--- Decode unpadded (or padded) base64url into raw bytes.
-- @return string|nil bytes, string|nil error
function M.base64url_decode(str)
  if type(str) ~= "string" then return nil, "not a string" end
  str = str:gsub("[%s=]", "")
  if #str == 0 then return "" end
  if #str % 4 == 1 then return nil, "truncated base64" end

  local out, acc, bits = {}, 0, 0
  for i = 1, #str do
    local ch = str:sub(i, i)
    local v = B64URL_REVERSE[ch]
    if not v then return nil, ("invalid base64 character %q"):format(ch) end
    acc = (acc << 6) | v
    bits = bits + 6
    if bits >= 8 then
      bits = bits - 8
      out[#out + 1] = string.char((acc >> bits) & 0xFF)
    end
  end
  return table.concat(out)
end

--- Parse a Wireshark range preference ("5150", "5150,6000-6010") into a list
-- of {lo, hi} pairs. Returns an empty list for empty/malformed input.
function M.parse_ranges(str)
  local ranges = {}
  if type(str) ~= "string" then return ranges end
  for part in str:gmatch("[^,%s]+") do
    local lo, hi = part:match("^(%d+)%s*%-%s*(%d+)$")
    if lo then
      ranges[#ranges + 1] = { lo = tonumber(lo), hi = tonumber(hi) }
    else
      local single = part:match("^(%d+)$")
      if single then
        local n = tonumber(single)
        ranges[#ranges + 1] = { lo = n, hi = n }
      end
    end
  end
  return ranges
end

--- True when `port` falls in any of the parsed ranges.
function M.in_ranges(ranges, port)
  if not port then return false end
  for i = 1, #ranges do
    if port >= ranges[i].lo and port <= ranges[i].hi then return true end
  end
  return false
end

--- Convert a wslua UInt64 to an exact Lua 5.4 integer.
--
-- UInt64:tonumber() returns a *float*, which silently loses precision above
-- 2^53. Reassembling from the 32-bit halves is exact for the full range and
-- costs nothing. (Envelope timestamps are microseconds since the epoch --
-- currently ~1.8e15, safe as a double today but not worth relying on.)
function M.u64_exact(u64)
  local hi = math.tointeger(u64:higher()) or 0
  local lo = math.tointeger(u64:lower()) or 0
  return (hi << 32) | lo
end

--- Lowercase hex, no separators.
function M.hex(s)
  return (s:gsub(".", function(c) return ("%02x"):format(c:byte()) end))
end

--- Render a 4-byte FourCC for display, escaping anything unprintable so a
-- garbage match never injects control characters into the packet tree.
function M.printable_fourcc(s)
  if not s then return "" end
  return (s:gsub(".", function(c)
    local b = c:byte()
    if b >= 0x20 and b < 0x7F then return c end
    return ("\\x%02x"):format(b)
  end))
end

--- True when every byte is an ASCII alphanumeric (explicit ranges, not %w,
-- which is locale-dependent).
function M.is_ascii_alnum(s)
  if not s or #s == 0 then return false end
  return s:match("^[0-9A-Za-z]+$") ~= nil
end

--- Abbreviate a long typed key for the info column: "VLD0:AbCd…WxYz".
-- @param typed string like "VLD0:<base64url>"
-- @param keep number of base64 characters to keep at each end (default 4)
function M.short_key(typed, keep)
  keep = keep or 4
  local prefix, body = typed:match("^([^:]*:)(.*)$")
  if not prefix then prefix, body = "", typed end
  if #body <= (keep * 2) + 1 then return typed end
  return prefix .. body:sub(1, keep) .. "\u{2026}" .. body:sub(-keep)
end

--- XOR `s` against the leading bytes of `key`.
--
-- veilid-core applies a private-network key exactly this way -- `nonce[n] ^=
-- nk[n]` for n in 0..len -- so a key shorter than `s` is a configuration
-- error, not something to paper over by repeating the key. Bytes beyond
-- #key are left untouched and the shortfall is reported.
-- @return string result, number bytes_not_covered
function M.xor_prefix(s, key)
  if not key or #key == 0 then return s, #s end
  local n = math.min(#s, #key)
  local out = {}
  for i = 1, n do
    out[i] = string.char(s:byte(i) ~ key:byte(i))
  end
  if n < #s then out[n + 1] = s:sub(n + 1) end
  return table.concat(out), math.max(0, #s - #key)
end

return M

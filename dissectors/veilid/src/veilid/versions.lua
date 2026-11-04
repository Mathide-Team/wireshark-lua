-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/versions.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Version registry: the single place in this dissector allowed to name a
-- concrete Veilid version FourCC.
--
-- WHY THIS EXISTS
-- ---------------
-- "ENV0", "RCP0" and "VLD0" all carry a version digit that veilid-core will
-- increment over time (it already ships a commented-out CRYPTO_KIND_VLD1, and
-- MAX_ENVELOPE_VERSIONS is 16). A dissector that compares against the literal
-- strings silently stops working the day a node upgrades.
--
-- What the wire format actually guarantees is narrow: only bytes 0x00..0x04 of
-- a message are version-independent. veilid-core's EnvelopeHeader is documented
-- as "at least 4 bytes ... depending on the version specified, the size may
-- vary and should be cast to the appropriate struct", and
-- Envelope::try_from_signed_data reads exactly those 4 bytes before
-- dispatching. Even crypto_kind at 0x04 and size at 0x08 are ENV0 details.
--
-- So: the 4-byte FourCC selects a layout table from a registry. Everything
-- past offset 4 belongs to that table. Adding ENV1 support should mean adding
-- one registry entry, not editing a branch somewhere.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

-- Standalone-load guard (house idiom, used by every module with a dependency).
-- Wireshark recursively auto-loads every .lua file under the plugin directory,
-- and it reaches subdirectories BEFORE the top-level veilid.lua that sets up
-- package.path. In that pass our sibling modules are unreachable and there is
-- nothing useful to do, so return an inert table instead of raising. When
-- veilid.lua later require()s us for real, the path resolves and the module
-- body runs properly. Testing searchpath rather than pcall(require) means a
-- genuine syntax or runtime error in a sibling still propagates loudly.
if not package.searchpath("veilid.util", package.path) then return {} end

local util = require "veilid.util"

local M = {}

M.FOURCC_LEN = 4

-- Layout registries, keyed by full 4-character FourCC.
-- Populated by envelope.lua / receipt.lua via the register_* functions below.
M.ENVELOPE_VERSIONS = {}
M.RECEIPT_VERSIONS = {}

-- Message families, keyed by the 3-character prefix. This is what detection
-- and heuristics match on -- never a full literal.
M.FAMILIES = {
  ENV = { key = "ENV", name = "Envelope", registry = M.ENVELOPE_VERSIONS },
  RCP = { key = "RCP", name = "Receipt", registry = M.RECEIPT_VERSIONS },
}

-- Crypto kinds are an INDEPENDENT axis from message versions: an ENV0 envelope
-- names its crypto kind in a separate field, and nonce/signature lengths are
-- specified twice over (ENV0_NONCE_LENGTH vs VLD0_NONCE_LENGTH) and must
-- agree. Note "NONE" deliberately has no version digit, which is exactly why
-- this is a registry lookup and not a pattern match.
M.CRYPTO_KINDS = {}

--- Register a crypto kind. Values mirror veilid-core's per-system sizes.rs.
function M.register_crypto(fourcc, entry)
  entry.fourcc = fourcc
  M.CRYPTO_KINDS[fourcc] = entry
  return entry
end

M.register_crypto("VLD0", {
  name = "VLD0",
  description = "Ed25519 / X25519 / XChaCha20 / BLAKE3",
  public_key_len = 32,
  nonce_len = 24,
  signature_len = 64,
  shared_secret_len = 32,
  hash_len = 32,
  -- Phase 6 decryption parameters.
  dh = "x25519-blake3",
  crypt_domain = "VLD0_CRYPT",
  cipher = "xchacha20",
})

M.register_crypto("NONE", {
  name = "NONE",
  description = "no cryptography (test/debug builds)",
  public_key_len = 32,
  nonce_len = 24,
  signature_len = 64,
  shared_secret_len = 32,
  hash_len = 32,
  dh = "none",
  crypt_domain = nil,
  cipher = "none",
})

--- Register an envelope layout.
-- @param fourcc string e.g. "ENV0"
-- @param entry table { min_size, max_size, nonce_len, signature_len, dissect }
function M.register_envelope(fourcc, entry)
  entry.fourcc = fourcc
  entry.family = "ENV"
  M.ENVELOPE_VERSIONS[fourcc] = entry
  return entry
end

--- Register a receipt layout. Same shape as register_envelope.
function M.register_receipt(fourcc, entry)
  entry.fourcc = fourcc
  entry.family = "RCP"
  M.RECEIPT_VERSIONS[fourcc] = entry
  return entry
end

--- Split a 4-byte FourCC into family prefix and version.
--
-- Returns nil for anything that is not 4 printable ASCII alphanumerics, which
-- is a cheap first filter for heuristics.
-- @param s string of exactly 4 raw bytes
-- @return table|nil { fourcc, family, version_char, version_num }
function M.parse_fourcc(s)
  if type(s) ~= "string" or #s ~= M.FOURCC_LEN then return nil end
  if not util.is_ascii_alnum(s) then return nil end
  local version_char = s:sub(4, 4)
  return {
    fourcc = s,
    family = s:sub(1, 3),
    version_char = version_char,
    version_num = tonumber(version_char, 10),
  }
end

--- Classify a message by its leading FourCC.
--
-- Three distinct outcomes, and callers must treat them differently:
--   nil                        -> not a Veilid message; reject
--   { layout = nil, ... }      -> known family, UNKNOWN version. Still Veilid.
--                                 Show what we can, emit a note, never a
--                                 malformed error. A capture from a future
--                                 node must remain recognizable.
--   { layout = <table>, ... }  -> fully dissectable
-- @param s string of exactly 4 raw bytes
function M.classify(s)
  local fc = M.parse_fourcc(s)
  if not fc then return nil end
  local family = M.FAMILIES[fc.family]
  if not family then return nil end
  fc.family_name = family.name
  fc.layout = family.registry[fc.fourcc]
  return fc
end

--- Look up crypto parameters. Returns nil for unknown kinds; callers should
-- degrade to a note rather than refusing to dissect, since the crypto kind
-- only governs interpretation of key material, not envelope structure.
function M.lookup_crypto(s)
  if type(s) ~= "string" or #s ~= M.FOURCC_LEN then return nil end
  return M.CRYPTO_KINDS[s]
end

--- Smallest min_size across every registered layout, for "could this possibly
-- be a message?" length checks in heuristics.
function M.global_min_size()
  local min
  for _, registry in pairs { M.ENVELOPE_VERSIONS, M.RECEIPT_VERSIONS } do
    for _, entry in pairs(registry) do
      if entry.min_size and (not min or entry.min_size < min) then
        min = entry.min_size
      end
    end
  end
  -- Nothing registered yet: fall back to the universal header length.
  return min or M.FOURCC_LEN
end

--- Largest max_size across every registered layout.
function M.global_max_size()
  local max
  for _, registry in pairs { M.ENVELOPE_VERSIONS, M.RECEIPT_VERSIONS } do
    for _, entry in pairs(registry) do
      if entry.max_size and (not max or entry.max_size > max) then
        max = entry.max_size
      end
    end
  end
  return max or 65535
end

return M

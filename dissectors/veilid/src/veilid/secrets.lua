-- SPDX-License-Identifier: MPL-2.0
-- Importé de https://gitlab.com/SuperTeece/veilid-wireshark-dissector (veilid/secrets.lua),
-- commit a0a4eb3734df36d78969e831c2b8f4ad00e1930f du 06/08/2026. Code amont non modifié.

-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- SPDX-License-Identifier: MPL-2.0

-- Shared-secret sidecar loader.
--
-- Veilid derives the envelope body key as
--   BLAKE3(VLD0_CRYPT || X25519(our_secret, peer_public))
-- X25519 and BLAKE3 are not available in Wireshark Lua, so the derivation is
-- done out of band by tools/veilid-secrets.py and the finished secrets are
-- read from a file. Wireshark's TLS keylog preference works the same way and
-- for the same reason.
--
-- File format (whitespace-separated, '#' comments, blank lines ignored):
--   <crypto_kind> <peer_node_id_base64url> <shared_secret_hex>
-- e.g.
--   VLD0 CAAD0fhiVV0-nPlwOiqCqjzq_1b93mYQVusYJ2ZFqro 1f2e...
--
-- The secret is symmetric, so one line covers both directions with that peer.
-- The crypto kind is recorded so a future VLD1 peer cannot silently be
-- decrypted with VLD0 assumptions.
--
-- NO SIDE EFFECTS AT LOAD TIME -- see util.lua.

if not package.searchpath("veilid.util", package.path) then return {} end

local util = require "veilid.util"

local M = {}

-- "<crypto_kind>:<peer_id_b64url>" -> secret bytes
local secrets = {}
local loaded_path = nil
local load_error = nil
local count = 0

function M.reset()
  secrets = {}
  loaded_path = nil
  load_error = nil
  count = 0
end

--- Load (or reload) the secrets file. Cheap to call repeatedly with the same
-- path: it is a no-op unless the path changed.
-- @return number secrets loaded, string|nil error
function M.load(path)
  if path == loaded_path then return count, load_error end

  secrets = {}
  count = 0
  load_error = nil
  loaded_path = path

  if not path or path == "" then return 0, nil end

  local fh, err = io.open(path, "r")
  if not fh then
    load_error = tostring(err)
    return 0, load_error
  end

  local lineno = 0
  for line in fh:lines() do
    lineno = lineno + 1
    line = line:gsub("#.*$", ""):match("^%s*(.-)%s*$")
    if line ~= "" then
      local kind, peer, hex = line:match("^(%S+)%s+(%S+)%s+(%S+)$")
      if not kind then
        load_error = ("%s:%d: expected '<crypto_kind> <peer_id> <secret_hex>'")
          :format(path, lineno)
        break
      end
      if #hex % 2 ~= 0 then
        load_error = ("%s:%d: secret has an odd number of hex digits")
          :format(path, lineno)
        break
      end
      local raw = hex:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end)
      secrets[kind .. ":" .. peer] = raw
      count = count + 1
    end
  end
  fh:close()

  return count, load_error
end

--- Find the shared secret for a message between two typed node IDs.
--
-- Exactly one of them should be a peer we have a secret for; the other is the
-- local node. Returns the secret plus which ID matched, so the caller can
-- report whose key was used.
-- @param crypto_kind FourCC string, e.g. "VLD0"
-- @param ... typed node IDs ("VLD0:<base64url>")
-- @return string|nil secret, string|nil matched_id
function M.lookup(crypto_kind, ...)
  if count == 0 then return nil end
  for _, typed in ipairs { ... } do
    if typed then
      -- Strip the "KIND:" prefix; the file stores bare base64url.
      local bare = typed:match("^[^:]*:(.*)$") or typed
      local secret = secrets[crypto_kind .. ":" .. bare]
      if secret then return secret, typed end
    end
  end
  return nil
end

function M.status()
  return { path = loaded_path, count = count, error = load_error }
end

return M

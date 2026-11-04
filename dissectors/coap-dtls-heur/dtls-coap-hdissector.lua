-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/msangoi/dtls-coap-dissector (dtls-coap-hdissector.lua),
-- commit f1d033f64251179629d5b35b052aa1fff60d5c00 du 03/11/2016.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
local original_coap_dissector = Dissector.get("coap")

function h_dissector(buffer,pinfo,tree) 
  original_coap_dissector:call(buffer, pinfo, tree)
  return true
end

-- register an heuristic dissector in charge of decoding all decrypted payload as CoAP data
coaps_proto = Proto("coaps","CoAP over DTLS")
coaps_proto:register_heuristic("dtls", h_dissector)


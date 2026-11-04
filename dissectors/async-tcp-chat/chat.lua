-- SPDX-License-Identifier: BSD-3-Clause
-- Importé de https://github.com/handlemind/async-tcp-ip (chat.lua),
-- commit 8b3ea3f73e6a220e54bd69a1f3ee5e487660ce4d du 12/06/2025.
-- Licence amont : domaine public, ou BSD-3-Clause à défaut (en-tête du fichier) — voir README.md.
-- authors: Hadriel Kaplan <hadriel@128technology.com>, Stephen Cleary
-- Copyright (c) 2015-2022, Hadriel Kaplan, Stephen Cleary
-- This code is in the Public Domain, or the BSD (3 clause) license if Public Domain does not apply in your country.
-- Thanks to Hadriel Kaplan, who wrote the original FPM Lua script.

-- This is a starting point for defining a dissector for a custom TCP protocol.
-- This approach assumes that each message has a header that indicates the message length.
-- The code in this example uses a 4-byte header which is just a 4-byte big-endian message length,
--   and this length does not include the length of the header.
-- Modify the sections marked TODO to adjust these assumptions.

-- TODO: Change these constants to match your protocol.
local NAME = "chat"
local PORT = 2048
local HEADER_SIZE = 8 -- size (in bytes) of the message header; this doesn't have to be the complete header, but should be enough to determine the length.
local proto = Proto(NAME, "Sample chat protocol")
local fields = {
	-- All fields should go here, not just header fields.
	-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#:~:text=11.6.7.%C2%A0ProtoField
	length_prefix = ProtoField.uint32(NAME .. ".length_prefix", "Length Prefix", base.DEC),
	type = ProtoField.uint32(NAME .. ".type", "Type", base.DEC),
	text_length = ProtoField.uint16(NAME .. ".text_length", "Text Length", base.DEC),
	text = ProtoField.string(NAME .. ".text", "Text"),
}
proto.fields = fields
local types = {
	[0] = "CHAT",
	[1] = "BROADCAST",
	[2] = "KEEPALIVE",
	[3] = "SET_NICKNAME",
	[4] = "ACK",
	[5] = "NAK",
}

-- this holds the plain "data" Dissector, in case we can't dissect it
local data = Dissector.get("data")

-- Extract the length of the message from the header.
-- This length should include the size of the header itself.
function read_message_length_from_header(header_range)
	-- TODO: This sample protocol assumes the header is just a 4-byte big-endian uint length field.
	local length_prefix_range = header_range:range(0, 4)
	return length_prefix_range:uint() + 4
end

-- Whatever you return from this method is passed as the first argument into dissect_message_fields
function dissect_header_fields(header_range, packet_info, tree)
	-- TODO: Add other header fields here; the example protocol is just a 4-byte big endian "length_prefix"
	-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
	local length_prefix_range = header_range:range(0, 4)
	tree:add_packet_field(fields.length_prefix, length_prefix_range, ENC_BIG_ENDIAN)

	local type_range = header_range:range(4, 4)
	tree:add_packet_field(fields.type, type_range, ENC_BIG_ENDIAN)

	return type_range:uint()
	-- TODO: Consider returning some values (e.g., a "type" value parsed from the header) so dissect_message_fields can use it.
end

function dissect_message_fields(header_result, body_range, packet_info, tree)
	-- TODO: dissect the message fields
	-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
	local type = types[header_result]
	if type == nil then
		type = "Unknown (" .. header_result .. ")"
	end
	packet_info.cols.info:append(": " .. type)

	local offset = 0
	if header_result == 0 then
		tree:add_packet_field(fields.text_length, body_range:range(offset, 2), ENC_BIG_ENDIAN)
		local text_length = body_range:range(offset, 2):uint()
		offset = offset + 2

		tree:add_packet_field(fields.text, body_range(offset, text_length), ENC_UTF_8 + ENC_STRING)
		offset = offset + text_length
	else
		-- Fallback behavior: if we find an unknown message type, pass it to the `data` dissector.
		-- append the INFO column
		data:call(body_range:tvb(offset), packet_info, tree)
	end
end

--
-- From here on out, there shouldn't have to be any changes for your protocol.
--

----------------------------------------
-- The function to check the length field.
--
-- This returns two things:
--   1. the length of the message, including the header.
--      If 0, then some parsing error happened.
--      If negative, then the absolute value of this is the number of bytes necessary to get a complete message.
--      If -DESEGMENT_ONE_MORE_SEGMENT, then an unknown number of bytes are still necessary to get a complete message.
--   2. the TvbRange object for the header. This is nil if length <= 0.
checkLength = function(tvbuf, offset)
	-- This example protocol implementation never returns 0 from this function,
	-- but if you get a packet that doesn't look like it's from your protocol,
	-- then it would be appropriate to return 0 from this function.

	-- "bytes_remaining" is the number of bytes remaining in the Tvb buffer which we
	-- have available to dissect in this run
	local bytes_remaining = tvbuf:len() - offset

	if bytes_remaining < HEADER_SIZE then
		-- we need more bytes, so tell the main dissector function that we
		-- didn't dissect anything, and we need an unknown number of more
		-- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
		-- return as a negative number
		return -DESEGMENT_ONE_MORE_SEGMENT
	end

	-- if we got here, then we know we have enough bytes in the Tvb buffer
	-- to at least figure out the full length of this messsage

	local header_range = tvbuf:range(offset, HEADER_SIZE)
	local message_length = read_message_length_from_header(header_range)

	if bytes_remaining < message_length then
		-- we need more bytes to get the whole message
		return -(message_length - bytes_remaining)
	end

	return message_length, header_range
end

----------------------------------------
-- The following is a local function used for dissecting our messages
-- inside the TCP segment using the desegment_offset/desegment_len method.
-- It's a separate function because we run over TCP and thus might need to
-- parse multiple messages in a single segment/packet. So we invoke this
-- function only dissects one message and we invoke it in a while loop
-- from the Proto's main disector function.
--
-- This function is passed in the original Tvb, Pinfo, and TreeItem from the Proto's
-- dissector function, as well as the offset in the Tvb that this function should
-- start dissecting from.
--
-- This function returns the length of the message it dissected as a
-- positive number, or as a negative number the number of additional bytes it
-- needs if the Tvb doesn't have them all, or a 0 for error.
--
function dissect(tvbuf, packet_info, root, offset)
	local message_length, header_range = checkLength(tvbuf, offset)

	if message_length <= 0 then
		return message_length
	end

	-- if we got here, then we have a whole message in the Tvb buffer
	-- so let's finish dissecting it...

	-- set the protocol column to show our protocol name
	packet_info.cols.protocol:set(NAME)

	-- set the INFO column too, but only if we haven't already set it before
	-- for this frame/packet, because this function can be called multiple
	-- times per packet/Tvb
	if string.find(tostring(packet_info.cols.info), "^" .. NAME) == nil then
		packet_info.cols.info:set(NAME)
	end

	-- We start by adding our protocol to the dissection display tree.
	local tree = root:add(proto, tvbuf:range(offset, message_length))

	-- dissect the header fields
	local header_result = dissect_header_fields(header_range, packet_info, tree)

	-- dissect the message fields
	dissect_message_fields(header_result, tvbuf(offset + HEADER_SIZE, message_length - HEADER_SIZE), packet_info, tree)

	return message_length
end

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- The 'tvbuf' is a Tvb object, 'packet_info' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function proto.dissector(tvbuf, packet_info, root)
	-- get the length of the packet buffer (Tvb).
	local packet_length = tvbuf:len()

	-- check if capture was only capturing partial packet size
	if packet_length ~= tvbuf:reported_length_remaining() then
		-- captured packets are being sliced/cut-off, so don't try to dissect/reassemble
		return 0
	end

	local bytes_consumed = 0

	-- we do this in a while loop, because there could be multiple messages
	-- inside a single TCP segment, and thus in the same tvbuf - but our
	-- dissector() will only be called once per TCP segment, so we
	-- need to do this loop to dissect each message in it
	while bytes_consumed < packet_length do
		-- We're going to call our "dissect()" function, which is defined
		-- later in this script file. The dissect() function returns the
		-- length of the message it dissected as a positive number, or if
		-- it's a negative number then it's the number of additional bytes it
		-- needs if the Tvb doesn't have them all. If it returns a 0, it's a
		-- dissection error.
		local result = dissect(tvbuf, packet_info, root, bytes_consumed)

		if result > 0 then
			-- we successfully processed a message, of 'result' length
			bytes_consumed = bytes_consumed + result
			-- go again on another while loop
		elseif result == 0 then
			-- If the result is 0, then it means we hit an error of some kind,
			-- so return 0. Returning 0 tells Wireshark this packet is not for
			-- us, and it will try heuristic dissectors or the plain "data"
			-- one, which is what should happen in this case.
			return 0
		else
			-- we need more bytes, so set the desegment_offset to what we
			-- already consumed, and the desegment_len to how many more
			-- are needed
			packet_info.desegment_offset = bytes_consumed

			-- the negative result so it's a positive number
			packet_info.desegment_len = -result

			-- even though we need more bytes, this packet is for us, so we
			-- tell wireshark all of its bytes are for us by returning the
			-- number of Tvb bytes we "successfully processed", namely the
			-- length of the Tvb
			return packet_length
		end
	end

	-- In a TCP dissector, you can either return nothing, or return the number of
	-- bytes of the tvbuf that belong to this protocol, which is what we do here.
	-- Do NOT return the number 0, or else Wireshark will interpret that to mean
	-- this packet did not belong to your protocol, and will try to dissect it
	-- with other protocol dissectors (such as heuristic ones)
	return bytes_consumed
end

DissectorTable.get("tcp.port"):add(PORT, proto)

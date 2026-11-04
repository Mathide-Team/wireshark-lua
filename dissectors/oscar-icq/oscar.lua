-- SPDX-License-Identifier: GPL-3.0-or-later
-- Importé de https://github.com/luc-lynx/icq-dissector (oscar.lua),
-- commit 9a1ecd72a0e510957ce41a89521e3faf23f3da09 du 12/01/2016.
-- Licence amont : GPL-3.0-or-later (en-tête du fichier ; LICENSE amont : GPL v2) — voir README.md.
--    Lua dissector for OSCAR protocol (http://iserverd.khstu.ru/oscar/)
--    Copyright (C) 2016  Evgeny Sidorov <luc-lynx@yandex.com>
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <http://www.gnu.org/licenses/>.

local icq_msg_proto = Proto("icqumsg", "ICQ User to Server Text Messages")

local icq_msg_channel = ProtoField.uint16("icqumsg.chn", "Message Channel", base.HEX)
local icq_msg_uin_len = ProtoField.uint8("icqumsg.uin_len", "Screenname string length", base.DEC)
local icq_msg_uin = ProtoField.string("icqumsg.uin", "Sender UIN")
local icq_msg_text = ProtoField.string("icqumsg.text", "Message Text")

icq_msg_proto.fields = { icq_msg_channel, icq_msg_uin_len, icq_msg_uin, icq_msg_text }

local icq_msg_channels = {
	[0x0001] = "Plain text",
	[0x0002] = "RTF Message",
	[0x0004] = "Typed old-style messages"
}

local unicode_russian = {
	[0x0401] = "Ё",
	[0x0410] = "A",
	[0x0411] = "Б",
	[0x0412] = "В",
	[0x0413] = "Г",
	[0x0414] = "Д",
	[0x0415] = "Е",
	[0x0416] = "Ж",
	[0x0417] = "З",
	[0x0418] = "И",
	[0x0419] = "Й",
	[0x041a] = "К",
	[0x041b] = "Л",
	[0x041c] = "М",
	[0x041d] = "Н",
	[0x041e] = "О",
	[0x041f] = "П",
	[0x0420] = "Р",
	[0x0421] = "С",
	[0x0422] = "Т",
	[0x0423] = "У",
	[0x0424] = "Ф",
	[0x0425] = "Х",
	[0x0426] = "Ц",
	[0x0427] = "Ч",
	[0x0428] = "Ш",
	[0x0429] = "Щ",
	[0x042a] = "Ъ",
	[0x042b] = "Ы",
	[0x042c] = "Ь",
	[0x042d] = "Э",
	[0x042e] = "Ю",
	[0x042f] = "Я",
	[0x0430] = "а",
	[0x0431] = "б",
	[0x0432] = "в",
	[0x0433] = "г",
	[0x0434] = "д",
	[0x0435] = "е",
	[0x0436] = "ж",
	[0x0437] = "з",
	[0x0438] = "и",
	[0x0439] = "й",
	[0x043a] = "к",
	[0x043b] = "л",
	[0x043c] = "м",
	[0x043d] = "н",
	[0x043e] = "о",
	[0x043f] = "п",
	[0x0440] = "р",
	[0x0441] = "с",
	[0x0442] = "т",
	[0x0443] = "у",
	[0x0444] = "ф",
	[0x0445] = "х",
	[0x0446] = "ц",
	[0x0447] = "ч",
	[0x0448] = "ш",
	[0x0449] = "щ",
	[0x044a] = "ъ",
	[0x044b] = "ы",
	[0x044c] = "ь",
	[0x044d] = "э",
	[0x044e] = "ю",
	[0x044f] = "я"	
}

local cp1251_russian = {
	[0xb8] = "ё",
	[0xc0] = "А",
	[0xc1] = "Б",
	[0xc2] = "В",
	[0xc3] = "Г",
	[0xc4] = "Д",
	[0xc5] = "Е",
	[0xc6] = "Ж",
	[0xc7] = "З",
	[0xc8] = "И",
	[0xc9] = "Й",
	[0xca] = "К",
	[0xcb] = "Л",
	[0xcc] = "М",
	[0xcd] = "Н",
	[0xce] = "О",
	[0xcf] = "П",
	[0xd0] = "Р",
	[0xd1] = "С",
	[0xd2] = "Т",
	[0xd3] = "У",
	[0xd4] = "Ф",
	[0xd5] = "Х",
	[0xd6] = "Ц",
	[0xd7] = "Ч",
	[0xd8] = "Ш",
	[0xd9] = "Щ",
	[0xda] = "Ъ",
	[0xdb] = "Ы",
	[0xdc] = "Ь",
	[0xdd] = "Э",
	[0xde] = "Ю",
	[0xdf] = "Я",
	[0xe0] = "а",
	[0xe1] = "б",
	[0xe2] = "в",
	[0xe3] = "г",
	[0xe4] = "д",
	[0xe5] = "е",
	[0xe6] = "ж",
	[0xe7] = "з",
	[0xe8] = "и",
	[0xe9] = "й",
	[0xea] = "к",
	[0xeb] = "л",
	[0xec] = "м",
	[0xed] = "н",
	[0xee] = "о",
	[0xef] = "п",
	[0xf0] = "р",
	[0xf1] = "с",
	[0xf2] = "т",
	[0xf3] = "у",
	[0xf4] = "ф",
	[0xf5] = "х",
	[0xf6] = "ц",
	[0xf7] = "ч",
	[0xf8] = "ш",
	[0xf9] = "щ",
	[0xfa] = "ъ",
	[0xfb] = "ы",
	[0xfc] = "ь",
	[0xfd] = "э",
	[0xfe] = "ю",
	[0xff] = "я"
}

function get_string(buf)
	if buf:len() == 0 then 
		return "" 
	end
	
	result = ""
	for t = 0, buf:len() - 1, 1 do
		local chr = buf(t, 1):uint()
		if cp1251_russian[chr] ~= nil then
			result = result .. cp1251_russian[chr]
		else
			result = result .. buf(t, 1):string()
		end
	end
	return result
end

function get_unicode_string(buf) 
	if buf:len() == 0 then
		return ""
	end
	
	result = ""
	local ln = 0
	if buf:len() % 2 == 1 then
		ln = ((buf:len() - 1) / 2) - 1
	else
		ln = (buf:len() / 2) - 1
	end
	
	for t = 0, ln, 1 do
		local fst = buf(2*t,1):uint()
		if fst == 0x04 then
			if unicode_russian[buf(2*t, 2):uint()] ~= nil then
				result = result .. unicode_russian[buf(2*t, 2):uint()]
			else
				result = result .. "-" -- if not in russian code set
			end
		elseif fst == 0x00 then
			result = result .. buf(2*t + 1, 1):string()
		else
			result = result .. "*" -- if "unknown" code set
		end
	end
	return result
end

function icq_msg_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	
	local subtree = tree:add(icq_msg_proto, "ICQ User to Server Message")
	
	local chn = buf(8,2):uint()
	local chn_item = subtree:add(icq_msg_channel, buf(8,2))
	
	if icq_msg_channels[chn] ~= nil then
		chn_item:append_text(" - " .. icq_msg_channels[chn])
	end
	
	local uin_len = buf(10,1):uint()
	subtree:add(icq_msg_uin_len, buf(10,1))
	subtree:add(icq_msg_uin, buf(11, uin_len))
	
	local offset = 11 + uin_len
	
	if chn == 0x0001 then
		offset = offset + 2 -- TLV.Type(0x02) - message data
		offset = offset + 2 -- TLV.Length
		offset = offset + 1 -- fragment identifier (array of required capabilities)
		offset = offset + 1 -- fragment version
		offset = offset + 2 + buf(offset, 2):uint() -- Length of rest data AND 	byte array of required capabilities (1 - text)
		offset = offset + 1 -- fragment identifier (text message)
		offset = offset + 1 -- fragment version
		local text_len = buf(offset, 2):uint() - 4 -- Length of rest data - Message charset number - Message language number
		offset = offset + 2 -- Length of rest data
		offset = offset + 4 -- Message charset number AND Message language number
		subtree:add(icq_msg_text, buf(offset, text_len)):set_text("Txt: " .. get_string(buf(offset, text_len)))
	end
end

-- ICQ Server to User Text Messages Dissector

local icq_smsg_proto = Proto("icqsmsg", "ICQ Server to Text Messages")

local icq_smsg_channel = ProtoField.uint16("icqsmsg.chn", "Message Channel", base.HEX)
local icq_smsg_uin_len = ProtoField.uint8("icqsmsg.uin_len", "Screenname string length", base.DEC)
local icq_smsg_uin = ProtoField.string("icqsmsg.uin", "Sender UIN")
local icq_smsg_tlv_num = ProtoField.uint16("icqsmsg.tlv_num", "Number of TLVs")
local icq_smsg_nick = ProtoField.string("icqsmsg.nick", "Sender nick")
local icq_smsg_tlv_len = ProtoField.uint16("icqsmsg.tlv_len", "Length of TLV with message", base.HEX) 
local icq_smsg_req_cap_len = ProtoField.uint16("icqsmsg.req_cap_len", "\"byte array of required capabilities\" Length", base.HEX)
local icq_smsg_req_cap_arr = ProtoField.bytes("icqsmsg.req_cap_arr", "Byte array of required capabilities")
local icq_smsg_msg_tlv_len = ProtoField.uint16("icqsmsg.msg_tlv_len", "Message TLV Length", base.HEX)
local icq_smsg_msg_charset = ProtoField.uint16("icqsmsg.charset", "Message Text Charset", base.HEX)
local icq_smsg_msg_charset_subset = ProtoField.uint16("icqsmsg.charset_sub", "Message Text Charset Subset", base.HEX)
local icq_smsg_text = ProtoField.string("icqsmsg.text", "Message Text")

icq_smsg_proto.fields = { 
	icq_smsg_channel, 
	icq_smsg_uin_len, 
	icq_smsg_uin, 
	icq_smsg_nick, 
	icq_smsg_tlv_num, 
	icq_smsg_tlv_len, 
	icq_smsg_req_cap_len,
	icq_smsg_req_cap_arr,
	icq_smsg_msg_tlv_len,
	icq_smsg_msg_charset,
	icq_smsg_msg_charset_subset,
	icq_smsg_text 
}

function icq_smsg_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	local subtree = tree:add(icq_smsg_proto, "ICQ Server to User Message")
	
	local chn = buf(8,2):uint()
	subtree:add(icq_smsg_channel, buf(8,2))
	local uin_len = buf(10, 1):uint()
	subtree:add(icq_smsg_uin_len, buf(10,1))
	subtree:add(icq_smsg_uin, buf(11, uin_len))
	local offset = 11 + uin_len
	offset = offset + 2 -- warning level
	local tlv_num = buf(offset, 2):uint()
	subtree:add(icq_smsg_tlv_num, buf(offset, 2))
	offset = offset + 2 -- number of tlv	
	
	if chn == 0x0001 then		
		for t = 0, tlv_num, 1 do
			local tlv_type = buf(offset, 2):uint()
			offset = offset + 2
			local tlv_len = buf(offset, 2):uint()
			offset = offset + 2
			local old_offset = offset
			if tlv_type == 0x0018 then
				subtree:add(icq_smsg_nick, buf(offset, tlv_len)):append_text(" - Decoded nickname: " .. get_string(buf(offset, tlv_len)))
			end
			if tlv_type == 0x0002 then
				local loc_offset = offset
				loc_offset = loc_offset + 2 -- fragment id and fragment version
				local fr_len = buf(loc_offset, 2):uint()
				subtree:add(icq_smsg_req_cap_len, buf(loc_offset, 2))
				loc_offset = loc_offset + 2 -- length
				subtree:add(icq_smsg_req_cap_arr, buf(offset, fr_len))
				loc_offset = loc_offset + fr_len
				
				loc_offset = loc_offset + 1 -- fragment id (msg text)
				loc_offset = loc_offset + 1 -- fragment version
				local text_len = buf(loc_offset, 2):uint() - 4 -- - Msg Charset and Msg Charset subset
				subtree:add(icq_smsg_msg_tlv_len, buf(loc_offset, 2))
				loc_offset = loc_offset + 2 -- TLV.Length
				subtree:add(icq_smsg_msg_charset, buf(loc_offset, 2))
				local chset = buf(loc_offset, 2):uint()
				loc_offset = loc_offset + 2 -- Msg Charset
				subtree:add(icq_smsg_msg_charset_subset, buf(loc_offset, 2))
				local chset_sub = buf(loc_offset, 2):uint()
				loc_offset = loc_offset + 2 -- Msg Charset Subset
				if (chset == 0x0000) then
					subtree:add(icq_smsg_text, buf(loc_offset, text_len)):set_text("Txt: " .. get_string(buf(loc_offset, text_len)))
				elseif (chset == 0x0002) then
					subtree:add(icq_smsg_text, buf(loc_offset, text_len)):set_text("Txt: " .. get_unicode_string(buf(loc_offset, text_len)))
				else
					subtree:add(icq_smsg_text, buf(loc_offset, text_len))
				end
				
				loc_offset = loc_offset + text_len			
			end
			offset = offset + tlv_len
		end
	end
end


-- User Info Block TLV Dissector

local uibtlv_proto = Proto("uibtlv", "User Info Block TLV")
local uibtlv_type = ProtoField.uint16("uibtlv.type", "UIB TLV Type", base.HEX)
local uibtlv_len = ProtoField.uint16("uibtlv.len", "UIB TLV Length", base.HEX)
local uibtlv_data = ProtoField.bytes("uibtlv.data", "UIB TLV Data")

uibtlv_proto.fields = { uibtlv_type, uibtlv_len, uibtlv_data }

local tlv_types = {
	[0x0001] = "User class (nick flags)",
	[0x0002] = "Create time",
	[0x0003] = "Sigon time (unix time_t format)",
	[0x0004] = "Idle time (in seconds)",
	[0x0005] = "Account creation time (member since)",
	[0x0006] = "User status (ICQ Only)",
	[0x000a] = "External IP Address (ICQ Only)",
	[0x000c] = "User DC info (ICQ Only)",
	[0x000d] = "Client capabilities",
	[0x000f] = "Online time (in seconds)"	
}

function uibtlv_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	
	local subtree = tree:add(uibtlv_proto, "TLV Chain element")
	local type_item = subtree:add(uibtlv_type, buf(0,2))
	if tlv_types[buf(0,2):uint()] ~= nil then
		type_item:append_text(" - " .. tlv_types[buf(0,2):uint()])
	end	
	local ln = buf(2,2):uint()
	subtree:add(uibtlv_len, buf(2,2))
	subtree:add(uibtlv_data, buf(4, ln))
end

-- User Info Block dissector
local uib_proto = Proto("uib", "User Info Block")
local uib_uin_len = ProtoField.uint8("uib.uin_len", "UIN length", base.DEC)
local uib_uin = ProtoField.string("uib.uin", "UIN")
local uib_wl = ProtoField.uint16("uib.wl", "Warning level", base.HEX)
local uib_tlv_num = ProtoField.uint16("uib.tlv_num", "Number of TLV's", base.DEC)
local uib_tlv_data = ProtoField.bytes("uib.tlv_data", "User Info Blocks TLVs")

uib_proto.fields = { uib_uin_len, uib_uin, uib_wl, uib_tlv_num, uib_tlv_data }  

function uib_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	local subtree = tree:add(uib_proto, "User Info Block")
	local ln = buf(0,1):uint()
	subtree:add(uib_uin_len, buf(0,1))
	subtree:add(uib_uin, buf(1, ln))	
	subtree:add(uib_wl, buf(ln+1,2))
	subtree:add(uib_tlv_num, buf(ln+3, 2))
	subtree:add(uib_tlv_data, buf(ln+5, buf:len() - ln - 5))
	
	pinfo.cols.info = tostring(pinfo.cols.info) .. " - UIN: " .. (buf(1, ln):string()) .. "; "
	
	local count = buf(ln + 3, 2):uint() - 1
	local total_len = 0
	local buf_start = ln + 5
	for t = 0, count, 1 do
		total_len = buf(buf_start + 2, 2):uint() + 2 + 2 -- word + word + len
		local uibtlv_diss = Dissector.get("uibtlv")
		uibtlv_diss:call(buf(buf_start, total_len):tvb(), pinfo, subtree)
		buf_start = buf_start + total_len
	end
end

-- SNAC Protocol dissector
local snac_proto = Proto("snac", "SNAC protocol")
local snac_service_id = ProtoField.uint16("snac.service_id", "Family (service) id number", base.HEX)
local snac_subtype_id = ProtoField.uint16("snac.subtype_id", "Family subtype id number", base.HEX)
local snac_flags = ProtoField.uint16("snac.flags", "SNAC flags", base.HEX)
local snac_request_id = ProtoField.uint32("snac.request_id", "SNAC request id", base.HEX)
local snac_data = ProtoField.bytes("snac.data", "SNAC data")

snac_proto.fields = { snac_service_id, snac_subtype_id, snac_flags, snac_request_id, snac_data }

local general_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Client is now online and ready for normal function",
	[0x0003] = "Server supported snac families list",
	[0x0004] = "Request for new service",
	[0x0005] = "Redirect (for 0x0004 subtype)",
	[0x0006] = "Request rate limits information",
	[0x0007] = "Rate limits information response",
	[0x0008] = "Add rate limits group",
	[0x0009] = "Delete rate limits group",
	[0x000a] = "Rate information changed / rate limit warning",
	[0x000b] = "Server pause command",
	[0x000c] = "Client pause ack",
	[0x000d] = "Server resume command",
	[0x000e] = "Request own online information",
	[0x000f] = "Requested online info response",
	[0x0010] = "Evil notification",
	[0x0011] = "Set idle time",
	[0x0012] = "Migration notice and info",
	[0x0013] = "Message of the day (MOTD)",
	[0x0014] = "Set privacy flags",
	[0x0015] = "Well known urls",
	[0x0016] = "No operation (NOP)",
	[0x0017] = "Request server services versions",
	[0x0018] = "Server services versions",
	[0x001e] = "Set status (set location info)",
	[0x001f] = "Client verification request",
	[0x0020] = "Client verification reply",
	[0x0021] = "Client's extended status from server"
}

local location_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Request limitations/params",
	[0x0003] = "Limitations/params response",
	[0x0004] = "Set user information",
	[0x0005] = "Request user info",
	[0x0006] = "User information response",
	[0x0007] = "Watcher sub request",
	[0x0008] = "Watcher notification",
	[0x0009] = "Update directory info request",
	[0x000A] = "Update directory info reply",
	[0x000B] = "Query for SNAC(02,0C)",
	[0x000C] = "Reply to SNAC(02,0B)",
	[0x000F] = "Update user directory interests",
	[0x0010] = "Update user directory interests reply",
	[0x0015] = "User info query"
}

local management_srv = {
	[0x0001] = "Client/server error",
	[0x0002] = "Request limitations/params",
	[0x0003] = "Limitations/params responce",
	[0x0004] = "Add buddy(s) to contact list",
	[0x0005] = "Remove buddy(ies) from contact",
	[0x0006] = "Query for list of watchers",
	[0x0007] = "Requested watchers list",
	[0x0008] = "Watcher sub request",
	[0x0009] = "Watcher notification",
	[0x000a] = "Notification rejected",
	[0x000b] = "User online notification",
	[0x000c] = "User offline notification"
}

local messages_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Set ICBM parameters",
	[0x0003] = "Reset ICBM parameters",
	[0x0004] = "Request parameters info",
	[0x0005] = "Requested parameters info response",
	[0x0006] = "Send message thru server",
	[0x0007] = "Message for client from server",
	[0x0008] = "Evil request",
	[0x0009] = "Server evil ack",
	[0x000a] = "Missed call (msg not delivered)",
	[0x000b] = "Client/server message error or data",
	[0x000c] = "Server message ack",
	[0x0014] = "Mini typing notifications (MTN)"
}

local invitation_srv = {
	[0x0001] = "Client server error",
	[0x0002] = "Invite a friend to join AIM",
	[0x0003] = " Invitation server ack"
}

local administrative_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Request account info",
	[0x0003] = "Requested account info",
	[0x0004] = "Change account info (screenname, password) request",
	[0x0005] = "Change account info ack",
	[0x0006] = "Account confirm request",
	[0x0007] = "Account confirm ack",
	[0x0008] = "Account delete request",
	[0x0009] = "Account delete ack"
}

local popup_srv = {
	[0x0001] = "Client server error",
	[0x0002] = "Display popup message server command"
}

local pricacy_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Request service parameters",
	[0x0003] = "Requested service parameters",
	[0x0004] = "Set group permissions mask",
	[0x0005] = "Add to visible list",
	[0x0006] = "Delete from visible list",
	[0x0007] = "Add to invisible list",
	[0x0008] = "Delete from invisible list",
	[0x0009] = "Service error",
	[0x000A] = "Add to visible list (?)",
	[0x000B] = "Delete from visible list (?)"
}

local lookup_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Search user by email",
	[0x0003] = "Search response"
}

local stats_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Set minimum report interval",
	[0x0003] = "Usage stats report",
	[0x0004] = "Usage stats report ack"
}

local chat_navigation_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Request limits",
	[0x0003] = "Request exchange information",
	[0x0004] = "Request room information",
	[0x0005] = "Request extended room information",
	[0x0006] = "Request member list",
	[0x0007] = "Search for room",
	[0x0008] = "Create room",
	[0x0009] = "Requested information response"
}

local chat_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Room information update",
	[0x0003] = "Users joined notification",
	[0x0004] = "Users left notification",
	[0x0005] = "Channel message from client",
	[0x0006] = "Channel message to client",
	[0x0007] = "Evil request",
	[0x0008] = "Evil reply",
	[0x0009] = "Chat error or data"
}

local buddy_icons_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Upload your icon to server",
	[0x0003] = "Server ack for icon upload",
	[0x0004] = "Request buddy icon from server (AIM only)",
	[0x0005] = "Server response to a buddy icon request (AIM only)",
	[0x0006] = "Request buddy icon from server (ICQ)",
	[0x0007] = "Server response to a buddy icon request (ICQ)"
}

local server_side_srv = {
	[0x0001] = "Client / server error",
	[0x0002] = "Request service parameters",
	[0x0003] = "Service parameters reply",
	[0x0004] = "Request contact list (first time)",
	[0x0005] = "Contact list checkout",
	[0x0006] = "Server contact list reply",
	[0x0007] = "Load server contact list (after login)",
	[0x0008] = "SSI edit: add item(s)",
	[0x0009] = "SSI edit: update group header",
	[0x000a] = "SSI edit: remove item",
	[0x000e] = "SSI edit server ack",
	[0x000f] = "client local SSI is up-to-date",
	[0x0011] = "Contacts edit start (begin transaction)",
	[0x0012] = "Contacts edit end (finish transaction)",
	[0x0014] = "Grant future authorization to client",
	[0x0015] = "Future authorization granted",
	[0x0016] = "Delete yourself from another client server contact",
	[0x0018] = "Send authorization request",
	[0x0019] = "Authorization request",
	[0x001a] = "Send authorization reply",
	[0x001b] = "Authorization reply",
	[0x001c] = "\"You were added\" message"
}

local auth_srv = {
	[0x0001] = "Server error (registration refused)",
	[0x0002] = "Client login request (md5 login sequence)",
	[0x0003] = "Server login reply / error reply",
	[0x0004] = "Request new uin",
	[0x0005] = "New uin response",
	[0x0006] = "Request md5 authkey",
	[0x0007] = "Server md5 authkey response",
	[0x000a] = "Server SecureID request",
	[0x000b] = "Client SecureID reply"
}

local snac_srv = {
	[0x0001] = general_srv,
	[0x0002] = location_srv,
	[0x0003] = management_srv,
	[0x0004] = messages_srv,
	[0x0006] = invitation_srv,
	[0x0007] = administrative_srv,
	[0x0008] = popup_srv,
	[0x0009] = pricacy_srv,
	[0x000a] = lookup_srv,
	[0x000b] = stats_srv,
	[0x000d] = chat_navigation_srv,
	[0x000e] = chat_srv,
	[0x0010] = buddy_icons_srv,
	[0x0013] = server_side_srv,
	[0x0017] = auth_srv
}

local snac_srv_names = {
	[0x0001] = "Generic service controls",
	[0x0002] = "Location services",
	[0x0003] = "Buddy List management service",
	[0x0004] = "ICBM (messages) service",
	[0x0005] = "Advertisements service",
	[0x0006] = "Invitation service",
	[0x0007] = "Administrative service",
	[0x0008] = "Popup notices service",
	[0x0009] = "Privacy management service",
	[0x000a] = "User lookup service (not used any more)",
	[0x000b] = "Usage stats service",
	[0x000c] = "Translation service",
	[0x000d] = "Chat navigation service",
	[0x000e] = "Chat service",
	[0x000f] = "Directory user search",
	[0x0010] = "Server-stored buddy icons (SSBI) service",
	[0x0013] = "Server Side Information (SSI) service",
	[0x0015] = "ICQ specific extensions service",
	[0x0017] = "Authorization/registration service",
	[0x0085] = "Broadcast service - IServerd extension"
}

function snac_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end	
	
	local subtree = tree:add(snac_proto, "SNAC Protocol data")
	local srv_id = buf(0,2):uint()
	local msg_id = buf(2,2):int()
	
	if snac_srv[srv_id] ~= nil then
		local t_srv = subtree:add(snac_service_id, buf(0,2))
		t_srv:append_text(" - " .. snac_srv_names[srv_id])
		
		if (snac_srv[srv_id])[msg_id] ~= nil then
			local t_msg = subtree:add(snac_subtype_id, buf(2,2))
			t_msg:append_text(" - " .. (snac_srv[srv_id])[msg_id])
			pinfo.cols.info = tostring(pinfo.cols.info) .. " SNAC - " .. (snac_srv[srv_id])[msg_id]
		else
			subtree:add(snac_subtype_id, buf(2,2))
		end
	else
		subtree:add(snac_service_id, buf(0,2))
		subtree:add(snac_subtype_id, buf(2,2))
	end
	
	subtree:add(snac_flags, buf(4,2))
	subtree:add(snac_request_id, buf(6,4))
	subtree:add(snac_data, buf(10, buf:len() - 10))
	
	if (srv_id == 0x0001 and msg_id == 0x000f) then
		uib_diss = Dissector.get("uib")
		uib_diss:call(buf(10 + 8):tvb(), pinfo, tree)
	end 
	
	if (srv_id == 0x0003 and (msg_id == 0x000b or msg_id == 0x000c)) then
		uib_diss = Dissector.get("uib")
		uib_diss:call(buf(10):tvb(), pinfo, tree)
	end
	
	if (srv_id == 0x0004 and msg_id == 0x0006) then
		icqmsg_diss = Dissector.get("icqumsg")
		icqmsg_diss:call(buf(10):tvb(), pinfo, tree)
	end
	
	if (srv_id == 0x0004 and msg_id == 0x0007) then
		icqsmsg_diss = Dissector.get("icqsmsg")
		icqsmsg_diss:call(buf(10):tvb(), pinfo, tree)
	end
end

-- FLAP Protocol dissector
local flap_proto = Proto("flap", "FLAP protocol")

local flap_packet_types = { 
	[0x01] = "New Connection Negotiation", 
	[0x02] = "SNAC data", 
	[0x03] = "FLAP-level Error", 
	[0x04] = "Close Connection Negotiation", 
	[0x05] = "Keep alive"
}

local flap_proto_magic = ProtoField.uint8("flap.magic", "FLAP Magic", base.HEX)
local flap_proto_channel = ProtoField.uint8("flap.channel", "FLAP Channel", base.HEX, packet_types)
local flap_datagram_seq_number = ProtoField.uint16("flap.seq_num", "FLAP Datagram seq number", base.HEX)
local flap_data_size = ProtoField.uint16("flap.data_size", "FLAP Data size", base.HEX)
local flap_data = ProtoField.bytes("flap.data", "FLAP Data")

flap_proto.fields = { flap_proto_magic, flap_proto_channel, flap_datagram_seq_number, flap_data_size, flap_data } 

function flap_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	local mag = buf(0,1):uint()
	
	local type_str = flap_packet_types[buf(1,1):uint()]
	if type_str == nil then type_str = "Unknown" end
	
	pinfo.cols.protocol = flap_proto.name	
	subtree = tree:add(flap_proto, buf(0))
	
	if mag == 0x2A then
		if buf(1,1):uint() ~= 0x02 then
			pinfo.cols.info = tostring(pinfo.cols.info) .. " Type: " .. type_str
		end
		subtree:add(flap_proto_magic, buf(0,1))
		subtree:add(flap_proto_channel, buf(1,1))
		subtree:add(flap_datagram_seq_number, buf(2,2))
		local chn = buf(1,1):uint()
		subtree:add(flap_data_size, buf(4,2))	
		local data_len = buf(4,2):uint()
		subtree:add(flap_data, buf(6, data_len))
		--subtree:add(flap_data, buf(6, buf:len() - 6))
		
		if chn == 2 then
			local snac_diss = Dissector.get("snac")
			--if snac_diss ~= nil then
				snac_diss:call(buf(6):tvb(),pinfo,subtree)
			--end
		end		
	else
		pinfo.cols.info = tostring(pinfo.cols.info) .. string.format(" Unknown version of FLAP Protocol. Magic: (0x%02x)", mag)
		subtree:append_text(string.format(", Unknown version of FLAP Protocol. Magic: (0x%02x)", mag))
	end
end

local flap_packets_proto = Proto("flapp", "Bunch of FLAP Packets")
local flap_packets_data = ProtoField.bytes("flapp.data", "Bunch of FLAP Packets Data")

flap_packets_proto.fields = { flap_packets_data }

function flap_packets_proto.dissector(buf, pinfo, tree)
	if buf:len() == 0 then return end
	
	pinfo.cols.protocol = flap_packets_proto.name
	pinfo.cols.info = ""
	
	subtree = tree:add(flap_packets_proto, buf(0))
	subtree:add(flap_packets_data, buf(0))

	local start = 0
	local ln = 0
	while start < buf:len() do
		flap_diss = Dissector.get("flap")
		if buf(start, 1):uint() == 0x2A then
			ln = buf(start + 4,2):uint() + 6 -- magic + channel + seq_num + data size value
			if ln > buf:len() - start then -- workaround =)
				flap_diss:call(buf(start):tvb(), pinfo, tree)
			else
				flap_diss:call(buf(start, ln):tvb(), pinfo, tree)
			end
			start = start + ln
		else
			flap_diss:call(buf(start):tvb(), pinfo, tree)
			start = buf:len()
		end
	end
end


local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(5190, flap_packets_proto)

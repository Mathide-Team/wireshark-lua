-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/tscheffl/LIFX (Wireshark/lifx.lua),
-- commit db2d5826e760c5db5d5bac101d99b5a0a6a43a2f du 13/02/2022.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
--[[

Copyright (c)   2012 Mark Wolfe, https://github.com/wolfeidau/lifx
			2022 Thomas Scheffler

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

]]--

local lifx = Proto("lifx", "LIFX wifi lightbulb")
local F = lifx.fields

function switch(t)
	t.case = function (self, pType, buffer, pinfo, tree)
		local f=self[pType]
		if packetNames[pType] then pinfo.cols.info = packetNames[pType] end
		if f then
			if type(f)=="function" then
				f(buffer, pinfo, tree, self)
			end
		end
	end
	return t
end

local onOffStrings = {
	[0x0000] = "Off",
	[0x0001] = "On",
	[0xffff] = "On"
}

local resetSwitchStrings = {
	[0] = "Up",
	[1] = "Down"
}

local interfaceStrings = {
	[1] = "soft_ap",
	[2] = "station"
}

local wifiStatusStrings = {
	[0] = "connecting",
	[1] = "connected",
	[2] = "failed",
	[3] = "off"
}

local securityProtocolStrings = {
	[1] = "OPEN",
	[2] = "WEP_PSK",
	[3] = "WPA_TKIP_PSK",
	[4] = "WPA_AES_PSK",
	[5] = "WPA2_AES_PSK",
	[6] = "WPA2_TKIP_PSK",
	[7] = "WPA2_MIXED_PSK"
}

local serviceStrings = {
	[1] = "UDP",
	[2] = "TCP"
}

packetNames = {
	[0x0002]   = "Get PAN gateway (2)",
	[0x0003]   = "PAN gateway state (3)",
	[0x0004]   = "Get time",
	[0x0005]   = "Set time",
	[0x0006]   = "Time state",
	[0x0007]   = "Get reset switch state",
	[0x0008]   = "Reset switch state",
	[0x0009]   = "Get dummy load",
	[0x000a]   = "Set dummy load",
	[0x000b]   = "Dummy load",
	[0x000c]   = "Get mesh info",
	[0x000d]   = "Mesh info",
	[0x000e]   = "Get mesh firmware (14)",
	[0x000f]   = "Mesh firmware state (15)",
	[0x0010]   = "Get wifi info (10)",
	[0x0011]   = "Wifi info (11)",
	[0x0012]   = "Get wifi firmware state (18)",
	[0x0013]   = "Wifi firmware state (19)",
	[0x0014]   = "Get power state (20)",
	[0x0015]   = "Set power state (21)",
	[0x0016]   = "Power state (22)",
	[0x0017]   = "Get bulb label",
	[0x0018]   = "Set bulb label",
	[0x0019]   = "Bulb label",
	[0x001a]   = "Get tags",
	[0x001b]   = "Set tags",
	[0x001c]   = "Tags",
	[0x001d]   = "Get tag labels",
	[0x001e]   = "Set tag labels",
	[0x001f]   = "Tag labels",
	[0x0020]   = "Get version (32)",
	[0x0021]   = "Version state (33)",
	[0x0022]   = "Get info (34)",
	[0x0023]   = "Info state (35)",
	[0x0024]   = "Get MCU rail voltage",
	[0x0025]   = "MCU rail voltage",
	[0x0026]   = "Reboot",
	[0x0027]   = "Set factory test mode",
	[0x0028]   = "Disable factory test mode",
	[0x0032]   = "StateLocation (50)",
	[0x003a]   = "Echo Request (58)",
	[0x003b]   = "Echo Reply (59)",	
	[0x0065]   = "Get light state (101)",
	[0x0066]   = "Set light colour (102",
	[0x0067]   = "Set waveform",
	[0x0068]   = "Set dim (absolute)",
	[0x0069]   = "Set dim (relative)",
	[0x006b]   = "Light status (107)",
	[0x006f]   = "Light temperature (111)",
	[0x012d]   = "Get wifi state (301)",
	[0x012e]   = "Set wifi state (302)",
	[0x012f]   = "Wifi state (303)",
	[0x0130]   = "Get access points",
	[0x0131]   = "Set access point",
	[0x0132]   = "Access point",
	[0x0191]   = "Get Ambient Light state",
	[0x0192]   = "Ambient Light state"
}

function panGatewayState(buffer, pinfo, tree)
	tree:add(F.service, buffer(0, 1))
	tree:add_le(F.port, buffer(1, 4))
end

function setTime(buffer, pinfo, tree)
	tree:add(F.time, buffer(0, 8))
end

function timeState(buffer, pinfo, tree)
	tree:add(F.time, buffer(0, 8))
end

function resetSwitchState(buffer, pinfo, tree)
	tree:add(F.resetSwitch, buffer(0, 1))
end

function meshInfo(buffer, pinfo, tree)
	tree:add(F.signal, buffer(0, 4))
	tree:add(F.tx, buffer(4, 4))
	tree:add(F.rx, buffer(8, 4))
	tree:add(F.mcuTemperature, buffer(12, 2))
end

function echoRequest(buffer, pinfo, tree)
	tree:add(F.echo, buffer(0, 64))
end

function echoReply(buffer, pinfo, tree)
	tree:add(F.echo, buffer(0, 64))
end

function meshFirmwareState(buffer, pinfo, tree)
	local build   = tree:add(buffer(0, 8), "Build")
	local install = tree:add(buffer(8, 8), "Reserved")
	local usecs = buffer(0,8):uint64()
	local le_usecs = usecs:bswap() --LIFX uses little endian
	local secs  = (le_usecs / 1000000000):tonumber()
	
	build:add(F.time_utc, buffer(0,8), NSTime.new(secs))

	--build:add(F.time_utc, usecs)
	--build:add(F.second, buffer(0, 1))
	--build:add(F.minute, buffer(1, 1))
	--build:add(F.hour,   buffer(2, 1))
	--build:add(F.day,    buffer(3, 1))
	--build:add(F.month,  buffer(4, 3))
	--build:add(F.year,   buffer(7, 1))

	usecs = buffer(8,8):uint64()
	le_usecs = usecs:bswap() --LIFX uses little endian
	secs  = (le_usecs / 1000000000):tonumber()

	install:add(F.time_utc, buffer(8,8), NSTime.new(secs))

	--install:add(F.time_utc, buffer(8, 8))
	--install:add(F.second, buffer(8,  1))
	--install:add(F.minute, buffer(9,  1))
	--install:add(F.hour,   buffer(10, 1))
	--install:add(F.day,    buffer(11, 1))
	--install:add(F.month,  buffer(13, 3))
	--install:add(F.year,   buffer(15, 1))

	tree:add(F.version, buffer(16, 4))
end

function wifiInfo(buffer, pinfo, tree)
	tree:add(F.signal, buffer(0, 4))
	tree:add(F.tx, buffer(4, 4))
	tree:add(F.rx, buffer(8, 4))
	tree:add(F.mcuTemperature, buffer(12, 2))
end

function wifiFirmwareState(buffer, pinfo, tree)
	local build   = tree:add(buffer(0, 8), "Build")
	local install = tree:add(buffer(8, 8), "Reserved")

	build:add(F.time_utc, buffer(0, 8))
	--build:add(F.second, buffer(0, 1))
	--build:add(F.minute, buffer(1, 1))
	--build:add(F.hour,   buffer(2, 1))
	--build:add(F.day,    buffer(3, 1))
	--build:add(F.month,  buffer(4, 3))
	--build:add(F.year,   buffer(7, 1))

	install:add(F.time_utc, buffer(8, 8))
	--install:add(F.second, buffer(8,  1))
	--install:add(F.minute, buffer(9,  1))
	--install:add(F.hour,   buffer(10, 1))
	--install:add(F.day,    buffer(11, 1))
	--install:add(F.month,  buffer(12, 3))
	--install:add(F.year,   buffer(15, 1))

	tree:add(F.version, buffer(16, 4))
end

function setPowerState(buffer, pinfo, tree)
	tree:add(F.onoffReq, buffer(0, 1))
end

function powerState(buffer, pinfo, tree)
	tree:add(F.onoffRes, buffer(0, 2))
end

function bulbLabel(buffer, pinfo, tree)
	tree:add(F.bulbName, buffer(0, 32))
end

function setBulbLabel(buffer, pinfo, tree)
	tree:add(F.bulbName, buffer(0, 32))
end

function setTags(buffer, pinfo, tree)
	tree:add(F.tags, buffer(0, 8))
end

function tags(buffer, pinfo, tree)
	tree:add(F.tags, buffer(0, 8))
end

function getTagLabels(buffer, pinfo, tree)
	tree:add(F.tags, buffer(0, 8))
end

function setTagLabels(buffer, pinfo, tree)
	tree:add(F.tags,  buffer(0, 8))
	tree:add(F.label, buffer(8, 40))
end

function tagLabels(buffer, pinfo, tree)
	tree:add(F.tags,  buffer(0, 8))
	tree:add(F.label, buffer(8, 40))
end

function versionState(buffer, pinfo, tree)
	tree:add(F.vendor,  buffer(0, 4))
	tree:add(F.product, buffer(4, 4))
	tree:add(F.version,  buffer(8, 4))
end

function infoState(buffer, pinfo, tree)
	tree:add(F.time,     buffer(0,  8))
	--tree:add(F.uptime,   buffer(8,  8))
	local usecs = buffer(8,8):uint64()
	local le_usecs = usecs:bswap() --LIFX uses little endian
	local secs  = (le_usecs / 1000000000):tonumber()
	tree:add(F.uptime, buffer(8,8), NSTime.new(secs))	
	tree:add(F.downtime, buffer(16, 8))
end

function mcuRailVoltage(buffer, pinfo, tree)
	tree:add(F.voltage, buffer(0, 4))
end

function stateLocation(buffer, pinfo, tree)
	tree:add(F.location, buffer(0, 16))
	tree:add(F.label, buffer(16, 32))
	--tree:add(F.updated, buffer(48, 8))
	local usecs = buffer(48,8):uint64()
	local le_usecs = usecs:bswap() --LIFX uses little endian
	local secs  = (le_usecs / 1000000000):tonumber()
	
	tree:add(F.time_utc, buffer(48, 8), NSTime.new(secs))

end

function setFactoryTestMode(buffer, pinfo, tree)
	tree:add(F.on, buffer(0, 1))
end

function setLightColour(buffer, pinfo, tree)
	tree:add(F.stream       , buffer(0, 1))
	tree:add_le(F.hue       , buffer(1, 2))
	tree:add_le(F.saturation, buffer(3, 2))
	tree:add_le(F.brightness, buffer(5, 2))
	tree:add_le(F.kelvin    , buffer(7, 2))
	tree:add_le(F.fadeTime  , buffer(9, 4))
end

function setWaveform(buffer, pinfo, tree)
	tree:add(F.stream       , buffer(0 , 1))
	tree:add(F.transient    , buffer(1 , 1))
	tree:add_le(F.hue       , buffer(2 , 2))
	tree:add_le(F.saturation, buffer(4 , 2))
	tree:add_le(F.brightness, buffer(6 , 2))
	tree:add_le(F.kelvin    , buffer(8 , 2))
	tree:add_le(F.period    , buffer(10, 4))
	tree:add(F.cycles       , buffer(14, 4))
	tree:add(F.dutyCycles   , buffer(18, 2))
	tree:add(F.waveform     , buffer(20, 1))
end

function setDimAbsolute(buffer, pinfo, tree)
	tree:add_le(F.brightness, buffer(0, 2))
	tree:add_le(F.fadeTime  , buffer(2, 4))
end

function setDimRelative(buffer, pinfo, tree)
	tree:add_le(F.brightness, buffer(0, 2))
	tree:add_le(F.fadeTime  , buffer(2, 4))
end

function lightStatus(buffer, pinfo, tree)
	tree:add_le(F.hue       , buffer(0 , 2))
	tree:add_le(F.saturation, buffer(2 , 2))
	tree:add_le(F.brightness, buffer(4 , 2))
	tree:add_le(F.kelvin    , buffer(6 , 2))
	tree:add(F.dim          , buffer(8 , 2))
	tree:add(F.power        , buffer(10, 2))
	tree:add(F.bulbName     , buffer(12, 32))
	tree:add(F.tags         , buffer(44, 8))
end

function lightTemperature(buffer, pinfo, tree)
	tree:add_le(F.kelvin    , buffer(0 , 2))
end

function getWifiState(buffer, pinfo, tree)
	tree:add(F.interface, buffer(0, 1))
end

function setWifiState(buffer, pinfo, tree)
	tree:add(F.interface , buffer(0, 1))
	tree:add(F.wifiStatus, buffer(1, 1))
	tree:add(F.ip4Address, buffer(2, 4))
	tree:add(F.ip6Address, buffer(6, 16))
end

function wifiState(buffer, pinfo, tree)
	tree:add(F.interface , buffer(0, 1))
	tree:add(F.wifiStatus, buffer(1, 1))
	tree:add(F.ip4Address, buffer(2, 4))
	tree:add(F.ip6Address, buffer(6, 16))
end

function setAccessPoint(buffer, pinfo, tree)
	tree:add(F.interface       , buffer(0 , 1))
	tree:add(F.ssid            , buffer(1 , 32))
	tree:add(F.password        , buffer(33, 64))
	tree:add(F.securityProtocol, buffer(97, 1))
end

function accessPoint(buffer, pinfo, tree)
	tree:add(F.interface       , buffer(0 , 1))
	tree:add(F.ssid            , buffer(1 , 32))
	tree:add(F.securityProtocol, buffer(33, 1))
	tree:add(F.strength,         buffer(34, 2))
	tree:add(F.channel,          buffer(36, 2))
end

function ambientLightState(buffer, pinfo, tree)
	tree:add(F.lux       , buffer(0, 4))
end

packetTable = switch {
	[0x0002] = getPanGateway,
	[0x0003] = panGatewayState,
	[0x0004] = getTime,
	[0x0005] = setTime,
	[0x0006] = timeState,
	[0x0007] = getResetSwitchState,
	[0x0008] = resetSwitchState,
	[0x0009] = getDummyLoad,
	[0x000a] = setDummyLoad,
	[0x000b] = dummyLoad,
	[0x000c] = getMeshInfo,
	[0x000d] = meshInfo,
	[0x000e] = getMeshFirmware,
	[0x000f] = meshFirmwareState,
	[0x0010] = getWifiInfo,
	[0x0011] = wifiInfo,
	[0x0012] = getWifiFirmwareState,
	[0x0013] = wifiFirmwareState,
	[0x0014] = getPowerState,
	[0x0015] = setPowerState,
	[0x0016] = powerState,
	[0x0017] = getBulbLabel,
	[0x0018] = setBulbLabel,
	[0x0019] = bulbLabel,
	[0x001a] = getTags,
	[0x001b] = setTags,
	[0x001c] = tags,
	[0x001d] = getTagLabels,
	[0x001e] = setTagLabels,
	[0x001f] = tagLabels,
	[0x0020] = getVersion,
	[0x0021] = versionState,
	[0x0022] = getInfo,
	[0x0023] = infoState,
	[0x0024] = getMcuRailVoltage,
	[0x0025] = mcuRailVoltage,
	[0x0026] = reboot,
	[0x0027] = setFactoryTestMode,
	[0x0028] = disableFactoryTestMode,
	[0x0032] = stateLocation,
	[0x003a] = echoRequest,
	[0x003b] = echoReply,	
	[0x0065] = getLightState,
	[0x0066] = setLightColour,
	[0x0067] = setWaveform,
	[0x0068] = setDimAbsolute,
	[0x0069] = setDimRelative,
	[0x006b] = lightStatus,
	[0x006f] = lightTemperature,
	[0x012d] = getWifiState,
	[0x012e] = setWifiState,
	[0x012f] = wifiState,
	[0x0130] = getAccessPoints,
	[0x0131] = setAccessPoint,
	[0x0132] = accessPoint,
	[0x0191] = getAmbientLightState,
	[0x0192] = ambientLightState
}

F.size             = ProtoField.uint16("lifx.size"           , "Packet size"          , base.DEC)
F.protocol         = ProtoField.uint16("lifx.protocol"       , "LIFX protocol"        , base.HEX)
F.reserved         = ProtoField.bytes("lifx.reserved"        , "Reserved"             , base.SPACE)
F.targetAddr       = ProtoField.ether("lifx.targetAddr"      , "Target address"       , base.HEX)
F.site             = ProtoField.ether("lifx.site"            , "Site address"         , base.HEX)
F.timestamp        = ProtoField.uint64("lifx.timestamp"      , "Timestamp"            , base.HEX)
F.packetType       = ProtoField.uint16("lifx.packetType"     , "Packet type"          , base.HEX , packetNames)
F.unknown          = ProtoField.bytes("lifx.unknown"         , "Unknown"              , base.SPACE)
F.onoffReq         = ProtoField.uint8("lifx.onoff"           , "On/off setting"       , base.HEX , onOffStrings)
F.bulbName         = ProtoField.string("lifx.bulbName"       , "Bulb name"            , base.ASCII)
F.hue              = ProtoField.uint16("lifx.hue"            , "Hue"                  , base.DEC)
F.saturation       = ProtoField.uint16("lifx.saturation"     , "Saturation"           , base.DEC)
F.brightness       = ProtoField.uint16("lifx.brightness"     , "Brightness"           , base.DEC)
F.kelvin           = ProtoField.uint16("lifx.kelvin"         , "Colour temperature"   , base.DEC)
F.fadeTime         = ProtoField.uint16("lifx.fadeTime"       , "Fade time"            , base.DEC)
F.onoffRes         = ProtoField.uint16("lifx.onoffResponse"  , "On/off"               , base.HEX , onOffStrings)
F.time             = ProtoField.uint64("lifx.time"           , "Time (us since epoch)", base.HEX)
F.time_utc         = ProtoField.absolute_time("lifx.time"    , "Timestamp (UTC)"      , base.ENC_TIME_TIMESPEC)		
F.uptime           = ProtoField.relative_time("lifx.uptime"  , "Uptime"               , base.ENC_TIME_TIMESPEC)
F.downtime         = ProtoField.uint64("lifx.downtime"       , "Downtime"             , base.HEX)
F.resetSwitch      = ProtoField.uint8("lifx.resetSwitch"     , "Reset switch"         , base.HEX , resetSwitchStrings)
F.tags             = ProtoField.uint64("lifx.tags"           , "Tags"                 , base.HEX)
F.voltage          = ProtoField.uint64("lifx.voltage"        , "Voltage"              , base.DEC)
F.stream           = ProtoField.uint8("lifx.stream"          , "Stream"               , base.HEX)
F.transient        = ProtoField.uint8("lifx.transient"       , "Transient"            , base.HEX)
F.period           = ProtoField.uint32("lifx.period"         , "Period"               , base.HEX)
F.cycles           = ProtoField.float("lifx.cycles"          , "Cycles"               , base.HEX)
F.dutyCycles       = ProtoField.uint16("lifx.dutyCycles"     , "Duty cycles"          , base.HEX)
F.waveform         = ProtoField.uint8("lifx.waveform"        , "Waveform"             , base.HEX)
F.dim              = ProtoField.uint16("lifx.dim"            , "Dim"                  , base.DEC)
F.power            = ProtoField.uint16("lifx.power"          , "Power"                , base.HEX , onOffStrings)
F.interface        = ProtoField.uint8("lifx.interface"       , "Interface"            , base.DEC , interfaceStrings)
F.wifiStatus       = ProtoField.uint8("lifx.wifiStatus"      , "Wifi status"          , base.HEX , wifiStatusStrings)
F.ip4Address       = ProtoField.bytes("lifx.ip4Address"      , "IP4 address"          , base.SPACE)
F.ip6Address       = ProtoField.bytes("lifx.ip6Address"      , "IP6 address"          , base.SPACE)
F.ssid             = ProtoField.bytes("lifx.ssid"            , "SSID (UTF8)"          , base.SPACE)
F.password         = ProtoField.bytes("lifx.password"        , "Password (UTF8)"      , base.SPACE)
F.securityProtocol = ProtoField.uint8("lifx.securityProtocol", "Security protocol"    , base.HEX , securityProtocolStrings)
F.signal           = ProtoField.float("lifx.signal"          , "Signal"               , base.DEC)
F.tx               = ProtoField.uint32("lifx.tx"             , "Tx"                   , base.DEC)
F.rx               = ProtoField.uint32("lifx.rx"             , "Rx"                   , base.DEC)
F.mcuTemperature   = ProtoField.uint16("lifx.mcuTemperature" , "MCU temperature"      , base.DEC)
F.second           = ProtoField.uint8("lifx.second"          , "Second"               , base.DEC)
F.minute           = ProtoField.uint8("lifx.minute"          , "Minute"               , base.DEC)
F.hour             = ProtoField.uint8("lifx.hour"            , "Hour"                 , base.DEC)
F.day              = ProtoField.uint8("lifx.day"             , "Day"                  , base.DEC)
F.month            = ProtoField.bytes("lifx.month"           , "Month"                , base.SPACE)
F.year             = ProtoField.uint8("lifx.year"            , "Year"                 , base.DEC)
F.label            = ProtoField.bytes("lifx.label"           , "Label"                , base.SPACE)
F.version          = ProtoField.uint32("lifx.version"        , "Version"              , base.HEX)
F.product          = ProtoField.uint32("lifx.product"        , "Product"              , base.HEX)
F.vendor           = ProtoField.uint32("lifx.vendor"         , "Vendor"               , base.HEX)
F.on               = ProtoField.uint8("lifx.on"              , "On"                   , base.HEX)
F.strength         = ProtoField.uint8("lifx.strength"        , "Strength"             , base.DEC)
F.channel          = ProtoField.uint8("lifx.channel"         , "Channel"              , base.DEC)
F.service          = ProtoField.uint8("lifx.service"         , "Service"              , base.HEX , serviceStrings)
F.port             = ProtoField.uint32("lifx.port"           , "Port"                 , base.DEC)
F.lux              = ProtoField.float("lifx.lux"             , "Lux"                  , base.HEX)
F.echo             = ProtoField.bytes("lifx.echo"            , "Echo Bytes"           , base.SPACE)
F.location         = ProtoField.bytes("lifx.location"        , "Device location"      , base.SPACE) 
F.label            = ProtoField.string("lifx.label"          , "Label"                , base.ASCII)
F.updated          = ProtoField.uint64("lifx.updated"        , "Updated at"           , base.HEX)

function lifx.dissector(buffer, pinfo, tree)
	analyse(buffer, pinfo, tree)
end

function analyse(buffer, pinfo, tree)
	pinfo.cols.info = "LIFX"

	-- LE maths on the packet length
	local lifxlength = buffer(0,2):le_uint()

	local subtree = tree:add(lifx, buffer(0, lifxlength), "LIFX packet")
	subtree:add_le(F.size, buffer(0,2))
	subtree:add(F.protocol, buffer(2,2))
	subtree:add(F.reserved, buffer(4,4))
	subtree:add(F.targetAddr, buffer(8,6))
	subtree:add(F.reserved, buffer(14,2))
	subtree:add(F.site, buffer(16,6))
	subtree:add(F.reserved, buffer(22,2))
	
	-- User readable Timestamp
	local usecs = buffer(24,8):uint64()
	local le_usecs = usecs:bswap() --LIFX uses little endian
	local secs  = (le_usecs / 1000000000):tonumber()
	
	subtree:add(F.time_utc,buffer(24,8), NSTime.new(secs))
	--subtree:add(F.timestamp, buffer(24,8))
	
	
	local packetPayload = subtree:add_le(F.packetType, buffer(32,2))
	subtree:add(F.reserved, buffer(34,2))

	-- Call the packet-specific handler
	packetTable:case(buffer(32,2):le_uint(), buffer(36), pinfo, packetPayload)

	-- Check if there's another LIFX packet inside this TCP packet
	if (lifxlength > 0 and buffer:len() > lifxlength) then
		analyse(buffer(lifxlength), pinfo, tree)
	end


end

local tcpTable = DissectorTable.get("tcp.port")
tcpTable:add(56700, lifx)
local udpTable = DissectorTable.get("udp.port")
udpTable:add(56700, lifx)


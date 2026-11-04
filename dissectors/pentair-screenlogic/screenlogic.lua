-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/EdDuran/WireShark-ScreenLogic-Dissector (screenlogic.lua),
-- commit 032e1dc3e39ec579c25da10539ecc87cc4df7260 du 24/05/2023.
-- Licence amont : GPL-3.0-only (LICENSE amont) — voir README.md.
-------------------------------------------------------------------------------
--
-- Pentair ScreenLogic Protocol WireShark Dissector
--
-- Keith Roberts
-- keith.roberts66@comcast.net
--
-- May 24, 2023  v1.0.0.0
--
-------------------------------------------------------------------------------

local default_settings =
{
    debug_level  = DEBUG,
    port         = 80
}

proto_pentair = Proto("Pentair", "Pentair ScreenLogic Protocol")
subproto_connect = Proto("Pentair.Connect", "Connect")
subproto_challenge = Proto("Pentair.Challenge", "Challenge")
subproto_challengeResponse = Proto("Pentair.ChallengeResponse", "Challenge Response")
subproto_login = Proto("Pentair.Login", "Login")
subproto_loginResponse = Proto("Pentair.LoginResponse", "Login Response")
subproto_saltConfig = Proto("Pentair.SaltConfig", "Salt Config")
subproto_saltConfigResponse = Proto("Pentair.SaltConfigResponse", "Salt Config Response")
subproto_setSaltConfig = Proto("Pentair.SetSaltConfig", "Set Salt Config")
subproto_setSaltConfigResponse = Proto("Pentair.SetSaltConfigResponse", "Set Salt Config Response")
subproto_allChemData = Proto("Pentair.AllChemData", "All Chem Data")
subproto_allChemDataResponse = Proto("Pentair.AllChemDataResponse", "All Chem Data Response")
subproto_pumpStatus = Proto("Pentair.PumpStatus", "Pump Status")
subproto_pumpStatusResponse = Proto("Pentair.PumpStatusResponse", "Pump Status Response")
subproto_controllerConfig = Proto("Pentair.ControllerConfig", "Controller Config")
subproto_controllerConfigResponse = Proto("Pentair.ControllerConfigResponse", "Controller Config Response")
subproto_status = Proto("Pentair.Status", "Status")
subproto_statusResponse = Proto("Pentair.StatusResponse", "Status Response")
subproto_version = Proto("Pentair.Version", "Version")
subproto_versionResponse = Proto("Pentair.VersionResponse", "Version Response")
subproto_pumpPresets = Proto("Pentair.Pump.Preset", "Pump Preset")
subproto_unknown = Proto("Pentair.Unknown", "Unknown")
subproto_scheduleChange = Proto("Pentair.ScheduleChange", "Schedule Change")
subproto_clock = Proto("Pentair.Clock", "Clock")
subproto_clockResponse = Proto("Pentair.ClockResponse", "Clock Response")
subproto_setClock = Proto("Pentair.SetClock", "Set Clock")
subproto_setClockResponse = Proto("Pentair.SetClockResponse", "Set Clock Response")
subproto_equipment = Proto("Pentair.Equipment", "Equipment")
subproto_equipmentResponse = Proto("Pentair.EquipmentResponse", "Equipment Response")


local vs_funcs = {
    [99999] = "Connect",
    [14]    = "Challenge",
    [15]    = "Challenge Response",
    [16]    = "Ping",
    [27]    = "Login",
    [28]    = "Login Response",
    [110]   = "Get Controller Mode",
    [111]   = "Get Controller Mode Response",
    [8058]  = "Get Firmware",
    [8059]  = "Get Firmware Response",
	[8110]  = "Get Clock",
	[8111]  = "Get Clock Response",
	[8112]  = "Set Clock",
	[8113]  = "Set Clock Response",
    [8120]  = "Get Version",
    [8121]  = "Get Version Response",
	[8300]	= "Unknown",
    [9611]  = "Query",
    [9612]  = "Response",
    [9806]  = "Weather Forecast Change",
    [9807]  = "Get Weather Forecast",
    [9808]  = "Get Weather Forecast Response",
    [12500] = "Status Change",
	[12501] = "Schedule Change",
    [12510] = "Get Circuit Definitions",
    [12511] = "Get Circuit Definitions Response",
    [12522] = "Add Client",
    [12523] = "Add Client Response",
    [12526] = "Get Status",
    [12527] = "Get Status Response",
    [12532] = "Get Controller Config",
    [12533] = "Get Controller Config Response",
    [12576] = "Set SCG Configuration",
    [12577] = "Set SCG Configuration Response",
    [12558] = "Get N Circuit Names",
    [12559] = "Get N Circuit Names Response",
    [12560] = "Get Circuit Names Response",
    [12561] = "Get Circuit Names",
    [12562] = "Get All Custom Names",
    [12563] = "Get All Custom Names Response",
    [12566] = "Get Equipment Configuration",
    [12567] = "Get Equipment Configuration Response",
    [12572] = "Get SCG Configuration",
    [12573] = "Get SCG Configuration Response",
    [12582] = "Get All Errors",
    [12583] = "Get All Errors Response",
    [12584] = "Get Pump Status",
    [12585] = "Get Pump Status Response",
    [12592] = "Get All Chem Data",
    [12593] = "Get All Chem Data Response"
}


-- declare fields

CONNECT = ProtoField.string("PENTAIR.CONNECT", "Connect", base.ASCII)
f_seq = ProtoField.uint16("Pentair.seq", "Sequence", base.DEC)
f_msg = ProtoField.uint16("Pentair.msg", "Message", base.DEC, vs_funcs)
f_len = ProtoField.uint16("Pentair.len", "Len", base.DEC)
f_byte = ProtoField.uint8("Pentair.Unknown8", "Unknown", base.HEX)
f_word16 = ProtoField.uint16("Pentair.Unknown16", "Unknown", base.HEX)
f_word = ProtoField.uint32("Pentair.Unknown32", "Unknown", base.HEX)
f_wordd = ProtoField.uint32("Pentair.Unknown32", "Unknown", base.DEC)
f_payload = ProtoField.bytes("Pentair.payload", "Payload", base.NONE)
f_text = ProtoField.string("Text", "Text", base.ASCII)
f_len32 = ProtoField.uint32("Pentair.Len32", "Len32", base.DEC)
f_processId = ProtoField.uint16("Pentair.ProcessId", "ProcessId", base.DEC)
f_clientVersion = ProtoField.string("Pentair.ClientVersion", "Client Version", base.ASCII)
f_password = ProtoField.string("Pentair.Password", "Password", base.ASCII)
f_firmwareVersion = ProtoField.string("Pentair.FirmwareVersion", "Firmware Version", base.ASCII)
f_controllerId = ProtoField.uint32("Pentair.ControllerId", "CtrlId", base.DEC)
f_saltPresent = ProtoField.string("Pentair.SaltPresent", "Salt Present", base.ASCII)
f_saltStatus = ProtoField.uint32("Pentair.SaltStatus", "Salt Status", base.HEX)
f_saltPoolLevel = ProtoField.uint32("Pentair.SaltPoolLevel", "Salt Pool Level", base.DEC)
f_saltSpaLevel = ProtoField.uint32("Pentair.SaltSpaLevel", "Salt Spa Level", base.DEC)
f_saltFlags = ProtoField.uint32("Pentair.SaltFlags", "Salt Flags", base.HEX)
f_saltPPM = ProtoField.uint32("Pentair.SaltPPM", "Salt PPM", base.DEC)
f_saltSuperTimer = ProtoField.uint32("Pentair.SaltSuperTimer", "Salt Super Timer", base.DEC)
f_poolMinSetPoint = ProtoField.uint8("Pentair.PoolMinSetPoint", "Pool Min Set Point", base.DEC)
f_poolMaxSetPoint = ProtoField.uint8("Pentair.PoolMaxSetPoint", "Pool Max Set Point", base.DEC)
f_spaMinSetPoint = ProtoField.uint8("Pentair.SpaMinSetPoint", "Spa Min Set Point", base.DEC)
f_spaMaxSetPoint = ProtoField.uint8("Pentair.SpaMaxSetPoint", "Spa Max Set Point", base.DEC)
f_isCelsius = ProtoField.string("Pentair.IsCelsius", "Is Celsius", base.ASCII)
f_typeStr = ProtoField.string("Pentair.Type", "Type", base.ASCII)
f_controllerType = ProtoField.uint8("Pentair.ControllerType", "Controller Type", base.DEC)
f_hardwareType = ProtoField.uint8("Pentair.HardwareType", "Hardware Type", base.DEC)
f_controllerBuffer = ProtoField.uint8("Pentair.ControllerBuffer", "Controller Buffer", base.DEC)
f_controllerData = ProtoField.uint8("Pentair.ControllerData", "Controller Data", base.DEC)
f_equipmentFlags = ProtoField.string("Pentair.EquipmentFlags", "Equipment Flags", base.ASCII)
f_circuit = ProtoField.string("Pentair.Circuit", "Circuit", base.ASCII)
f_cirCount = ProtoField.uint32("Pentair.CirCount", "Circuit Count", base.DEC)
f_cirId = ProtoField.uint32("Pentair.CirId", "Circuit Id", base.DEC)
f_pumpType = ProtoField.string("Pentair.PumpType", "Type", base.ASCII)
f_pumpState = ProtoField.string("Pentair.PumpState", "State", base.ASCII)
f_pumpWatts = ProtoField.uint32("Pentair.PumpWatts", "Watts", base.DEC)
f_pumpRPM = ProtoField.uint32("Pentair.PumpRPM", "RPM", base.DEC)
f_pumpGPM = ProtoField.uint32("Pentair.PumpGPM", "GPM", base.DEC)
f_pumpPresetCID = ProtoField.uint32("Pentair.Pump.Preset.CID", "CID", base.DEC)
f_pumpPresetSetPoint = ProtoField.uint32("Pentair.Pump.Preset.SetPoint", "Set Point", base.DEC)
f_pumpPresetIsRPM = ProtoField.uint32("Pentair.Pump.Preset.IsRPM", "Is RPM", base.DEC)
f_ok = ProtoField.uint32("Pentair.Status.Ok", "Ok", base.DEC)
f_freezeMode = ProtoField.uint8("Pentair.Status.FreezeMode", "Freeze Mode", base.DEC)
f_remotes = ProtoField.uint8("Pentair.Status.Remotes", "Remotes", base.DEC)
f_poolDelay = ProtoField.string("Pentair.Status.PoolDelay", "Pool Delay", base.ASCII)
f_spaDelay = ProtoField.string("Pentair.Status.SpaDelay", "Spa Delay", base.ASCII)
f_cleanerDelay = ProtoField.string("Pentair.Status.CleanerDelay", "Cleaner Delay", base.ASCII)
f_airTemp = ProtoField.uint32("Pentair.Status.AirTemp", "Air Temp", base.DEC)
f_lastTemp = ProtoField.uint32("Pentair.Status.Body.LastTemp", "Last Temp", base.DEC)
f_heatStatus = ProtoField.string("Pentair.Status.Body.HeatStatus", "Heat Status", base.ASCII)
f_heatSetPoint = ProtoField.uint32("Pentair.Status.Body.HeatSetPoint", "Heat Set Point", base.DEC)
f_heatMode = ProtoField.string("Pentair.Status.Body.HeatMode", "Heat Mode", base.ASCII)
f_coolSetPoint = ProtoField.uint32("Pentair.Status.Body.CoolSetPoint", "Cool Set Point", base.DEC)
f_bodyType = ProtoField.uint32("Pentair.Status.Body.Type", "Body Type", base.DEC)
f_cirType = ProtoField.uint32("Pentair.Status.Circuit.Type", "Circuit Type", base.DEC)
f_cirState = ProtoField.string("Pentair.Status.Circuit.State", "State", base.ASCII)
f_cirColorSet = ProtoField.uint8("Pentair.Status.Circuit.ColorSet", "Color Set", base.DEC)
f_cirColorPos = ProtoField.uint8("Pentair.Status.Circuit.ColorPos", "Color Pos", base.DEC)
f_cirColorStagger = ProtoField.uint8("Pentair.Status.Circuit.ColorStagger", "Color Stagger", base.DEC)
f_cirDelay = ProtoField.uint8("Pentair.Status.Circuit.Delay", "Delay", base.DEC)
f_ph = ProtoField.uint32("Pentair.Status.Circuit.Ph", "pH", base.DEC)
f_orp = ProtoField.uint32("Pentair.Status.Circuit.Orp", "ORP", base.DEC)
f_saturation = ProtoField.uint32("Pentair.Status.Circuit.Saturation", "Saturation", base.DEC)
f_phTank = ProtoField.uint32("Pentair.Status.Circuit.PhTank", "pH Tank", base.DEC)
f_orpTank = ProtoField.uint32("Pentair.Status.Circuit.OrpTank", "ORP Tank", base.DEC)
f_alarm = ProtoField.string("Pentair.Status.Circuit.Alarm", "Alarm", base.ASCII)

f_nameIndex = ProtoField.uint8("Pentair.Status.Circuit.NameIndex", "Name Index", base.DEC)
f_function = ProtoField.string("Pentair.Status.Circuit.Function", "Function", base.ASCII)
f_interface = ProtoField.string("Pentair.Status.Circuit.Interface", "Interface", base.ASCII)
f_flags = ProtoField.uint8("Pentair.Status.Circuit.Flags", "Flags", base.DEC)
f_deviceId = ProtoField.uint8("Pentair.Status.Circuit.DeviceId", "Device ID", base.DEC)
f_defaultRT = ProtoField.uint8("Pentair.Status.Circuit.DefaultRT", "Default RT", base.DEC)

f_year = ProtoField.uint16("Pentair.Date.Year", "Year", base.DEC)
f_month = ProtoField.uint16("Pentair.Date.Month", "Month", base.DEC)
f_day = ProtoField.uint16("Pentair.Date.Day", "Day", base.DEC)
f_hours = ProtoField.uint16("Pentair.Time.Hours", "Hours", base.DEC)
f_minutes = ProtoField.uint16("Pentair.Time.Minutes", "Minutes", base.DEC)
f_seconds = ProtoField.uint16("Pentair.Time.Seconds", "Seconds", base.DEC)
f_autoDST = ProtoField.string("Pentair.Time.AutoDST", "AutoDST", base.ASCII)
f_dayOfWeek = ProtoField.string("Pentair.Time.DayOfWeek", "Day of Week", base.ASCII)



proto_pentair.fields = {
    f_seq, f_msg, f_len, f_word16, f_payload, f_text, f_processId, f_controllerIndex,
    f_clientVersion, f_password, f_firmwareVersion, f_wordd, f_controllerId,
    f_saltPresent, f_saltStatus, f_saltPoolLevel, f_saltSpaLevel, f_saltFlags,
    f_saltPPM, f_saltSuperTimer, f_poolMinSetPoint, f_poolMaxSetPoint, f_spaMinSetPoint,
    f_spaMaxSetPoint, f_isCelsius, f_controllerType, f_hardwareType, f_controllerBuffer,
    f_equipmentFlags, f_circuit, f_cirCount, f_cirId, f_pumpType, f_pumpState, f_pumpWatts,
    f_pumpRPM, f_pumpGPM, f_pumpPresetCID, f_pumpPresetSetPoint, f_pumpPresetIsRPM,
    f_ok, f_freezeMode, f_remotes, f_poolDelay, f_spaDelay, f_cleanerDelay, f_byte,
    f_airTemp, f_lastTemp, f_heatStatus, f_heatSetPoint, f_heatMode, f_coolSetPoint, f_bodyType,
    f_cirType, f_cirState, f_cirColorSet, f_cirColorPos, f_cirColorStagger, f_cirDelay,
    f_ph, f_orp, f_saturation, f_phTank, f_orpTank, f_alarm, f_nameIndex, f_function,
    f_interface, f_flags, f_deviceId, f_defaultRT, f_year, f_month, f_day, f_hours, f_minutes,
	f_seconds, f_autoDST, f_dayOfWeek, f_len32, f_controllerData,
}

f_schema = ProtoField.uint16("Login.Schema", "Schema", base.DEC)
f_type = ProtoField.uint16("Login.Type", "Connection Type", base.DEC)

subproto_login.fields = { f_schema, f_type, f_word }

f_mac = ProtoField.string("Pentair.MAC", "MAC", base.ASCII)

subproto_challengeResponse.fields = { f_mac }

f_controllerIndex = ProtoField.uint32("Pentair.ControllerIndex", "CtrlIndx", base.DEC)

subproto_saltConfig.fields = { f_controllerIndex }


--
-- ============================================================================
--
-- Pentair ScreenLogic Protocol
--
function proto_pentair.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = proto_pentair.name
    local packetLength = buffer:len();
    local offset = 0

    local t_pentair = tree:add(proto_pentair, buffer(), "ScreenLogic Data")
    --
    -- Special case for ConnectServerHost
    --
    if packetLength >= 21 and buffer(offset,21):string() == "CONNECTSERVERHOST\r\n\r\n" then
        local dissector = pentair_table:get_dissector(99999)
        if (dissector ~= nil) then
            dissector:call(buffer, pinfo, t_pentair)
        else
            t_pentair:add(f_text, string.format("Dissector 'connect' not found"))
        end
    else
        -- Add the header tree item and populate
        t_hdr = t_pentair:add(buffer(offset, 8), "Header")
        local seq = buffer(offset, 2)
        local msg = buffer(offset + 2, 2)
        local len = buffer(offset + 4, 4)

        t_hdr:add_le(f_seq, seq)
        t_hdr:add_le(f_msg, msg)
        t_hdr:add_le(f_len, len)

        local msgCode = buffer(offset + 2, 2):le_uint()
        offset = offset + 8
        --
        -- Look up Dissector for [msg]
        --
        local dissector = pentair_table:get_dissector(msgCode)
        if (dissector ~= nil) then
            -- call dissector
            dissector:call(buffer(offset,packetLength - offset):tvb(), pinfo, t_pentair)
        else
            t_hdr:add(f_text, string.format("Dissector %d not found", msgCode))
            -- Dissector not found, output payload bytes
            if len:le_uint() ~= 0 then
                local payloadLen = buffer:len() - offset
                t_hdr:add(f_payload, buffer(offset, payloadLen))
            end
        end
    end
end -- pentair dissector

--
-- ============================================================================
--
-- Login
--
-- (int) Schema [use 348]
-- (int) Connection type [use 0]
-- (String) Client Version [use ‘Android’]
-- (byte[ ]) Data [use array filled with zeros of length 16] • (int) Process ID [use 2]
--
function subproto_login.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_login.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_login, buffer(), "Login")

    -- Schema (4)
    -- Connection Type (4)
    subtree:add_le(f_schema, buffer(offset,4)); offset = offset + 4
    subtree:add_le(f_type, buffer(offset,4)); offset = offset + 4
    
    -- Client Version
    local str, fullLen, newOffset = getString(buffer, offset)
    subtree:add_le(f_len, buffer(offset, 4)); offset = offset + 4
    subtree:add(f_clientVersion, buffer(offset, fullLen)); offset = newOffset

    -- Password
    str, fullLen, newOffset = getString(buffer, offset)
    subtree:add_le(f_len, buffer(offset, 4)); offset = offset + 4
    subtree:add(f_password, buffer(offset, fullLen)); offset = newOffset

    -- Pad Byte
    --offset = offset + 1

    local processId = buffer(offset, 2):le_uint()
    subtree:add_le(f_processId, buffer(offset, 4)); offset = offset + 4

    if (packetLength > offset) then
        subtree:add(f_payload, buffer(offset, packetLength - offset))
    end
    
end

--
---------------------------------------
--
-- Login Response
--
function subproto_loginResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_loginResponse.name
    length = buffer:len()
    local subtree = tree:add(subproto_login, buffer(), "Login Response")
--    subtree:add_le(f_schema, buffer(0,2))
--    subtree:add_le(f_type, buffer(2,2))
end

--
-- ============================================================================
--
-- Connect
--
function subproto_connect.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_connect.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_connect, buffer(offset,21))
    local offset = 21 -- skip over "CONNECTSERVERHOST\r\n\r\n"

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset,packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Challenge
--
function subproto_challenge.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_challenge.name
    local packetLength = buffer:len()
    local offset = 0

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset,packetLength - offset))
    end
end

--
---------------------------------------
--
-- Challenge Response
--
function subproto_challengeResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_challengeResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_challengeResponse, buffer)

    local len = buffer(offset,4):le_uint()
    subtree:add_le(f_len, buffer(offset,4))

    local str, fullLen, newOffset = getString(buffer, offset); offset = offset +4
    subtree:add(f_mac, buffer(offset, fullLen)); offset = offset + fullLen

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset,packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Salt Config
--
function subproto_saltConfig.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_saltConfig.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_saltConfig, buffer)

    subtree:add(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Salt Config Response
--
function subproto_saltConfigResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_saltConfigResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_saltConfigResponse, buffer(), "Salt Config Response")

    local present = buffer(offset,4):le_uint();
    local str; if (present == 0) then str = "No" else str = "Yes" end
    subtree:add(f_saltPresent, buffer(offset,4), str); offset = offset + 4;

    subtree:add_le(f_saltStatus, buffer(offset,4)); offset = offset + 4;
    subtree:add_le(f_saltPoolLevel, buffer(offset,4)); offset = offset + 4;
    subtree:add_le(f_saltSpaLevel, buffer(offset,4)); offset = offset + 4;

    local saltPPM = buffer(offset,4):le_uint() * 50
    subtree:add_le(f_saltPPM, buffer(offset,4), saltPPM); offset = offset + 4;

    subtree:add_le(f_saltFlags, buffer(offset,4)); offset = offset + 4;
    subtree:add_le(f_saltSuperTimer, buffer(offset,4)); offset = offset + 4;

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Set Salt Config
--
function subproto_setSaltConfig.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_setSaltConfig.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_setSaltConfig, buffer)

    subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_saltPoolLevel, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_saltSpaLevel, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_saltFlags, buffer(offset, 4)); offset = offset + 4;
    subtree:add_le(f_saltSuperTimer, buffer(offset, 4)); offset = offset + 4;

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Set Salt Config Response
--
function subproto_setSaltConfigResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_setSaltConfigResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_setSaltConfigResponse, buffer(), "Salt Config Response")
    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Get All Chem Data
--
function subproto_allChemData.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_allChemData.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_allChemData, buffer)

    subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Get All Chem Data Response
--
function subproto_allChemDataResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_allChemDataResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_allChemDataResponse, buffer(), "Get All Chem Data Response")
    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Pump Status
--
function subproto_pumpStatus.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_pumpStatus.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_pumpStatus, buffer)

    subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Pump Status Response
--
function subproto_pumpStatusResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_pumpStatusResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_pumpStatusResponse, buffer(), "Pump Status Response")

    local type = buffer(offset, 4):le_uint();
    subtree:add(f_pumpType, buffer(offset, 4), enum2string(type, PumpTypeMap)); offset = offset + 4;

    local state = buffer(offset, 4):le_uint();
    subtree:add(f_pumpState, buffer(offset, 4), enum2string(state, OnOffMap)); offset = offset + 4;

    subtree:add_le(f_pumpWatts, buffer(offset, 4)); offset = offset + 4;
    subtree:add_le(f_pumpRPM, buffer(offset, 4)); offset = offset + 4;
    subtree:add_le(f_word, buffer(offset, 4)); offset = offset + 4;
    subtree:add_le(f_pumpGPM, buffer(offset, 4)); offset = offset + 4;
    subtree:add_le(f_word, buffer(offset, 4)); offset = offset + 4;
    --
    -- preset
    --
    local len = packetLength - offset
    local presets = subtree:add(subproto_pumpPresets, buffer(offset, len), "Presets")
    for i = 0,7 do
        -- if cid == Circuit["deviceId"] name = "Default" else name = Circuit["name"]
        local preset = presets:add(subproto_pumpPresets, buffer(offset, 4+4+4), string.format("[%d]",i))
        preset:add_le(f_pumpPresetCID, buffer(offset, 4)); offset = offset + 4;
        preset:add_le(f_pumpPresetSetPoint, buffer(offset, 4)); offset = offset + 4;
        preset:add_le(f_pumpPresetIsRPM, buffer(offset, 4)); offset = offset + 4;
    end


    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

function enum2string(value, map)
    local str = map[value]
    if (str == nil) then str = "Unknown" end
    return string.format("%s (%d)", str, value)
end

function enum2stringNoValue(value, map)
    local str = map[value]
    if (str == nil) then str = "Unknown" end
    return str
end

--
-- ============================================================================
--
-- Controller Config
--
function subproto_controllerConfig.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_controllerConfig.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_controllerConfig, buffer)

    subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Controller Config Response
--
function subproto_controllerConfigResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_controllerConfigResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_controllerConfigResponse, buffer(), "Controller Config Response")

    -- Controller Id 4-bytes
    subtree:add_le(f_controllerId, buffer(offset, 4)); offset = offset + 4

    -- Pool Min Set Point 1-byte
    subtree:add_le(f_poolMinSetPoint, buffer(offset, 1)); offset = offset + 1

    -- Pool Max Set Point 1-byte
    subtree:add_le(f_poolMaxSetPoint, buffer(offset, 1)); offset = offset + 1

    -- Spa Min Set Point 1-byte
    subtree:add_le(f_spaMinSetPoint, buffer(offset, 1)); offset = offset + 1

    -- Spa Max Set Point 1-byte
    subtree:add_le(f_spaMaxSetPoint, buffer(offset, 1)); offset = offset + 1

    -- IsCelsius 1-byte
    local isCelsius = buffer(offset,1):le_uint()
    subtree:add(f_isCelsius, buffer(offset, 1), enum2string(isCelsius, YesNoMap)); offset = offset + 1

    -- Controller Type 1-byte
    -- Hardware Type 1-byte
    local controllerType = buffer(offset,1):le_uint()
    local hardwareType = buffer(offset+1,1):le_uint()
    local type = (controllerType * 10) + hardwareType
    local typeStr = enum2stringNoValue(type, ControllerTypeMap)
    local typeTree = subtree:add(subproto_unknown, buffer(offset,2), typeStr)
    typeTree:add_le(f_controllerType, buffer(offset, 1)); offset = offset + 1
    typeTree:add_le(f_hardwareType, buffer(offset, 1)); offset = offset + 1

    -- Controller Buffer Type 1-byte
    subtree:add_le(f_controllerBuffer, buffer(offset, 1)); offset = offset + 1

    -- Equipment Flags 4-bytes
    local flags = buffer(offset,4):le_uint()
    local flagsStr = {}
    for k, v in pairs(EquipmentFlagsMap) do
        if (bit.band(flags,k) == k) then
            flagsStr[#flagsStr+1] = tostring(v)
        end
    end
    subtree:add(f_equipmentFlags, buffer(offset, 4),
        string.format("%s (%d)", table.concat(flagsStr,","),flags))
    offset = offset + 4

    -- Generic Circuit Name n-bytes
    subtree:add_le(f_len, buffer(offset, 4));
    local str, fullLen, newOffset = getString(buffer, offset); offset = offset + 4
    subtree:add(f_circuit, buffer(offset, fullLen)):prepend_text("Generic ")
    offset = newOffset

    -- Circuits
    local circuitsOffsetStart = offset
    local cirCount = buffer(offset, 4):le_uint();
    local cirTree = subtree:add(subproto_unknown, buffer(offset, 4), string.format("Circuits [%d]", cirCount))
    offset = offset + 4

    for i = 1, cirCount do
        local cirOffsetStart = offset
        local cirId = buffer(offset, 4):le_uint()
        local str, fullLen, newOffset = getString(buffer, offset+4);
        local circuit = cirTree:add(subproto_unknown, buffer(offset, newOffset-offset), string.format("Circuit (%d) %s", cirId, str))
        offset = newOffset

        circuit:add(f_nameIndex, buffer(offset, 1)); offset = offset + 1
        local val = buffer(offset,1):le_uint();
        local str = enum2string(val, CircuitFunctionMap)
        circuit:add(f_function, buffer(offset, 1), str); offset = offset + 1
        val = buffer(offset,1):le_uint();
        str = enum2string(val, CircuitInterfaceMap)
        circuit:add(f_interface, buffer(offset, 1), str); offset = offset + 1
        circuit:add(f_flags, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_cirColorSet, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_cirColorStagger, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_deviceId, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_defaultRT, buffer(offset, 2)); offset = offset + 2
        circuit:add(f_byte, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_byte, buffer(offset, 1)); offset = offset + 1
        circuit:add(f_byte, buffer(offset, 1)); offset = offset + 1
        circuit:set_len(offset - cirOffsetStart)
    end
    cirTree:set_len(offset - circuitsOffsetStart)

    -- Colors
    local colorCount = buffer(offset, 4):le_uint();
    local colTree = subtree:add(subproto_unknown, buffer(offset, 4), string.format("Colors [%d]", colorCount))
    local colorsOffset = offset

    offset = offset + 4

    for i = 1, colorCount do
        local colorOffset = offset
        local str, fullLen, newOffset = getString(buffer, offset);
        local r = buffer(newOffset+0,4):le_uint();
        local g = buffer(newOffset+4,4):le_uint();
        local b = buffer(newOffset+8,4):le_uint();
        local color = colTree:add(subproto_unknown, buffer(offset, 0),
            string.format("%s, R:%d, G:%d B:%d", str, r, g, b))
        offset = newOffset
        color:add_le(f_wordd, buffer(offset,4)):set_text(string.format("Red:   %d",r)); offset = offset + 4
        color:add_le(f_wordd, buffer(offset,4)):set_text(string.format("Green: %d",g)); offset = offset + 4
        color:add_le(f_wordd, buffer(offset,4)):set_text(string.format("Blue:  %d",b)); offset = offset + 4
        color:set_len(offset - colorOffset)
    end
    colTree:set_len(offset - colorsOffset)

    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data
    subtree:add_le(f_byte, buffer(offset,1)):prepend_text("Pump Data: "); offset = offset + 1  -- pump data

    subtree:add_le(f_wordd, buffer(offset,4)):prepend_text("Interface Tab Flag: "); offset = offset + 4 -- interface tab flag
    subtree:add_le(f_wordd, buffer(offset,4)):prepend_text("Show Alarms: "); offset = offset + 4 -- show alarms

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- Get the string at the specified buffer offset
-- buffer points to int32 length, followed by string
-- returns:
--   string
--   fullLen of string including trailing 0's
--   newOffset length
--
function getString(buffer, offset)
    local strLen = buffer(offset,4):le_uint(); offset = offset + 4
    local mod = strLen % 4
    local fullLen = strLen
    if (mod ~= 0) then fullLen = strLen + (4 - mod) end
    local str = buffer(offset, strLen):string()
    newOffset = offset + fullLen
    return str, fullLen, newOffset
end

--
-------------------------------------------------------------------------------
--
-- Status
--
function subproto_status.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_status.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_status, buffer)

    subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
---------------------------------------
--
-- Status Response
--
function subproto_statusResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_statusResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_statusResponse, buffer(), "Status Response")
    local len

    subtree:add_le(f_ok, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_freezeMode, buffer(offset, 1)); offset = offset + 1
    subtree:add_le(f_remotes, buffer(offset, 1)); offset = offset + 1

    local poolDelay = buffer(offset,1):le_uint()
    local spaDelay = buffer(offset+1, 1):le_uint()
    local cleanerDelay = buffer(offset+2, 1):le_uint()

    local delayTree = subtree:add(subproto_unknown, buffer(offset, 3),
        string.format("Delays: Pool: %s, Spa: %s, Cleaner: %s",
            enum2stringNoValue(poolDelay, YesNoMap),
            enum2stringNoValue(spaDelay, YesNoMap),
            enum2stringNoValue(cleanerDelay, YesNoMap))
    )
    delayTree:add(f_poolDelay, buffer(offset, 1), enum2string(poolDelay, YesNoMap)); offset = offset + 1
    delayTree:add(f_spaDelay, buffer(offset, 1), enum2string(spaDelay, YesNoMap)); offset = offset + 1
    delayTree:add(f_cleanerDelay, buffer(offset, 1), enum2string(cleanerDelay, YesNoMap)); offset = offset + 1

    unknownTree = subtree:add(subproto_unknown, buffer(offset, 3), string.format("Unknown (%d)", 3))
    unknownTree:add(f_byte, buffer(offset, 1)); offset = offset + 1;
    unknownTree:add(f_byte, buffer(offset, 1)); offset = offset + 1;
    unknownTree:add(f_byte, buffer(offset, 1)); offset = offset + 1;

    subtree:add_le(f_airTemp, buffer(offset, 4)); offset = offset + 4;
    --
    -- Body
    --
    local bodyCount = buffer(offset,4):le_uint(); 
    len = bodyCount * (4*6) + 4;
    local bodies = subtree:add(subproto_unknown, buffer(offset, len), "Bodies")
    offset = offset + 4

    for i=0,bodyCount-1 do
        local bodyType = buffer(offset,4):le_uint();
        local bodyStart = offset;

        local lastTemp = buffer(offset+4, 4):le_uint();
        local heatStatus = buffer(offset+8, 4):le_uint();
        local heatSetPoint = buffer(offset+12, 4):le_uint();
        local coolSetPoint = buffer(offset+16, 4):le_uint();
        local heatMode = buffer(offset+20, 4):le_uint();

        local bodyDetails = string.format("%s: @%d, %s:%s, Cool@%d, Heat@%d",
            enum2string(bodyType, BodyMap),
            lastTemp,
            enum2stringNoValue(heatMode, HeatModeMap),
            enum2stringNoValue(heatStatus, OnOffMap),
            coolSetPoint,
            heatSetPoint
        )
        local bodyTree = bodies:add(subproto_unknown, buffer(bodyStart, 4*6), bodyDetails)


        offset = offset + 4
        bodyTree:add_le(f_lastTemp, buffer(offset, 4)); offset = offset + 4
        local heatStatus = buffer(offset,4):le_uint()
        bodyTree:add(f_heatStatus, buffer(offset, 4), enum2string(heatStatus, OnOffMap)); offset = offset + 4
        bodyTree:add_le(f_heatSetPoint, buffer(offset, 4)); offset = offset + 4
        bodyTree:add_le(f_coolSetPoint, buffer(offset, 4)); offset = offset + 4
        local heatMode = buffer(offset,4):le_uint()
        bodyTree:add(f_heatMode, buffer(offset, 4), enum2string(heatMode, HeatModeMap)); offset = offset + 4
    end

    -- Circuit Count 4

    local cirCount = buffer(offset,4):le_uint()
    local circuits = subtree:add(subproto_unknown, buffer(offset, (cirCount*12)+4), string.format("Circuits (%d)", cirCount))
    offset = offset + 4

    -- For i=1,CircuitCount do
    --   Circuit Id 4
    --   Circuit State 4
    --   Color Set 1
    --   Color Pos 1
    --   Color Stagger 1
    --   Circuit Delay 1

    for i=1,cirCount do
        local cirId = buffer(offset,4):le_uint()
        offset = offset + 4
        local cirState = buffer(offset,4):le_uint()
        local cirStateStr = enum2string(cirState, OnOffMap)
        local cirStateStrWO = enum2stringNoValue(cirState, OnOffMap)
        local cirTree = circuits:add(subproto_unknown, buffer(offset,12), string.format("Circuit [%d]: %s", cirId, cirStateStrWO))
        cirTree:add_le(f_cirState, buffer(offset, 4), cirStateStr); offset = offset + 4
        cirTree:add_le(f_cirColorSet, buffer(offset, 1)); offset = offset + 1
        cirTree:add_le(f_cirColorPos, buffer(offset, 1)); offset = offset + 1
        cirTree:add_le(f_cirColorStagger, buffer(offset, 1)); offset = offset + 1
        cirTree:add_le(f_cirDelay, buffer(offset, 1)); offset = offset + 1
    end

    --  PH 4
    --  ORP 4
    --  Saturation 4
    --  SaltPPM 4
    --  PHTank 4
    --  ORPTank 4
    --  Alarm 4

    subtree:add_le(f_ph, buffer(offset,4)); offset = offset + 4
    subtree:add_le(f_orp, buffer(offset,4)); offset = offset + 4
    subtree:add_le(f_saturation, buffer(offset,4)); offset = offset + 4
    local saltPPM = buffer(offset,4):le_uint()
    subtree:add(f_saltPPM, buffer(offset,4), saltPPM*50); offset = offset + 4
    subtree:add_le(f_phTank, buffer(offset,4)); offset = offset + 4
    subtree:add_le(f_orpTank, buffer(offset,4)); offset = offset + 4

    local alarm = buffer(offset,4):le_uint()
    subtree:add_le(f_alarm, buffer(offset,4), enum2string(alarm, YesNoMap)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Firmware Version
--
function subproto_version.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_version.name
    local packetLength = buffer:len()
    local offset = 0
end

--
---------------------------------------
--
-- Firmware Version Response
--
function subproto_versionResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_versionResponse.name
    local packetLength = buffer:len()
    local offset = 0
    local subtree = tree:add(subproto_versionResponse, buffer(), "Firmware Version Response")

    -- Firmware Version 
    local str, fullLen, newOffset = getString(buffer, offset)
    subtree:add_le(f_len, buffer(offset, 4)); offset = offset + 4;
    subtree:add(f_firmwareVersion, buffer(offset, fullLen)); offset = newOffset

    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4
    subtree:add_le(f_wordd, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
end

--
-- ============================================================================
--
-- Unknown
--
function subproto_unknown.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_unknown.name
    local packetLength = buffer:len()
    local offset = 0
	
    local subtree = tree:add(subproto_unknown, buffer(), "Unknown")

	if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end

end

--
-- ============================================================================
--
-- Schedule Change
--
function subproto_scheduleChange.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_scheduleChange.name
    local packetLength = buffer:len()
    local offset = 0
	
    local subtree = tree:add(subproto_unknown, buffer(), "Unknown")

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
	
end

--
-- ============================================================================
--
-- Clock Request
--
function subproto_clock.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_clock.name
    local packetLength = buffer:len()
    local offset = 0

end

--
-- ============================================================================
--
-- Equipment
--
function subproto_equipment.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_equipment.name
    local packetLength = buffer:len()
    local offset = 0
	
	subtree:add_le(f_controllerIndex, buffer(offset, 4)); offset = offset + 4

    if packetLength > offset then
        subtree:add_le(f_payload, buffer(offset, packetLength - offset))
    end
	
	return offset
		
end

--
-- ============================================================================
--
-- Equipment Response
--
function subproto_equipmentResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_equipmentResponse.name
    local packetLength = buffer:len()
    local offset = 0

    local subtree = tree:add(subproto_equipment, buffer(), "Equipment")

	local controllerType = buffer(offset,1):le_uint()
    local hardwareType = buffer(offset+1,1):le_uint()
    local type = (controllerType * 10) + hardwareType
    local typeStr = enum2stringNoValue(type, ControllerTypeMap)
    local typeTree = subtree:add(subproto_unknown, buffer(offset,2), typeStr)
    typeTree:add_le(f_controllerType, buffer(offset, 1)); offset = offset + 1
    typeTree:add_le(f_hardwareType, buffer(offset, 1)); offset = offset + 1

	subtree:add_le(f_byte, buffer(offset,1)); offset = offset + 1 
	subtree:add_le(f_byte, buffer(offset,1)); offset = offset + 1
	subtree:add_le(f_controllerData, buffer(offset,4)); offset = offset + 4
	
	offset = getArray(subtree, buffer, offset, "Version Data")
	offset = getArray(subtree, buffer, offset, "Speed Data")
	offset = getArray(subtree, buffer, offset, "Valve Data")
	offset = getArray(subtree, buffer, offset, "Remote Data")
	offset = getArray(subtree, buffer, offset, "Sensor Data")
	offset = getArray(subtree, buffer, offset, "Delay Data")
	offset = getArray(subtree, buffer, offset, "Macros Data")
	offset = getArray(subtree, buffer, offset, "Misc Data")
	offset = getArray(subtree, buffer, offset, "Light Data")
	offset = getArray(subtree, buffer, offset, "Flows Data")
	offset = getArray(subtree, buffer, offset, "SGS Data")
	offset = getArray(subtree, buffer, offset, "Spa Flows Data")

	
	return offset	
end

--
-- Get Equipment Data array
--
-- Return: new Offset
--
function getArray(tree, buffer, offset, name)
	print("getArray("..name.."): offset="..offset)
    local len = buffer(offset,4):le_uint()
	print("len="..len)
	
    local arrayTree = tree:add(subproto_unknown, buffer(offset,len+4), name)

	arrayTree:add_le(f_len32, buffer(offset,4)); offset = offset + 4
	arrayTree:add_le(f_payload, buffer(offset, len))

	local mod = len % 4
	if (mod ~= 0) then
		print("..mod="..mod)
		len = len + (4 - mod)
	end
	
	
	newOffset = offset + len
	print("..newOffset="..newOffset)
    return newOffset
end




--
-- ============================================================================
--
-- Clock Response
--
function subproto_clockResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_clockResponse.name
    local packetLength = buffer:len()
    local offset = 0
	
	return DecodeClock(buffer, pinfo, tree, offset)
		
end


--
-- ============================================================================
--
-- Set Clock
--
function subproto_setClock.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_setClock.name
    local packetLength = buffer:len()
    local offset = 0
	
	return DecodeClock(buffer, pinfo, tree, offset)
end

function DecodeClock(buffer, pinfo, tree, offset)
	local year = buffer(offset,2):le_uint(); offset = offset + 2
	local month = buffer(offset,2):le_uint(); offset = offset + 2
	local dayOfWeek = buffer(offset,2):le_uint(); offset = offset + 2
	local day = buffer(offset,2):le_uint(); offset = offset + 2
	local hours = buffer(offset,2):le_uint(); offset = offset + 2
	local minutes = buffer(offset,2):le_uint(); offset = offset + 2
	local seconds = buffer(offset,2):le_uint(); offset = offset + 2
	local unk2 = buffer(offset,2):le_uint(); offset = offset + 2
	local autoDST = buffer(offset,2):le_uint(); offset = offset + 2
	local unk3 = buffer(offset,2):le_uint(); offset = offset + 2
	
	local Clock = string.format("Clock: %s %s %d, %d %02d:%02d:%02d %s",
	   DayOfWeekMap[dayOfWeek], MonthMap[month], day, year, hours, minutes, seconds,
	   ternary(autoDST == 1, "AutoDST", "ManualDST"))
	
    local subtree = tree:add(subproto_clockResponse, buffer(), Clock);
	offset = 0;
	
	subtree:add_le(f_year, buffer(offset, 2)); offset = offset + 2;
	subtree:add_le(f_month, buffer(offset, 2)); offset = offset + 2;
	subtree:add(f_dayOfWeek, buffer(offset, 2), enum2string(dayOfWeek, DayOfWeekMap)); offset = offset + 2;
	subtree:add_le(f_day, buffer(offset, 2)); offset = offset + 2;
	subtree:add_le(f_hours, buffer(offset, 2)); offset = offset + 2;
	subtree:add_le(f_minutes, buffer(offset, 2)); offset = offset + 2;
	subtree:add_le(f_seconds, buffer(offset, 2)); offset = offset + 2;
	subtree:add_le(f_word16, buffer(offset, 2)); offset = offset + 2;
	subtree:add(f_autoDST, buffer(offset, 2), enum2string(autoDST, YesNoMap)); offset = offset + 2;

	subtree:add_le(f_word16, buffer(offset, 2)); offset = offset + 2;
	
	return offset;
end


--
-- ============================================================================
--
-- Set Clock
--
function subproto_setClockResponse.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = subproto_setClockResponse.name
    local packetLength = buffer:len()
    local offset = 0

end

--
-- =============================================================================
--
-- Ternary Operator .. ie, ( condition ? true : false )
--
function ternary(cond, T, F)
	if cond then return T else return F end
end


--
-- ============================================================================
--
-- Enumeration Maps
--
    BodyMap = {}
    BodyMap[0] = "Pool"
    BodyMap[1] = "Spa"

    OnOffMap = {}
    OnOffMap[0] = "Off"
    OnOffMap[1] = "On"

    YesNoMap = {}
    YesNoMap[0] = "No"
    YesNoMap[1] = "Yes"

    HeatModeMap = {}
    HeatModeMap[0] = "Off"
    HeatModeMap[1] = "Solar"
    HeatModeMap[2] = "Solar Preferred"
    HeatModeMap[3] = "Heater"
    HeatModeMap[4] = "Do Not Change"

    PumpTypeMap = {}
    PumpTypeMap[0] = "None"
    PumpTypeMap[1] = "Intelliflo VF"
    PumpTypeMap[2] = "Intelliflo VS"
    PumpTypeMap[3] = "Intelliflow VSF"

    ControllerTypeMap = {}
    ControllerTypeMap[0]   = "IntelliTouch i5+3S"
    ControllerTypeMap[10]  = "IntelliTouch i7+3"
    ControllerTypeMap[20]  = "IntelliTouch i9+3"
    ControllerTypeMap[30]  = "IntelliTouch i5+3S"
    ControllerTypeMap[40]  = "IntelliTouch i9+3S"
    ControllerTypeMap[50]  = "IntelliTouch i10+3D"
    ControllerTypeMap[51]  = "IntelliTouch i10X"
    ControllerTypeMap[110] = "Suntouch/Intellicom"
    ControllerTypeMap[130] = "EasyTouch2 8"
    ControllerTypeMap[131] = "EasyTouch2 8P"
    ControllerTypeMap[132] = "EasyTouch2 4"
    ControllerTypeMap[133] = "EasyTouch2 4P"
    ControllerTypeMap[135] = "EasyTouch2 PL4"
    ControllerTypeMap[136] = "EasyTouch2 PSL4"
    ControllerTypeMap[140] = "EasyTouch1 8"
    ControllerTypeMap[141] = "EasyTouch1 8P"
    ControllerTypeMap[142] = "EasyTouch1 4"
    ControllerTypeMap[143] = "EasyTouch1 4P"

    CircuitFunctionMap = {}
    CircuitFunctionMap[0] = "Generic"
    CircuitFunctionMap[1] = "Spa"
    CircuitFunctionMap[2] = "Pool"
    CircuitFunctionMap[5] = "Master Cleaner"
    CircuitFunctionMap[7] = "Light"
    CircuitFunctionMap[8] = "Dimmer"
    CircuitFunctionMap[9] = "Sam Light"
    CircuitFunctionMap[10] = "Sal Light"
    CircuitFunctionMap[11] = "PhotonGen"
    CircuitFunctionMap[12] = "Color Wheel"
    CircuitFunctionMap[13] = "Valve"
    CircuitFunctionMap[14] = "Spillway"
    CircuitFunctionMap[15] = "Floor Cleaner"
    CircuitFunctionMap[16] = "IntelliBrite"
    CircuitFunctionMap[17] = "MagicStream"


    CircuitInterfaceMap = {}
    CircuitInterfaceMap[0] = "Pool"
    CircuitInterfaceMap[1] = "Spa"
    CircuitInterfaceMap[2] = "Generic Feature"
    CircuitInterfaceMap[3] = "Light"
    CircuitInterfaceMap[4] = "IntelliBrite"

    EquipmentFlagsMap = {}
    EquipmentFlagsMap[0x0001] = "Solar"
    EquipmentFlagsMap[0x0002] = "Solar as Heat Pump" 
    EquipmentFlagsMap[0x0004] = "Chlorinator" 
    EquipmentFlagsMap[0x0008] = "Bit-3"
    EquipmentFlagsMap[0x0010] = "Bit-5"
    EquipmentFlagsMap[0x0020] = "Spa Side Remote"
    EquipmentFlagsMap[0x0800] = "Cooling"
    EquipmentFlagsMap[0x8000] = "Intellichem"
	
	MonthMap = {}
	MonthMap[1] = "Jan"
	MonthMap[2] = "Feb"
	MonthMap[3] = "Mar"
	MonthMap[4] = "Apr"
	MonthMap[5] = "May"
	MonthMap[6] = "Jun"
	MonthMap[7] = "Jul"
	MonthMap[8] = "Aug"
	MonthMap[9] = "Sep"
	MonthMap[10] = "Oct"
	MonthMap[11] = "Nov"
	MonthMap[12] = "Dec"
	
	DayOfWeekMap = {}
	DayOfWeekMap[0] = "Mon"
	DayOfWeekMap[1] = "Tue"
	DayOfWeekMap[2] = "Wed"
	DayOfWeekMap[3] = "Thu"
	DayOfWeekMap[4] = "Fri"
	DayOfWeekMap[5] = "Sat"
	DayOfWeekMap[6] = "Sun"

--
-- ============================================================================
--
-- Load TCP Port Table
-- Register Pentair to Port 80
--
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(80, proto_pentair)

pentair_table = DissectorTable.new("pentair")
pentair_table:add(99999, subproto_connect)
pentair_table:add(14,    subproto_challenge)
pentair_table:add(15,    subproto_challengeResponse)
pentair_table:add(27,    subproto_login)
pentair_table:add(28,    subproto_loginResponse)
pentair_table:add(8110,  subproto_clock)
pentair_table:add(8111,  subproto_clockResponse)
pentair_table:add(8112,  subproto_setClock)
pentair_table:add(8113,  subproto_setClockResponse)
pentair_table:add(8120,  subproto_version)
pentair_table:add(8121,  subproto_versionResponse)
pentair_table:add(8300,  subproto_unknown)
pentair_table:add(12501, subproto_scheduleChange)
pentair_table:add(12526, subproto_status)
pentair_table:add(12527, subproto_statusResponse)
pentair_table:add(12532, subproto_controllerConfig)
pentair_table:add(12533, subproto_controllerConfigResponse)
pentair_table:add(12566, subproto_equipment)
pentair_table:add(12567, subproto_equipmentResponse)
pentair_table:add(12572, subproto_saltConfig)
pentair_table:add(12573, subproto_saltConfigResponse)
pentair_table:add(12576, subproto_setSaltConfig)
pentair_table:add(12577, subproto_setSaltConfigResponse)
pentair_table:add(12584, subproto_pumpStatus)
pentair_table:add(12585, subproto_pumpStatusResponse)
pentair_table:add(12592, subproto_allChemData)
pentair_table:add(12593, subproto_allChemDataResponse)

-- SPDX-License-Identifier: MIT
-- Importé de https://github.com/kargs-net/kargs-net.github.io (captures/irb.lua),
-- commit c7f6b224d314da0d7bfe3711fee34cd3a693680e du 31/05/2026.
-- Licence amont : MIT (LICENSE amont) — voir README.md.
-- The Watt Stopper - In Room Bus dissector
-- Copyright Steve Karg <skarg@users.sourceforge.net>
--[[

Copy this file to the plugins directory:
i.e. C:\Program Files\Wireshark\plugins\1.6.3

TODO:
add dissection to all the packet types

]]

local irb = Proto("DLM", "The Watt Stopper DLM bus")

local f = irb.fields

-- Value Strings
local vs_fc = {
    [0] = "none",
    [1] = "Arbitrate Request",
    [3] = "Arbitrate Release",
    [4] = "PnG Request",
    [5] = "PnG Enter",
    [6] = "PnG Exit",
    [7] = "PnG Required",
    [8] = "PnG Configure",
    [9] = "PnG Deny",
    [10] = "PnL Request",
    [11] = "PnL Enter",
    [12] = "PnL Exit",
    [13] = "PnL Next",
    [14] = "PnL Data",
    [15] = "PnL Set",
    [16] = "Set",
    [17] = "Clear Device",
    [18] = "Memory Read",
    [19] = "MAC Response",
    [20] = "MAC Ping",
    [21] = "MAC Reboot",
    [22] = "MAC Reset",
    [23] = "MAC Report",
    [24] = "Sensor Default",
    [25] = "Memory Write",
    [26] = "Short Address",
    [27] = "PnL Load Query",
    [28] = "Load Table",
    [29] = "Sensor Query",
    [30] = "Sensor Data",
    [31] = "Active for Override",
    [32] = "Schedule Request",
    [33] = "Schedule Overrides",
    [35] = "Scene Include Exclude",
    [36] = "Scene Set",
    [37] = "Test Mode Override",
    [38] = "Sensor Detection",
    [39] = "Ack Load",
    [40] = "Ack IR",
    [41] = "Set MAC",
    [42] = "Clear Bindings",
    [43] = "IRB Clear",
    [44] = "IRB Reset",
    [45] = "IRB Reboot",
    [46] = "Device Query",
    [47] = "Memory Reply",
    [48] = "Test Mode Exit",
    [49] = "Device Response",
    [50] = "Test Mode",
    [51] = "Sensor Warning",
    [52] = "Sensor Goto",
    [53] = "PnL Toggle Binding",
    [54] = "Scene Table On Level",
    [55] = "Scene Table Off Level",
    [56] = "Scene Table Fade Rate",
    [57] = "Lock Switches",
    [58] = "Button Query",
    [59] = "Button ID",
    [60] = "Group Status",
    [61] = "Load Data",
    [62] = "Load Count Request",
    [63] = "Load Count",
    [64] = "24V Request",
    [65] = "24V Reply",
    [66] = "24V Assign",
    [67] = "Ack Load Query",
    [68] = "Function Code 68",
    [69] = "Factory Defaults Request",
    [70] = "Factory Defaults Unlock",
    [71] = "Function Code 71",
    [72] = "Presentation Mode",
    [74] = "Analog Photocell",
    [75] = "Power Monitor",
    [76] = "Power Monitor High Resolution",
    [77] = "Power Monitor Shades",
    [78] = "Status Report",
    [79] = "Status Response",
    [80] = "Get",
    [81] = "Set Macro",
    [82] = "Radio Activate",
    [83] = "BAS Module Report",
    [84] = "BAS Module Response",
    [85] = "Active Profile Set",
    [86] = "Function Code 86",
    [87] = "PnG/PnL Lock/Unlock",
    [88] = "IRB Environment Type",
    [89] = "Function Code 89",
    [90] = "Locale Query",
    [91] = "Locale Response",
    [92] = "MAC Ping Stop",
    [93] = "Function Code 93",
    [94] = "Load Shed",
    [95] = "Function Code 95",
    [96] = "Bootloader Present",
    [97] = "Bootloader Start",
    [98] = "Bootloader Gone",
    [99] = "Function Code 99",
    [100] = "PnS Tug Lock",
    [101] = "24V Enable",
    [102] = "Shade Bus Power Control",
    [103] = "Shade Count Request",
    [104] = "Shade Count",
    [105] = "TnG Deny",
    [106] = "TnL Request",
    [107] = "TnL Enter",
    [108] = "TnL Exit",
    [109] = "TnL Next",
    [110] = "TnL Data",
    [111] = "TnL Set",
    [112] = "Daylight Set Sensor Calibration",
    [113] = "Daylight Commission Auto",
    [114] = "Daylight Commission Manual",
    [115] = "Daylight Report Task Levels",
    [116] = "Daylight Commission Stop",
    [117] = "Daylight Commission Complete",
    [118] = "Daylight Adjust Start",
    [119] = "Daylight Adjust Level",
    [120] = "Daylight Adjust End",
    [121] = "Daylight Report Task Setpoint",
    [122] = "Photocell COV",
    [123] = "Function Code 123",
    [124] = "Function Code 124",
    [125] = "Function Code 125",
    [126] = "Function Code 126",
    [127] = "Function Code 127",
    [128] = "Master MAC Report",
    [129] = "Master MAC Response",
    [130] = "Get Image",
    [131] = "Get Image",
    [132] = "Get Image Mask",
    [133] = "Get Image Data",
    [133] = "Smartwire Process",
    [134] = "Tag Network Description",
    [135] = "Image Mask Data",
    [136] = "Masking Event",
    [137] = "Group Control",
    [138] = "Color Acknowledge",
    [139] = "Luna Bootload Command",
    [140] = "Function Code 140",
    [141] = "Function Code 141",
    [142] = "Function Code 142",
    [143] = "Function Code 143",
    [144] = "Debug Message",

    [240] = "Switch Error",
    [245] = "Load Step Request",
    [246] = "Load Step Response",
    [254] = "Room Error",
    [255] = "Test"
}

local vs_sfc = {
    [0] = "ACK",
    [1] = "Load ID",
    [2] = "Load Table",
    [3] = "Zone",
    [4] = "Scene",
    [8] = "Short Address",
    [9] = "Scene Name",
    [10] = "LED On Level",
    [11] = "LED Off Level",
    [12] = "LED Brightness",
    [13] = "Sensor Sensitivity",
    [14] = "Sensor Priority",
    [16] = "Relay Close Time",

    [100] = "Sensor Features v1",
    [101] = "Sensor/Switch Load Table",
    [102] = "Sensor/Switch Load Status",
    [103] = "Sensor Features v2",
    [105] = "Switch Features",
    [106] = "Button Label",
    [107] = "Button Features",
    [108] = "LMxW Load Table",
    [109] = "LMxW Load Status",

    [110] = "Daylight Features",
    [111] = "Daylight Load Table",
    [112] = "Daylight Dimming",
    [113] = "Daylight Switching",
    [114] = "Daylight Zone Dimming",
    [115] = "Daylight Zone Switching",
    [116] = "Photocell Features",
    [117] = "Daylight Calibration",
    [118] = "Daylight Dual Head Features",
    [119] = "Daylight Dual Head Calibration",

    [120] = "Load Power",
    [121] = "Load Label",
    [122] = "Load Features",
    [123] = "Load Mode Dimming",
    [124] = "Load Mode",
    [125] = "Load Scene",
    [126] = "Load Priority Array",
    [127] = "Load Reference Current",
    [128] = "Load Scene Enabled",
    [129] = "Load Trim",

    [130] = "BACnet Module Features",
    [131] = "BACnet Strings",
    [132] = "BACnet Demand Response",
    [133] = "BACnet Group Name",
    [134] = "BACnet Group Features",
    [135] = "BACnet Dark Features",
    [136] = "BACnet Status",
    [137] = "BACnet Occupy",
    [138] = "BACnet Button",
    [139] = "Crypto Data",

    [140] = "Holiday",
    [141] = "Location",
    [142] = "Time",
    [143] = "Daylight Savings Time",
    [144] = "Schedule Name",
    [145] = "Schedule",

    [150] = "Load Power High Resolution",
    [151] = "Camera Sensor Features",

    [154] = "802.15.4 Radio",

    [159] = "Log Message",

    [160] = "Ballast Curve",
    [161] = "Shade LED Status",
    [162] = "Shade Calibration",
    [163] = "Shade Power",
    [164] = "Shade Statistics",

    [176] = "LX Firmware Version",

    [178] = "LMSP Power Status",
    [179] = "LMSP USB Status",

    [181] = "LMSP Schedule",

    [200] = "Device Name",
    [201] = "Device Location",
    [202] = "Device Version",

    [255] = "NAK"
}

local vs_shed_mode = {
    [0] = "disabled",
    [1] = "enabled override allowed",
    [2] = "enabled override forbidden"
}

local vs_dimmer_command = {
    [0] = "Dimmer Stop",
    [1] = "Dimmer Up",
    [2] = "Dimmer Down"
}

local vs_group_local = {
    [0] = "Local and Remote",
    [1] = "Local Only",
    [2] = "Remote Only"
}

local vs_priority = {
    [0] = "Override or Egress",
    [1] = "Manual-Life Safety",
    [2] = "Automatic-Life Safety",
    [3] = "non-specific",
    [4] = "non-specific",
    [5] = "Critical Equipment Control",
    [6] = "Minimum On/Off",
    [7] = "Daylighting",
    [8] = "Manual Operator",
    [9] = "non-specific",
    [10] = "non-specific",
    [11] = "non-specific",
    [12] = "non-specific",
    [13] = "non-specific",
    [14] = "non-specific",
    [15] = "non-specific",
    [16] = "Lowest",
    [17] = "no-priority"
}

local vs_level = {
    [0] = "Off (0%)",
    [1] = "Minumum On (1%)",
    [100] = "Maximum On (100%)",
    [240] = "Last non-zero",
    [241] = "Do nothing",
    [242] = "Normal Hours Override",
    [243] = "After Hours Override",
    [244] = "Normal Hours",
    [245] = "After Hours",
    [246] = "Last non-zero occupied",
    [247] = "Group Off",
    [248] = "Group On",
    [249] = "Scene On",
    [250] = "Blink",
    [251] = "Shed Down",
    [252] = "Shed Up",
    [253] = "Scene Off",
    [254] = "Presentation",
    [255] = "Relinquish"
}

local vs_sensor_mode = {
    [0] = "nothing",
    [1] = "off-only",
    [2] = "on-only",
    [3] = "on and off",
    [4] = "on-only use override",
    [5] = "off-only use grace time",
    [6] = "on and off use grace time",
    [254] = "reload",
    [255] = "ignored"
}

local vs_button_mode = {
    [0] = "nothing",
    [1] = "off-only",
    [2] = "on-only",
    [3] = "on and off",
    [254] = "reload",
    [255] = "ignored"
}

local vs_button_momentary_mode = {
    [0] = "toggle tracking",
    [1] = "on-only",
    [2] = "off-only",
    [3] = "toggle non-tracking"
}

local vs_button_scene_lock = {
    [0] = "unlocked",
    [1] = "locked"
}

local vs_switch_button_mode = {
    [1] = "Scene 1",
    [2] = "Scene 2",
    [3] = "Scene 3",
    [4] = "Scene 4",
    [5] = "Scene 5",
    [6] = "Scene 6",
    [7] = "Scene 7",
    [8] = "Scene 8",
    [9] = "Scene 9",
    [10] = "Scene 10",
    [11] = "Scene 11",
    [12] = "Scene 12",
    [13] = "Scene 13",
    [14] = "Scene 14",
    [15] = "Scene 15",
    [16] = "Scene 16",
    [238] = "Rocker 0xEE",
    [239] = "Rocker 0xEF",
    [254] = "Load 0xFE",
    [255] = "Load 0xFF"
}

local vs_egress = {
    [0] = "disable blink warn",
    [1] = "enable blink warn",
    [255] = "ignored"
}

local vs_schedule_mode = {
    [100] = "After Hours",
    [255] = "Normal Hours"
}

local vs_override_time = {
    [0] = "no override",
    [255] = "ignored"
}

local vs_action = {
    [0] = "Scene 1",
    [1] = "Scene 2",
    [2] = "Scene 3",
    [3] = "Scene 4",
    [4] = "Scene 5",
    [5] = "Scene 6",
    [6] = "Scene 7",
    [7] = "Scene 8",
    [8] = "Scene 9",
    [9] = "Scene 10",
    [10] = "Scene 11",
    [11] = "Scene 12",
    [12] = "Scene 13",
    [13] = "Scene 14",
    [14] = "Scene 15",
    [240] = "Goto Level",
    [250] = "Blink",
    [255] = "Relinquish"
}

local vs_lm_class = {
    [0] = "NONE",
    [1] = "SWITCH",
    [2] = "SENSOR",
    [3] = "DAYLIGHT",
    [4] = "PHOTOCELL",
    [5] = "PLUGLOAD",
    [6] = "LOAD",
    [7] = "SHADE",
    [8] = "IR",
    [9] = "REMOTE",
    [10] = "BACNET",
    [11] = "PARTITION",
    [15] = "SENSOR SWITCH"
}

local vs_lm_type = {
    [0] = "ALL",
    [5] = "BC_300",
    [10] = "SW_100",
    [11] = "SW_101",
    [12] = "SW_102",
    [13] = "SW_103",
    [14] = "SW_104",
    [15] = "SW_105",
    [16] = "SW_108",
    [19] = "DM_101",
    [20] = "DM_102",
    [29] = "TS_100",
    [32] = "IO_101",
    [40] = "PC_100",
    [41] = "UC_100",
    [42] = "DC_100",
    [43] = "PX_100",
    [44] = "DX_100",
    [45] = "UC_200",
    [46] = "IO_201",
    [48] = "CC_100",
    [50] = "DW_101",
    [51] = "DW_102",
    [52] = "PW_101",
    [53] = "PW_102",
    [58] = "PD_102",
    [70] = "LS_400",
    [71] = "LS_500",
    [72] = "LS_600",
    [90] = "IO_301",
    [102] = "PL_101",
    [103] = "PL_201",
    [104] = "PL_202",
    [105] = "PL_201DK",
    [107] = "PL_202DK",
    [108] = "RC_2CREE1",
    [110] = "RC_101",
    [111] = "RC_102",
    [112] = "RC_211",
    [113] = "RC_212",
    [114] = "RC_213",
    [117] = "RC_221",
    [118] = "RC_222",
    [121] = "RC_231",
    [124] = "RC_114",
    [145] = "PANEL",
    [150] = "IR_100",
    [152] = "IO_102",
    [153] = "PS_104",
    [155] = "RH_101",
    [156] = "RH_102",
    [157] = "RH_105",
    [160] = "FSP_201",
    [161] = "FSP_211",
    [255] = "CLASS"
}

local vs_bridge = {
    [0] = "None",
    [1] = "BACnet",
    [2] = "ZigBee",
    [3] = "LonWorks"
}

local vs_noyes = {
    [1] = "No",
    [2] = "Yes"
}

local vs_offon = {
    [1] = "off",
    [2] = "on"
}

local vs_empty = {
    [1] = "empty",
    [2] = "not empty"
}

local vs_schedule = {
    [1] = "normal hours",
    [2] = "after hours"
}

local vs_enabled = {
    [1] = "disabled",
    [2] = "enabled"
}

local vs_multicast = {
    [0] = "Load",
    [1] = "Scene",
    [2] = "Zone",
    [3] = "BACnet"
}

local vs_short_command = {
    [0] = "None",
    [1] = "Ping",
    [2] = "Goto",
    [3] = "Ramp Up",
    [4] = "Ramp Down",
    [5] = "Stop",
    [6] = "Who Is",
    [7] = "Data Set",
    [8] = "Up",
    [9] = "Down",
    [10] = "Schedule"
}

local vs_donglecode = {
    [0] = "No Error",
    [1] = "Preamble 1 Error",
    [2] = "Preamble 2 Error",
    [3] = "Checksum Error",
    [4] = "Timeout Error",
    [8] = "Other Family Error"
}

local vs_bootcmd = {
    [0x0D] = "Acknowledge",
    [0x41] = "[A]ddress Set",
    [0x42] = "[B]lock Write Flash",
    [0x45] = "[E]xit",
    [0x53] = "[S]Programmer",
    [0x56] = "[V]ersion",
    [0x61] = "[a]uto increment",
    [0x62] = "[b]lock load query",
    [0x65] = "[e]rase chip",
    [0x67] = "[g]block read",
    [0x6e] = "safety [n]et",
    [0x73] = "[s]ignature",
    [0x75] = "[u]nlock"
}

local vs_group_trigger = {
    [0] = "Local",
    [1] = "Button",
    [2] = "Schedule",
    [3] = "Dark/Light",
    [4] = "Occupancy/Vacancy",
    [5] = "Local Button",
    [6] = "Terminal",
    [7] = "Status",
    [8] = "Remote"
}

-- Fields
f.donglecode = ProtoField.uint8("irb.donglecode", "donglecode", base.DEC, vs_donglecode)
f.deltadelay = ProtoField.uint16("irb.deltadelay", "deltadelay", base.DEC)
f.preamble1 = ProtoField.uint8("irb.preamble1", "preamble1", base.HEX)
f.preamble2 = ProtoField.uint8("irb.preamble2", "preamble2", base.HEX)
f.family = ProtoField.uint8("irb.family", "family", base.HEX)
f.family_type = ProtoField.uint8("irb.family.type", "family type", base.DEC, nil, 0xE0)
f.family_amode = ProtoField.uint8("irb.family.amode", "address mode", base.DEC, nil, 0x18)
f.family_ir = ProtoField.uint8("irb.family.ir", "IR direction", base.DEC, nil, 0x06)
f.seqno = ProtoField.uint8("irb.seqno", "seqno", base.DEC)
f.srcaddr = ProtoField.uint32("irb.srcaddr", "srcaddr", base.DEC)
f.dstaddr = ProtoField.uint32("irb.dstaddr", "dstaddr", base.DEC)
f.pkttype = ProtoField.uint8("irb.pkttype", "pkttype", base.DEC, vs_fc)
f.datalen = ProtoField.uint8("irb.datalen", "datalen", base.DEC)
f.multicast = ProtoField.uint32("irb.multicast", "multicast", base.DEC, vs_multicast, 0x000000C0)

f.sfc = ProtoField.uint8("irb.sfc", "SFC", base.DEC, vs_sfc)

f.arb_device = ProtoField.uint8("irb.arb.device", "device type", base.DEC, vs_lm_type)
f.arb_numload = ProtoField.uint8("irb.arb.numload", "load count", base.DEC)
f.arb_bridge = ProtoField.uint8("irb.arb.bridge", "bridge type", base.DEC, vs_bridge)

f.png_loads_all = ProtoField.uint8("irb.png.loads_all", "all loads", base.DEC)
f.png_loads = ProtoField.uint8("irb.png.loads", "loads except plugloads", base.DEC)
f.png_lock = ProtoField.uint8("irb.png.lock", "PnG Lock Level", base.DEC)

f.load_ack_index = ProtoField.uint8("irb.load_ack.index", "Load Index", base.DEC)
f.load_ack_settings = ProtoField.uint8("irb.load_ack.settings", "Load Ack Settings", base.HEX)
f.load_ack_settings_rbl = ProtoField.bool("irb.load_ack.settings.rbl", "Relay Bearing Load", 8, vs_noyes, 0x80)
f.load_ack_settings_rs = ProtoField.bool("irb.load_ack.settings.rs", "Relay Status", 8, vs_offon, 0x40)
f.load_ack_settings_dcl = ProtoField.bool("irb.load_ack.settings.dcl", "Dimming Capable Load", 8, vs_noyes, 0x20)
f.load_ack_settings_sts = ProtoField.bool("irb.load_ack.settings.sts", "Sensor Table State", 8, vs_empty, 0x10)
f.load_ack_settings_dl = ProtoField.bool("irb.load_ack.settings.dl", "Legacy Daylight Signal", 8, vs_offon, 0x08)
f.load_ack_settings_on = ProtoField.bool("irb.load_ack.settings.on", "Sensor Mode Auto On", 8, nil, 0x04)
f.load_ack_settings_ah = ProtoField.bool("irb.load_ack.settings.ah", "Normal or After Hours", 8, vs_schedule, 0x02)
f.load_ack_settings_bw = ProtoField.bool("irb.load_ack.settings.bw", "Blink Warn Enabled", 8, vs_enabled, 0x01)
f.load_ack_target_level = ProtoField.uint8("irb.load_ack.target_level", "Target Load Level", base.DEC, vs_level)
f.load_ack_priority = ProtoField.uint8("irb.load_ack.priority", "Priority", base.DEC, vs_priority)
f.load_ack_scene = ProtoField.uint8("irb.load_ack.scene", "Scene ID", base.DEC)
f.load_ack_profile = ProtoField.uint8("irb.load_ack.profile", "Room Profile", base.DEC)
f.load_ack_grace = ProtoField.uint8("irb.load_ack.grace", "Grace Time Countdown", base.DEC)
f.load_ack_direction = ProtoField.uint8("irb.load_ack.direction", "Ramp Direction", base.DEC, vs_dimmer_command)
f.load_ack_ramp = ProtoField.uint8("irb.load_ack.ramp", "Ramp Rate", base.DEC)
f.load_ack_fade = ProtoField.uint8("irb.load_ack.fade", "Fade Time", base.DEC)
f.load_ack_current_level = ProtoField.uint8("irb.load_ack.current_level", "Current Load Level", base.DEC, vs_level)
f.load_ack_timeout = ProtoField.uint8("irb.load_ack.timeout", "Override Time Countdown Minutes", base.DEC)
f.load_ack_scene_active = ProtoField.uint16("irb.load_ack.scene_active", "Scene Active Table", base.HEX)
f.load_ack_scene_table = ProtoField.uint16("irb.load_ack.scene_table", "Scene Bindings Table", base.HEX)
f.load_ack_limits = ProtoField.uint8("irb.load_ack.limits", "Dimming Limits", base.HEX)
f.load_ack_limits_shed = ProtoField.bool("irb.load_ack.limits.shed", "Load Shed", 8, nil, 0x01)
f.load_ack_limits_low = ProtoField.bool("irb.load_ack.limits.low", "Low Trim", 8, nil, 0x02)
f.load_ack_limits_high = ProtoField.bool("irb.load_ack.limits.high", "High Trim", 8, nil, 0x04)
f.load_ack_limits_lamp = ProtoField.bool("irb.load_ack.limits.lamp", "Lamp Lumen", 8, nil, 0x08)
f.load_ack_limits_burn = ProtoField.bool("irb.load_ack.limits.burn", "Burn-in", 8, nil, 0x10)
f.load_ack_limits_polarity = ProtoField.bool("irb.load_ack.limits.polarity", "Polarity", 8, nil, 0x20)
f.load_ack_limits_override = ProtoField.bool("irb.load_ack.limits.override", "Override", 8, nil, 0x40)
f.load_ack_limits_disabled = ProtoField.bool("irb.load_ack.limits.disabled", "Out of Service", 8, nil, 0x80)

f.load_shed_level = ProtoField.uint8("irb.load_shed.level", "Shed Level", base.DEC, vs_level)
f.load_shed_mode = ProtoField.uint8("irb.load_shed.mode", "Shed Mode", base.DEC, vs_shed_mode)
f.load_shed_origin = ProtoField.uint8("irb.load_shed.origen", "Shed Origin", base.DEC)
f.load_shed_timeout = ProtoField.uint8("shed.timeout", "Shed Timeout Minutes", base.DEC)

f.set_107_1 = ProtoField.uint8("set.107.1", "Button Index", base.DEC)
f.set_107_2 = ProtoField.uint8("set.107.2", "Button Mode", base.DEC, vs_switch_button_mode)
f.set_107_3 = ProtoField.uint8("set.107.3", "Button Fade Rate", base.DEC)
f.set_107_4 = ProtoField.uint8("set.107.4", "Button Ramp Rate", base.DEC)
f.set_107_5 = ProtoField.uint8("set.107.5", "Button Value ON", base.DEC, vs_level)
f.set_107_6 = ProtoField.uint8("set.107.6", "Button Value OFF", base.DEC, vs_level)
f.set_107_7 = ProtoField.uint8("set.107.7", "Button Time Delay", base.DEC)
f.set_107_8 = ProtoField.uint8("set.107.8", "Button Momentary Mode", base.DEC, vs_button_momentary_mode)
f.set_107_9 = ProtoField.uint8("set.107.9", "Button Priority", base.DEC)
f.set_107_10 = ProtoField.uint8("set.107.10", "Button LED Level", base.DEC)
f.set_107_12 = ProtoField.uint8("set.107.12", "Button Scene Lock", base.DEC, vs_button_scene_lock)
f.set_107_13 = ProtoField.uint8("set.107.13", "Button Fade ON", base.DEC)
f.set_107_14 = ProtoField.uint8("set.107.14", "Button Fade OFF", base.DEC)

f.set_125_1 = ProtoField.uint8("set.125.1", "Output Index", base.DEC)
f.set_125_2 = ProtoField.uint8("set.125.2", "Profile Index", base.DEC)
f.set_125_3 = ProtoField.uint8("set.125.3", "Scene Index", base.DEC)
f.set_125_4 = ProtoField.uint8("set.125.4", "Number of Pairs", base.DEC)
f.set_125_level = ProtoField.uint8("set.125.level", "Load Level", base.DEC, vs_level)
f.set_125_fade = ProtoField.uint8("set.125.fade", "Load Fade Time", base.DEC)

f.set_130_1 = ProtoField.uint24("set.130.1", "BACnet Device ID", base.DEC)
f.set_130_4 = ProtoField.uint8("set.130.4", "BACnet MS/TP MAC", base.DEC)
f.set_130_5 = ProtoField.uint8("set.130.5", "BACnet MS/TP Baud", base.DEC)
f.set_130_6 = ProtoField.uint8("set.130.6", "BACnet MS/TP Max_Master", base.DEC)
f.set_130_7 = ProtoField.uint8("set.130.7", "BACnet MS/TP MAC Actual", base.DEC)
f.set_130_8 = ProtoField.uint8("set.130.8", "IRB Poll Interval Minutes", base.DEC)
f.set_130_9 = ProtoField.uint16("set.130.9", "Room Square Feet", base.DEC)

f.load_table = ProtoField.uint64("irb.load_table", "Load Table", base.HEX)
f.load_table_1 = ProtoField.bool("irb.load_table.1","Loads 1-8", 8, vs_offon, 0xFF)
f.load_table_2 = ProtoField.bool("irb.load_table.2","Loads 9-16", 8, vs_offon, 0xFF)
f.load_table_3 = ProtoField.bool("irb.load_table.3","Loads 17-24", 8, vs_offon, 0xFF)
f.load_table_4 = ProtoField.bool("irb.load_table.4","Loads 25-32", 8, vs_offon, 0xFF)
f.load_table_5 = ProtoField.bool("irb.load_table.5","Loads 33-40", 8, vs_offon, 0xFF)
f.load_table_6 = ProtoField.bool("irb.load_table.6","Loads 41-48", 8, vs_offon, 0xFF)
f.load_table_7 = ProtoField.bool("irb.load_table.7","Loads 49-56", 8, vs_offon, 0xFF)
f.load_table_8 = ProtoField.bool("irb.load_table.8","Loads 56-64", 8, vs_offon, 0xFF)
f.load_table_command = ProtoField.uint8("irb.load_table.command", "Load Table Command", base.DEC, vs_short_command)

f.group_id = ProtoField.uint16("irb.group.id", "Group ID", base.DEC)
f.group_action = ProtoField.uint8("irb.group.action", "Group Action", base.DEC, vs_level)
f.group_priority = ProtoField.uint8("irb.group.priority", "Group Priority", base.DEC, vs_priority)
f.group_local = ProtoField.uint8("irb.group.local", "Group Local", base.DEC, vs_group_local)
f.group_trigger = ProtoField.uint8("irb.group.trigger", "Group Trigger", base.DEC, vs_group_trigger)
f.group_trigger_index = ProtoField.uint8("irb.group.trigger_index", "Group Trigger Index", base.DEC)

f.schedule_mode = ProtoField.uint8("irb.schedule.mode", "Schedule Mode", base.DEC, vs_schedule_mode)
f.schedule_sensor_override = ProtoField.uint8("irb.schedule.sensor_override", "Sensor Override", base.DEC, vs_sensor_mode)
f.schedule_button_override = ProtoField.uint8("irb.schedule.button_override", "Button Override", base.DEC, vs_button_mode)
f.schedule_egress_override = ProtoField.uint8("irb.schedule.egress_override", "Egress Override", base.DEC, vs_egress)
f.schedule_override_time = ProtoField.uint8("irb.schedule.override_time", "Override Time", base.DEC, vs_override_time)
f.schedule_channel = ProtoField.uint8("irb.schedule.channel", "Channel", base.DEC)
f.schedule_time_delay = ProtoField.uint8("irb.schedule.time_delay", "Time Delay Minutes", base.DEC, vs_override_time)

f.short_address_command = ProtoField.uint8("irb.cmd", "Short Address Command", base.DEC, vs_short_command)
f.cmd_goto_priority = ProtoField.uint8("irb.cmd.goto.priority", "Command Priority", base.HEX)
f.cmd_goto_level = ProtoField.uint8("irb.cmd.goto.level", "Command Level", base.DEC, vs_level)
f.cmd_goto_timeout = ProtoField.uint8("irb.cmd.goto.timeout", "Command Timeout (minutes)", base.DEC)
f.cmd_goto_origin = ProtoField.uint8("irb.cmd.goto.origin", "Command Origin", base.DEC)
f.cmd_goto_ramp = ProtoField.uint8("irb.cmd.goto.ramp", "Command Fade Rate", base.DEC)
f.cmd_goto_fade = ProtoField.uint8("irb.cmd.goto.fade", "Command Fade Time", base.DEC)
f.cmd_goto_action = ProtoField.uint8("irb.cmd.goto.action", "Command Action", base.DEC, vs_action)
f.cmd_goto_sensor = ProtoField.uint8("irb.cmd.goto.sensor", "Sensor Command", base.DEC, vs_level)

f.mac_class = ProtoField.uint8("irb.mac.class", "MAC Class", base.DEC, vs_lm_class)
f.mac_type = ProtoField.uint8("irb.mac.type", "MAC Type", base.DEC, vs_lm_type)

f.channels = ProtoField.uint8("irb.channels", "Channels", base.DEC)

f.png_output = ProtoField.uint8("irb.png.output", "PnG Output", base.DEC)
f.png_address = ProtoField.uint8("irb.png.address", "PnG Short Address", base.DEC)
f.load_settings = ProtoField.uint8("irb.png.address", "PnG Settings", base.HEX)
f.load_settings_pxm = ProtoField.bool("irb.load_settings.pxm", "Sensor Mode", 8, vs_noyes, 0x01)
f.load_settings_swm = ProtoField.bool("irb.load_settings.swm", "Switch Mode", 8, vs_noyes, 0x02)
f.load_settings_leg = ProtoField.bool("irb.load_settings.leg", "Legacy Sensor", 8, vs_noyes, 0x04)
f.load_settings_dl = ProtoField.bool("irb.load_settings.dl", "Daylighting", 8, vs_noyes, 0x08)

f.power_milliamps = ProtoField.uint16("irb.power.milliamps", "Milliamps", base.DEC)
f.power_volts = ProtoField.uint16("irb.power.volts", "Volts", base.DEC)
f.power_watts = ProtoField.uint16("irb.power.watts", "Watts", base.DEC)
f.power_pf = ProtoField.uint8("irb.power.pf", "Power Factor", base.DEC)
f.power_baseline = ProtoField.uint16("irb.power.baseline", "Baseline Watts", base.DEC)

f.pdu = ProtoField.bytes("irb.pdu", "IRB Payload")

f.bootcmd = ProtoField.uint8("irb.bootcmd", "boot command", base.DEC, vs_bootcmd)
f.bootrsp = ProtoField.string("irb.bootrsp", "boot response")
f.bootdata = ProtoField.bytes("irb.bootrsp", "boot data")
f.bootaddr = ProtoField.uint16("irb.bootaddr", "chip address")
f.bootmac = ProtoField.uint32("irb.bootmac", "serial number")

f.lrc = ProtoField.uint8("irb.lrc", "LRC Checksum", base.HEX)

-- Dissector
function irb.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "IRB"
    local dongle = buffer(0,3)
    local dongletree = tree:add(irb, dongle(0,3), "IRB Dongle")
    local donglecode = dongle(0,1):uint()
    dongletree:add(f.donglecode, dongle(0,1))
    dongletree:add(f.deltadelay, dongle(1,2))
    if (donglecode ~= 0) then
        if (donglecode == 3) then
            dongletree:add_expert_info(PI_CHECKSUM, PI_ERROR)
        else
            dongletree:add_expert_info(PI_MALFORMED, PI_ERROR)
        end
    else
        local irb_len = 0
        local family = bit.band(buffer(5,1):uint(),0xE0)
        if (family == 0xE0) then
            -- BOOTLOADER
            local irb_len_max = buffer:len() - 3
            irb_len = 4 + buffer(6,1):uint()
            if (irb_len > irb_len_max) then
                irb_len = irb_len_max
            end
            local boot_buf = buffer(3, irb_len)
            dlm_bootloader_dissector(boot_buf, pinfo, tree)
        end
        if (family == 0xA0) then
            -- DLM
            local irb_len_max = buffer:len() - 3
            local pdulen = buffer(16,1):uint()
            irb_len = 14 + pdulen
            if (irb_len > irb_len_max) then
                irb_len = irb_len_max
            end
            local irb_buf = buffer(3, irb_len)
            dlm_dissector(irb_buf, pinfo, tree)
        end
        local lrc_offset = 3 + irb_len;
        local lrc_offset_max = buffer:len() - 1
        if (lrc_offset > lrc_offset_max) then
            lrc_offset = lrc_offset_max
        end
        local lrc = buffer(lrc_offset, 1)
        local lrc_tree = tree:add(irb, lrc, "LRC")
        lrc_tree:add(f.lrc, lrc)
    end
end

function dlm_bootloader_dissector(tvb, pinfo, tree)
    local dissector_name = "Bootloader"
    pinfo.cols.info = dissector_name
    local header = tvb(0,4)
    local headertree = tree:add(irb, header(0,4), "Bootloader")
    headertree:add(f.preamble1, header(0,1))
    headertree:add(f.preamble2, header(1,1))
    local family_bytes = header(2,1)
    local family_tree = headertree:add(f.family, family_bytes)
    family_tree:add(f.family_type, family_bytes)
    family_tree:add(f.family_amode, family_bytes)
    family_tree:add(f.family_ir, family_bytes)
    headertree:add(f.datalen, header(3,1))
    local pdulen = header(3,1):uint()
    if (pdulen > 0) then
        local pdulenmax = tvb:len() - 4
        if (pdulen > pdulenmax) then
            headertree:add_expert_info(PI_MALFORMED, PI_ERROR,
                "datalen exceeds packet size")
            pdulen = pdulenmax
        end
        local pdu = tvb(4,pdulen)
        local pdutree = tree:add(irb, pdu, "Bootloader PDU")
        local opcode = pdu(0,1):uint()
        local fc_string = "Command " .. opcode
        local pduname = vs_bootcmd[opcode] or fc_string
        if (((opcode == 0x0D) and (pdulen <= 1)) or
            ((opcode == 0x41) and (pdulen <= 3)) or
            ((opcode == 0x42) and (pdulen <= 4)) or
            ((opcode == 0x45) and (pdulen <= 1)) or
            ((opcode == 0x53) and (pdulen <= 1)) or
            ((opcode == 0x56) and (pdulen <= 1)) or
            ((opcode == 0x61) and (pdulen <= 1)) or
            ((opcode == 0x62) and (pdulen <= 1)) or
            ((opcode == 0x65) and (pdulen <= 3)) or
            ((opcode == 0x67) and (pdulen <= 4)) or
            ((opcode == 0x6E) and (pdulen <= 3)) or
            ((opcode == 0x73) and (pdulen <= 1)) or
            ((opcode == 0x75) and (pdulen <= 5))) then
            pinfo.cols.info = dissector_name .. ":" .. pduname
            pdutree:add(f.bootcmd, pdu(0,1))
            if (opcode == 0x41) then
                pdutree:add(f.bootaddr, pdu(1,2))
            end
            if (opcode == 0x75) then
                pdutree:add(f.bootmac, pdu(1,4))
            end
        else
            if (pdulen <= 10) then
                pinfo.cols.info = dissector_name .. ":" .. "Response"
                pdutree:add(f.bootrsp, pdu(0,pdulen))
            else
                pinfo.cols.info = dissector_name .. ":" .. "Data"
                pdutree:add(f.bootdata, pdu(0,pdulen))
            end
        end
    end
end

function dlm_dissector(tvb, pinfo, tree)
    local header = tvb(0,14)
    local opcode = header(12,1):uint()
    local fc_string = "FC-" .. opcode
    local pduname = vs_fc[opcode] or fc_string
    local pdu_text = "Function Code: " .. pduname .. " (" .. opcode .. ")"
    local srcaddr = header(4,4):uint()
    local src_text = "Src: " .. srcaddr
    local dstaddr = header(8,4):uint()
    local dst_text = "Dst: " .. dstaddr
    hdr_text = pdu_text .. ", " .. src_text .. ", " .. dst_text
    local headertree = tree:add(irb, header(0,14), "IRB Header,", hdr_text)
    headertree:add(f.preamble1, header(0,1))
    headertree:add(f.preamble2, header(1,1))
    local family_bytes = header(2,1)
    local family_tree = headertree:add(f.family, family_bytes)
    family_tree:add(f.family_type, family_bytes)
    family_tree:add(f.family_amode, family_bytes)
    family_tree:add(f.family_ir, family_bytes)
    local seqno = header(3,1)
    headertree:add(f.seqno, seqno)

    headertree:add(f.srcaddr, header(4,4))
    pinfo.cols.src = header(4,4):uint()
    headertree:add(f.dstaddr, header(8,4))
    pinfo.cols.dst = header(8,4):uint()
    headertree:add(f.pkttype, header(12,1))
    headertree:add(f.datalen, header(13,1))

    local seqno_string = "[" .. seqno .. "] "
    pinfo.cols.info = seqno_string .. pduname

    local pdulen = header(13,1):uint();
    if (pdulen > 0) then
        local pdulenmax = tvb:len() - 14
        if (pdulen > pdulenmax) then
            headertree:add_expert_info(PI_MALFORMED, PI_ERROR,
                "datalen exceeds packet size")
            pdulen = pdulenmax
        end
        local pdu = tvb(14,pdulen)
        local pdutree = tree:add(f.pdu, pdu)
        if pduname == "Arbitrate Request" then
            pdutree:add(f.arb_device, pdu(0,1))
            pdutree:add(f.arb_numload, pdu(1,1))
            pdutree:add(f.arb_bridge, pdu(2,1))
        end
        if pduname == "PnG Configure" then
            pdutree:add(f.png_loads_all, pdu(0,1))
            pdutree:add(f.png_loads, pdu(1,1))
        end
        if pduname == "PnG Deny" then
            pdutree:add(f.png_lock, pdu(0,1))
        end
        if pduname == "Group Control" then
            pdutree:add(f.group_id, pdu(0,2))
            pdutree:add(f.group_action, pdu(2,1))
            pdutree:add(f.group_priority, pdu(3,1))
            pdutree:add(f.group_local, pdu(4,1))
            if (pdulen > 5) then
                pdutree:add(f.group_trigger, pdu(5,1))
            end
            if (pdulen > 6) then
                pdutree:add(f.group_trigger_index, pdu(6,1))
            end
        end
        if pduname == "Group Status" then
            pdutree:add(f.group_id, pdu(0,2))
            pdutree:add(f.group_action, pdu(2,1))
            if (pdulen > 3) then
                pdutree:add(f.group_trigger, pdu(3,1))
            end
        end
        if pduname == "Set" or pduname == "Get" then
            pdutree:add(f.sfc, pdu(0,1))
            local sfc = pdu(0,1):uint()
            local sfc_string = "SFC-" .. sfc
            local sfcname = vs_sfc[sfc] or sfc_string
            pinfo.cols.info = seqno_string .. pduname .. " " .. sfcname
            if pduname == "Set" then
                if sfcname == "BACnet Module Features" then
                    pdutree:add(f.set_130_1, pdu(1,3))
                    pdutree:add(f.set_130_4, pdu(4,1))
                    pdutree:add(f.set_130_5, pdu(5,1))
                    pdutree:add(f.set_130_6, pdu(6,1))
                    pdutree:add(f.set_130_7, pdu(7,1))
                    if (pdulen > 8) then
                        pdutree:add(f.set_130_8, pdu(8,1))
                    end
                    if (pdulen > 9) then
                        pdutree:add(f.set_130_9, pdu(9,2))
                    end
                end
                if sfcname == "Button Features" then
                    pdutree:add(f.set_107_1, pdu(1,1))
                    pdutree:add(f.set_107_2, pdu(2,1))
                    pdutree:add(f.set_107_3, pdu(3,1))
                    pdutree:add(f.set_107_4, pdu(4,1))
                    pdutree:add(f.set_107_5, pdu(5,1))
                    pdutree:add(f.set_107_6, pdu(6,1))
                    pdutree:add(f.set_107_7, pdu(7,1))
                    pdutree:add(f.set_107_8, pdu(8,1))
                    pdutree:add(f.set_107_9, pdu(9,1))
                    pdutree:add(f.set_107_10, pdu(10,1))
                    pdutree:add(f.set_107_12, pdu(12,1))
                    pdutree:add(f.set_107_13, pdu(13,1))
                    pdutree:add(f.set_107_14, pdu(14,1))
                end
                if sfcname == "Load ID" then
                    pdutree:add(f.png_output, pdu(1,1))
                    pdutree:add(f.png_address, pdu(2,1))
                    if (pdulen > 3) then
                        load_settings(pdu(3,1), pdutree)
                    end
                end
                if sfcname == "Load Scene" then
                    pdutree:add(f.set_125_1, pdu(1,1))
                    pdutree:add(f.set_125_2, pdu(2,1))
                    pdutree:add(f.set_125_3, pdu(3,1))
                    pdutree:add(f.set_125_4, pdu(4,1))
                    local pairs = pdu(4,1):uint()
                    local level_offset = 5
                    local fade_offset = 6
                    while (pairs > 0) do
                        pdutree:add(f.set_125_level, pdu(level_offset,1))
                        pdutree:add(f.set_125_fade, pdu(fade_offset,1))
                        level_offset = level_offset + 2
                        fade_offset = fade_offset + 2
                        pairs = pairs - 1
                    end
                end
                if sfcname == "Load Power" then
                end
                if sfcname == "Load Label" then
                end
                if sfcname == "Load Features" then
                end
                if sfcname == "Load Mode" then
                end
                if sfcname == "Load Priority Array" then
                end
                if sfcname == "Load Reference Current" then
                end
                if sfcname == "Load Scene Enabled" then
                end
                if sfcname == "NAK" then
                end
            end
        end
        if pduname == "Short Address" then
            local multicast_type = bit.band(dstaddr, 0x000000C0)
            local identifier = bit.band(dstaddr, 0x0000000F)
            if (multicast_type == 0x00) then
                -- load address multicast
                local load_number = identifier + 1
                local short_command = pdu(0,1):uint()
                local short_command_name = vs_short_command[short_command] or short_command
                pinfo.cols.info = seqno_string .. pduname .. ":" .. " Load " .. load_number .. "-" ..  short_command_name
                pdutree:add(f.short_address_command, pdu(0,1))
                local short_pdu_len = pdulen - 1
                local short_pdu = pdu(1, short_pdu_len)
                irb_short_command(short_pdu, pdutree, short_command_name)
            end
            if (multicast_type == 0x40) then
                -- scene address multicast
                local scene_number = identifier + 1
                local short_command = pdu(0,1):uint()
                local short_command_name = vs_short_command[short_command] or short_command
                pinfo.cols.info = seqno_string .. pduname .. ":" .. " Scene " .. scene_number .. "-" ..  short_command_name
                pdutree:add(f.short_address_command, pdu(0,1))
                local short_pdu_len = pdulen - 1
                local short_pdu = pdu(1, short_pdu_len)
                irb_short_command(short_pdu, pdutree, short_command_name)
            end
        end
        if pduname == "Load Table" then
            local short_command = pdu(8,1):uint()
            local short_command_name = vs_short_command[short_command] or short_command
            pinfo.cols.info = seqno_string .. pduname .. "-" .. short_command_name
            irb_load_table(pdu, pdutree)
            pdutree:add(f.load_table_command, pdu(8,1))
            local short_pdu_len = pdulen - 9
            local short_pdu = pdu(9, short_pdu_len)
            irb_short_command(short_pdu, pdutree, short_command_name)
        end
        if pduname == "Sensor Goto" then
            irb_load_table(pdu, pdutree)
            if (pdulen > 9) then
                pdutree:add(f.cmd_goto_level, pdu(8,1))
                pdutree:add(f.cmd_goto_sensor, pdu(9,1))
            else
                pdutree:add(f.cmd_goto_level, pdu(8,1))
            end
        end
        if pduname == "Ack Load" then
            local load_number = pdu(0,1):uint() + 1
            pinfo.cols.info = seqno_string .. pduname .. " " .. load_number
            pdutree:add(f.load_ack_index, pdu(0,1))
            load_ack_settings(pdu(1,1), pdutree)
            pdutree:add(f.load_ack_target_level, pdu(2,1))
            pdutree:add(f.load_ack_priority, pdu(3,1))
            pdutree:add(f.load_ack_scene, pdu(4,1))
            pdutree:add(f.load_ack_profile, pdu(5,1))
            pdutree:add(f.load_ack_grace, pdu(6,1))
            pdutree:add(f.load_ack_direction, pdu(7,1))
            pdutree:add(f.load_ack_ramp, pdu(8,1))
            pdutree:add(f.load_ack_fade, pdu(9,1))
            pdutree:add(f.load_ack_current_level, pdu(10,1))
            pdutree:add(f.load_ack_timeout, pdu(11,1))
            if (pdulen > 12) then
                pdutree:add(f.load_ack_scene_active, pdu(12,2))
                pdutree:add(f.load_ack_scene_table, pdu(13,2))
            end
            if (pdulen > 16) then
                local limits_byte = pdu(16,1)
                local limits_tree = pdutree:add(f.load_ack_limits, limits_byte)
                limits_tree:add(f.load_ack_limits_shed, limits_byte)
                limits_tree:add(f.load_ack_limits_low, limits_byte)
                limits_tree:add(f.load_ack_limits_high, limits_byte)
                limits_tree:add(f.load_ack_limits_lamp, limits_byte)
                limits_tree:add(f.load_ack_limits_burn, limits_byte)
                limits_tree:add(f.load_ack_limits_polarity, limits_byte)
                limits_tree:add(f.load_ack_limits_override, limits_byte)
                limits_tree:add(f.load_ack_limits_disabled, limits_byte)
            end
        end
        if pduname == "Schedule Request" then
            local schedule_mode = pdu(8,1):uint()
            local mode_name = vs_schedule_mode[schedule_mode] or schedule_mode
            pinfo.cols.info = seqno_string .. pduname .. "-" .. mode_name
            irb_load_table(pdu, pdutree)
            pdutree:add(f.schedule_mode, pdu(8,1))
            pdutree:add(f.schedule_sensor_override, pdu(9,1))
            pdutree:add(f.schedule_button_override, pdu(10,1))
            pdutree:add(f.schedule_egress_override, pdu(11,1))
            pdutree:add(f.schedule_override_time, pdu(12,1))
            pdutree:add(f.schedule_channel, pdu(13,1))
            pdutree:add(f.schedule_time_delay, pdu(13,1))
        end
        if pduname == "Load Shed" then
            local shed_mode = pdu(9,1):uint()
            local shed_mode_name = vs_shed_mode[shed_mode] or shed_mode
            pinfo.cols.info = seqno_string .. pduname .. ", " .. "Mode=" .. shed_mode_name
            irb_load_table(pdu, pdutree)
            pdutree:add(f.load_shed_level, pdu(8,1))
            pdutree:add(f.load_shed_mode, pdu(9,1))
            pdutree:add(f.load_shed_origin, pdu(10,1))
            pdutree:add(f.load_shed_timeout, pdu(11,1))
        end
        if pduname == "MAC Report" then
            pdutree:add(f.mac_type, pdu(0,1))
            pdutree:add(f.mac_class, pdu(1,1))
        end
        if pduname == "MAC Response" then
            pdutree:add(f.mac_type, pdu(0,1))
            pdutree:add(f.mac_class, pdu(1,1))
        end
        if pduname == "Status Report" then
            pdutree:add(f.mac_type, pdu(0,1))
            pdutree:add(f.mac_class, pdu(1,1))
        end
        if pduname == "Status Response" then
            pdutree:add(f.mac_type, pdu(0,1))
            pdutree:add(f.mac_class, pdu(1,1))
            pdutree:add(f.channels, pdu(2,1))
        end
        if pduname == "Power Monitor" then
            pdutree:add(f.power_milliamps, pdu(0,2))
            pdutree:add(f.power_volts, pdu(2,2))
            pdutree:add(f.power_watts, pdu(4,2))
            pdutree:add(f.power_pf, pdu(6,1))
            pdutree:add(f.power_baseline, pdu(7,2))
        end
    end
end

function load_settings(pdu, pdutree)
    local settings_bytes = pdu(0,1)
    local settings_tree = pdutree:add(f.load_settings, settings_bytes)
    settings_tree:add(f.load_settings_pxm, settings_bytes)
    settings_tree:add(f.load_settings_swm, settings_bytes)
    settings_tree:add(f.load_settings_leg, settings_bytes)
    settings_tree:add(f.load_settings_dl, settings_bytes)
end

function load_ack_settings(pdu, pdutree)
    local settings_bytes = pdu(0,1)
    local settings_tree = pdutree:add(f.load_ack_settings, settings_bytes)
    settings_tree:add(f.load_ack_settings_rbl, settings_bytes)
    settings_tree:add(f.load_ack_settings_rs, settings_bytes)
    settings_tree:add(f.load_ack_settings_dcl, settings_bytes)
    settings_tree:add(f.load_ack_settings_sts, settings_bytes)
    settings_tree:add(f.load_ack_settings_dl, settings_bytes)
    settings_tree:add(f.load_ack_settings_on, settings_bytes)
    settings_tree:add(f.load_ack_settings_ah, settings_bytes)
    settings_tree:add(f.load_ack_settings_bw, settings_bytes)
end

function irb_load_table(pdu, pdutree)
    local load_table_bytes = pdu(0,8)
    local load_table_tree = pdutree:add(f.load_table, load_table_bytes)
    load_table_tree:add(f.load_table_1, pdu(0,1))
    load_table_tree:add(f.load_table_2, pdu(1,1))
    load_table_tree:add(f.load_table_3, pdu(2,1))
    load_table_tree:add(f.load_table_4, pdu(3,1))
    load_table_tree:add(f.load_table_5, pdu(4,1))
    load_table_tree:add(f.load_table_6, pdu(5,1))
    load_table_tree:add(f.load_table_7, pdu(6,1))
    load_table_tree:add(f.load_table_8, pdu(7,1))
end

function irb_short_command(pdu, pdutree, short_command_name)
    if short_command_name == "Goto" then
        pdutree:add(f.cmd_goto_priority, pdu(0,1))
        pdutree:add(f.cmd_goto_level, pdu(1,1))
        pdutree:add(f.cmd_goto_timeout, pdu(2,1))
        pdutree:add(f.cmd_goto_origin, pdu(3,1))
        pdutree:add(f.cmd_goto_ramp, pdu(4,1))
        pdutree:add(f.cmd_goto_fade, pdu(5,1))
    end
    if short_command_name == "Ramp Up" then
        pdutree:add(f.cmd_goto_priority, pdu(0,1))
        pdutree:add(f.cmd_goto_ramp, pdu(1,1))
        pdutree:add(f.cmd_goto_origin, pdu(2,1))
    end
    if short_command_name == "Ramp Down" then
        pdutree:add(f.cmd_goto_priority, pdu(0,1))
        pdutree:add(f.cmd_goto_ramp, pdu(1,1))
        pdutree:add(f.cmd_goto_origin, pdu(2,1))
    end
    if short_command_name == "Stop" then
        pdutree:add(f.cmd_goto_priority, pdu(0,1))
        pdutree:add(f.cmd_goto_origin, pdu(1,1))
    end
    if short_command_name == "Up" then
        pdutree:add(f.cmd_goto_priority, pdu(0,1))
        pdutree:add(f.cmd_goto_ramp, pdu(1,1))
        pdutree:add(f.cmd_goto_origin, pdu(2,1))
    end
    if short_command_name == "Down" then
        pdutree:add(f.cmd_goto_ramp, pdu(0,1))
        pdutree:add(f.cmd_goto_origin, pdu(1,1))
    end
    if short_command_name == "Data Set" then
    end
end

local wtap_encap = DissectorTable.get("wtap_encap")
wtap_encap:add(wtap.USER0,irb)

-- PrivateTransfer hook into existing BACnet dissector
local pt = Proto("BACnet-PT", "PrivateTransfer")
local ptf = pt.fields
ptf.lrc = ProtoField.uint8("irb.lrc", "LRC Checksum", base.HEX)
ptf.tag1 = ProtoField.uint8("bacapp.pt.tag1", "Context Tag 1", base.HEX)
ptf.tag2open = ProtoField.uint8("bacapp.pt.tag2open", "Opening Tag 2", base.HEX)
ptf.apptag = ProtoField.bytes("bacapp.pt.apptag", "Application Tag")
ptf.appdata = ProtoField.bytes("bacapp.pt.appdata", "Application Data")
ptf.tag2close = ProtoField.uint8("bacapp.pt.tag2close", "Closing Tag 2", base.HEX)
ptf.service = ProtoField.uint16("bacapp.pt.service", "Service number", base.DEC)
ptf.group_id = ProtoField.uint16("bacapp.pt.group_id", "Group ID", base.DEC)
ptf.level = ProtoField.uint8("bacapp.pt.level", "Level", base.DEC, vs_level)
ptf.command = ProtoField.uint8("bacapp.pt.command", "Command", base.DEC, vs_level)
ptf.priority = ProtoField.uint8("bacapp.pt.priority", "Priority", base.DEC, vs_priority)
ptf.trigger = ProtoField.uint8("bacapp.pt.trigger", "Group Trigger", base.DEC, vs_group_trigger)
ptf.trigger_index = ProtoField.uint8("bacapp.pt.trigger_index", "Group Trigger Index", base.DEC)
ptf.fade_rate = ProtoField.uint8("bacapp.pt.fade_rate", "Fade Rate", base.DEC)
ptf.fade_time = ProtoField.uint8("bacapp.pt.fade_time", "Fade Time", base.DEC)
ptf.mac = ProtoField.uint32("bacapp.pt.mac", "Serial Number", base.DEC)
ptf.button = ProtoField.uint8("bacapp.pt.button", "Button Index", base.DEC)
ptf.mode = ProtoField.uint8("bacapp.pt.mode", "Button Mode", base.DEC)
ptf.zone = ProtoField.uint8("bacapp.pt.zone", "Zone", base.DEC)

-- decodes BACnet tag.
-- Public variables tag_len, len_value_tag, tag_number and context_specific
function tag_header(tvb, tvb_offset, pinfo, tree)
    tag_len = 1
    local lvt_offset = tvb_offset
    tag_info = 0
    local tag = tvb(lvt_offset,1)
    len_value_tag = bit.band(tag:uint(),0x07)
    -- debug
    -- local tag_tree = tree:add(pt, tag, "Len Value Tag", len_value_tag)
	-- To solve the problem of lvt values of 6/7 being indeterminate
	-- it can mean open/close tag or length of 6/7 after the length is
	-- computed below - store whole tag info, not just context bit.
    context_specific = bit.band(tag:uint(),0x08)
    if (context_specific == 0x08) then
        tag_info = bit.band(tag:uint(),0x07)
    end
    tag_number = bit.rshift(tag:uint(), 4)
    extended_tag_number = bit.band(tag:uint(),0xF0)
    if (extended_tag_number == 0xF0) then
        lvt_offset = lvt_offset + 1
        local tag = tvb(lvt_offset,1)
        tag_number = tag:uint()
        tag_len = tag_len + 1
        -- debug
        -- local tag_tree = tree:add(pt, tag, "Extended Tag", tag_number, tag_len)
    end
    if (len_value_tag == 5) then
        -- extended value tag
        lvt_offset = lvt_offset + 1
        local tag = tvb(lvt_offset,1)
        tag_value = tag:uint()
        tag_len = tag_len + 1
        if (tag_value == 254) then
            lvt_offset = lvt_offset + 1
            local tag = tvb(lvt_offset,2)
            len_value_tag = tag:uint()
            tag_len = tag_len + 2
        end
        if (tag_value == 255) then
            lvt_offset = lvt_offset + 1
            local tag = tvb(lvt_offset,4)
            len_value_tag = tag:uint()
            tag_len = tag_len + 4
        end
        if ((tag_value ~= 254) and (tag_value ~= 255)) then
            len_value_tag = tag_value;
        end
    end
end

function pt.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "BACnet-WattStopper"
    local tvb_offset = 0
    local service_number = 0
    local service_offset = 0
    local service_len = 0
    local service_tree = tree
    local service_text = "Service Data"
    tag_header(tvb, tvb_offset, pinfo, tree)
    if ((context_specific == 0x08) and (tag_number == 1)) then
        -- calculate all the pieces
        local service_number_len = tag_len + len_value_tag
        local service_number_buf = tvb(tvb_offset, service_number_len)
        local tag_buf = tvb(tvb_offset, tag_len)
        tvb_offset = tvb_offset + tag_len
        local value_buf = tvb(tvb_offset, len_value_tag)
        tvb_offset = tvb_offset + len_value_tag
        service_number = value_buf:uint()
        local srv_text = "(" .. service_number .. ")"
        -- now start printing pieces
        local tag_tree = tree:add(pt, service_number_buf, "Service Number", srv_text)
        tag_tree:add(ptf.tag1, tag_buf)
        tag_tree:add(ptf.service, value_buf)
        service_offset = tvb_offset
        service_len = tvb:len() - tvb_offset
        local service_data = tvb(service_offset, service_len)
        service_tree = tree:add(pt, service_data, service_text)
    end
    if ((service_number == 1) or
        (service_number == 2) or
        (service_number == 3)) then
        pinfo.cols.protocol = "PT->IRB"
    end
    if (service_number == 5) then
        pinfo.cols.protocol = "IRB->PT"
    end
    if ((service_number == 1) or
        (service_number == 2) or
        (service_number == 3) or
        (service_number == 5)) then
        tag_header(tvb, tvb_offset, pinfo, tree)
        if ((context_specific == 0x08) and
            (tag_number == 2) and
            (tag_info == 6))  then
            -- opening tag
            local tag_buf = tvb(tvb_offset, tag_len)
            tvb_offset = tvb_offset + tag_len
            -- application data
            tag_header(tvb, tvb_offset, pinfo, tree)
            if (context_specific == 0x00) then
                service_tree:add(ptf.tag2open, tag_buf)
                local apptag_buf = tvb(tvb_offset, tag_len)
                service_tree:add(ptf.apptag, apptag_buf)
                local app_data_offset = tvb_offset + tag_len
                local app_data_len = len_value_tag
                local app_data = tvb(app_data_offset, app_data_len)
                if (tag_number == 6) then
                    -- octetstring
                    local irb_tree = service_tree:add(pt, app_data, "IRB Message")
                    local family = bit.band(app_data(2,1):uint(),0xE0)
                    if (family == 0xE0) then
                        dlm_bootloader_dissector(app_data, pinfo, irb_tree)
                    end
                    if (family == 0xA0) then
                        dlm_dissector(app_data, pinfo, irb_tree)
                        local dlm_text = service_text .. ", IRB " .. hdr_text
                        service_tree:set_text(dlm_text)
                    end
                    local lrc_offset = app_data_offset + app_data_len - 1;
                    local lrc = tvb(lrc_offset, 1)
                    local lrc_tree = irb_tree:add(pt, lrc, "LRC")
                    lrc_tree:add(ptf.lrc, lrc)
                end
                if (tag_number ~= 6) then
                    service_tree:add(ptf.appdata, app_data)
                end
                tvb_offset = tvb_offset + tag_len + len_value_tag;
                -- closing tag
                tag_header(tvb, tvb_offset, pinfo, tree)
                tag_buf = tvb(tvb_offset, tag_len)
                service_tree:add(ptf.tag2close, tag_buf)
            end
        end
    end
    if (service_number == 4) then
        pinfo.cols.protocol = "PT->LMBC"
        pinfo.cols.info = "LMBC: IRB Tunnel Heartbeat"
    end
    if (service_number == 20) then
        pinfo.cols.protocol = "PT->LMBC"
        pinfo.cols.info = "LMBC: Close IRB Tunnel"
    end
    if (service_number == 100) then
        pinfo.cols.protocol = "PT->LMBC"
        pinfo.cols.info = "LMBC: Simulation"
    end
    if (service_number == 120) then
        pinfo.cols.protocol = "PT->LMBC"
        pinfo.cols.info = "LMBC: ReinitializeDevice"
    end
    if (service_number == 200) then
        pinfo.cols.protocol = "PT->COV"
        pinfo.cols.info = "LMBC: ChangeOfValue"
    end
    if (service_number == 300) then
        pinfo.cols.protocol = "PT->Group"
        pinfo.cols.info = "LMBC: Group Control"
    end
    if (service_number == 301) then
        pinfo.cols.protocol = "PT->Group"
        pinfo.cols.info = "LMBC: Group Status"
    end
    if (service_number == 302) then
        pinfo.cols.protocol = "PT->Group"
        pinfo.cols.info = "LMBC: Group Occupancy Sensor"
    end
    if (service_number == 303) then
        pinfo.cols.protocol = "PT->Group"
        pinfo.cols.info = "LMBC: Group Button"
    end
    if ((service_number == 300) or
        (service_number == 301) or
        (service_number == 302) or
        (service_number == 303)) then
        tag_header(tvb, tvb_offset, pinfo, tree)
        if ((context_specific == 0x08) and
            (tag_number == 2) and
            (tag_info == 6)) then
            -- opening tag
            local open_tag_buf = tvb(tvb_offset, tag_len)
            service_tree:add(ptf.tag2open, open_tag_buf)
            tvb_offset = tvb_offset + tag_len
            -- parse the service data for application data
            parsing_data = 1
            while (parsing_data > 0) do
                -- loop to parse the application tagged values
                tag_header(tvb, tvb_offset, pinfo, tree)
                local apptag_buf = tvb(tvb_offset, tag_len)
                service_tree:add(ptf.apptag, apptag_buf)
                if (context_specific == 0x00) then
                    if (tag_number == 2) then
                        -- unsigned
                        local app_data_offset = tvb_offset + tag_len
                        local app_data_len = len_value_tag
                        local app_data = tvb(app_data_offset, app_data_len)
                        if (parsing_data == 1) then
                            service_tree:add(ptf.group_id, app_data)
                        elseif (parsing_data == 2) then
                            if ((service_number == 300) or
                                (service_number == 301) or
                                (service_number == 303)) then
                                service_tree:add(ptf.level, app_data)
                            elseif (service_number == 302) then
                                service_tree:add(ptf.command, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        elseif (parsing_data == 3) then
                            if ((service_number == 300) or
                                (service_number == 303)) then
                                service_tree:add(ptf.priority, app_data)
                            elseif (service_number == 302) then
                                service_tree:add(ptf.level, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        elseif (parsing_data == 4) then
                            if ((service_number == 300) or
                                (service_number == 303)) then
                                service_tree:add(ptf.trigger, app_data)
                            elseif (service_number == 302) then
                                service_tree:add(ptf.zone, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        elseif (parsing_data == 5) then
                            if ((service_number == 300) or
                                (service_number == 303)) then
                                service_tree:add(ptf.trigger_index, app_data)
                            elseif (service_number == 302) then
                                service_tree:add(ptf.mac, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        elseif (parsing_data == 6) then
                            if (service_number == 303) then
                                service_tree:add(ptf.fade_rate, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        elseif (parsing_data == 7) then
                            if (service_number == 303) then
                                service_tree:add(ptf.fade_time, app_data)
                            else
                                service_tree:add(pt, app_data, "Unsigned Integer")
                            end
                        else
                            service_tree:add(pt, app_data, "Unsigned Integer")
                        end
                    else
                        local app_data_offset = tvb_offset + tag_len
                        local app_data_len = len_value_tag
                        local app_data = tvb(app_data_offset, app_data_len)
                        local irb_tree = service_tree:add(pt, app_data,
                            "Unknown Value")
                    end
                    tvb_offset = tvb_offset + tag_len + len_value_tag
                    parsing_data = parsing_data + 1
                end
                if (context_specific == 0x08) then
                    if ((tag_number == 2) and
                        (tag_info == 7)) then
                        -- closing tag
                        local close_tag_buf = tvb(tvb_offset, tag_len)
                        service_tree:add(ptf.tag2close, close_tag_buf)
                        -- break out of our loop
                        parsing_data = 0
                    end
                    tvb_offset = tvb_offset + tag_len
                end
            end
        end
    end
    if (service_number == 200) then
        tag_header(tvb, tvb_offset, pinfo, tree)
        if ((context_specific == 0x08) and
            (tag_number == 2) and
            (tag_info == 6)) then
            -- opening tag
            local open_tag_buf = tvb(tvb_offset, tag_len)
            service_tree:add(ptf.tag2open, open_tag_buf)
            tvb_offset = tvb_offset + tag_len
            -- parse the service data for application data
            parsing_data = 1
            while (parsing_data > 0) do
                -- loop to parse the application tagged values
                tag_header(tvb, tvb_offset, pinfo, tree)
                local apptag_buf = tvb(tvb_offset, tag_len)
                service_tree:add(ptf.apptag, apptag_buf)
                if (context_specific == 0x00) then
                    if (tag_number == 2) then
                        -- unsigned
                        local app_data_offset = tvb_offset + tag_len
                        local app_data_len = len_value_tag
                        local app_data = tvb(app_data_offset, app_data_len)
                        if (parsing_data == 1) then
                            service_tree:add(ptf.mac, app_data)
                        elseif (parsing_data == 2) then
                            service_tree:add(ptf.button, app_data)
                        elseif (parsing_data == 3) then
                            service_tree:add(ptf.level, app_data)
                        elseif (parsing_data == 4) then
                            service_tree:add(ptf.mode, app_data)
                        elseif (parsing_data == 5) then
                            service_tree:add(ptf.priority, app_data)
                        elseif (parsing_data == 6) then
                            service_tree:add(ptf.group_id, app_data)
                        else
                            service_tree:add(pt, app_data, "Unsigned Integer")
                        end
                    else
                        local app_data_offset = tvb_offset + tag_len
                        local app_data_len = len_value_tag
                        local app_data = tvb(app_data_offset, app_data_len)
                        local irb_tree = service_tree:add(pt, app_data,
                            "Unknown Value")
                    end
                    tvb_offset = tvb_offset + tag_len + len_value_tag
                    parsing_data = parsing_data + 1
                end
                if (context_specific == 0x08) then
                    if ((tag_number == 2) and
                        (tag_info == 7)) then
                        -- closing tag
                        local close_tag_buf = tvb(tvb_offset, tag_len)
                        service_tree:add(ptf.tag2close, close_tag_buf)
                        -- break out of our loop
                        parsing_data = 0
                    end
                    tvb_offset = tvb_offset + tag_len
                end
            end
        end
    end
    if (service_number == 9600) then
        pinfo.cols.protocol = "PT->LMBC"
        pinfo.cols.info = "LMBC: Baud Rate"
    end
end

local bacnet_pt_table = DissectorTable.get("bacapp.vendor_identifier")
bacnet_pt_table:add (86, pt)

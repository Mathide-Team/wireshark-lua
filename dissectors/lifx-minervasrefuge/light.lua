-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://codeberg.org/MinervasRefuge/LIFX-Wireshark (src/light.lua),
-- commit 49b1a390abb75f264dd3e5dd824c0c40c9272e72 du 11/06/2022.
-- Licence amont : GPL-3.0-only (COPYING amont) — voir README.md.
require("util")

local m = LDMOD {
   -- Light
   [107] = "LightState",
   [108] = "StateLightPower",
   [121] = "StateInfrared",
   [144] = "StateHevCycle",
   [147] = "StateHevCycleConfiguration",
   [149] = "StateLastHevCycleResult",

   -- Light [get]
   [101] = "GetColour",
   [116] = "GetLightPower",
   [120] = "GetInfrared",
   [142] = "GetHevCycle",
   [145] = "GetHevCycleConfiguration",
   [148] = "GetLastHevCycleResult",

   -- Light [set]
   [102] = "SetColour",
   [103] = "SetWaveform",
   [117] = "SetLightPower",
   [119] = "SetWaveformOptional",
   [122] = "SetInfrared",
   [143] = "SetHevCycle",
   [146] = "SetHevCycleConfiguration"
}

-- LightState
BuildProtoFieldGroup {
   mod=m, prefix = "ls_", key="lifx.LightState",
   
   {id="hue"       , fn="uint16"  , "hue"        , "Hue"        , DEC}     ,
   {id="satu"      , fn="uint16"  , "saturation" , "Saturation" , DEC}     ,
   {id="bright"    , fn="uint16"  , "brightness" , "Brightness" , DEC}     ,
   {id="kelvin"    , fn="uint16"  , "kelvin"     , "Kelvin"     , DEC}     ,
   {id="reserved"  , fn="bytes"   , "reserved1"  , "Reserved1"  , SPACE}   ,
   {id="power"     , fn="uint16"  , "power"      , "Power"      , DEC}     ,
   {id="label"     , fn="stringz" , "label"      , "Label"      , UNICODE} ,
   {id="reserved2" , fn="bytes"   , "reserved2"  , "Reserved2"  , SPACE}
}

---- GET

---- SET

-- Set Colour
BuildProtoFieldGroup {
   mod=m, prefix = "sc_", key="lifx.SetColour",
   
   {id="reserved" , fn="bytes"  , "reserved1"  , "Reserved1"  , SPACE} ,
   {id="hue"      , fn="uint16" , "hue"        , "Hue"        , DEC}   ,
   {id="satu"     , fn="uint16" , "saturation" , "Saturation" , DEC}   ,
   {id="bright"   , fn="uint16" , "brightness" , "Brightness" , DEC}   ,
   {id="kelvin"   , fn="uint16" , "kelvin"     , "Kelvin"     , DEC}   ,
   {id="durat"    , fn="uint32" , "duration"   , "Duration"   , DEC}  
}

-- SetWaveformOptional
BuildProtoFieldGroup {
   mod=m, prefix = "swo_", key="lifx.SetWaveformOptional",

   {id="reserved1" , fn="bytes"  , "reserved1"      , "Reserved1"      , SPACE} ,
   {id="trans"     , fn="uint8"  , "transient"      , "Transient"      , nil    , N_TF}  ,
   {id="hue"       , fn="uint16" , "hue"            , "Hue"            , DEC}   ,
   {id="satu"      , fn="uint16" , "saturation"     , "Saturation"     , DEC}   ,
   {id="bright"    , fn="uint16" , "brightness"     , "Brightness"     , DEC}   ,
   {id="kelvin"    , fn="uint16" , "kelvin"         , "Kelvin"         , DEC}   ,
   {id="period"    , fn="uint32" , "period"         , "Period"         , DEC}   ,
   {id="cycles"    , fn="float"  , "cycles"         , "Cycles"         , DEC}   ,
   {id="skrat"     , fn="int16"  , "skew_ratio"     , "Skew Ratio"     , DEC}   ,
   {id="wfrm"      , fn="uint8"  , "waveform"       , "Waveform"       , nil    , {[0]="SAW" , "SINE" , "HALF_SINE" , "TRIANGLE" , "PULSE"}} ,
   {id="shue"      , fn="uint8"  , "set_hue"        , "Set Hue"        , nil    , N_TF}  ,
   {id="ssatu"     , fn="uint8"  , "set_saturation" , "Set Saturation" , nil    , N_TF}  ,
   {id="sbright"   , fn="uint8"  , "set_brightness" , "Set Brightness" , nil    , N_TF}  ,
   {id="skelvin"   , fn="uint8"  , "set_kelvin"     , "Set Kelvin"     , nil    , N_TF}
}
   

-- Dissectors

addDissector(107, m, function (t, b, pinfo) -- LightState
   local length = b:len()
   le(t, m.ls_hue     , b(0, 2)):append_text(u16Percent(b(0,2)))
   le(t, m.ls_satu    , b(2, 2)):append_text(u16Percent(b(2,2)))
   le(t, m.ls_bright  , b(4, 2)):append_text(u16Percent(b(4,2)))
   le(t, m.ls_kelvin  , b(6, 2)):append_text("K")
   le(t, m.ls_reserved, b(8, 2))
   le(t, m.ls_power   , b(10, 2)):append_text(u16Percent(b(10,2)))
   local sz = b(12, length-12)
   le(t, m.ls_label, sz)
   local index = sz:strsize(UNICODE) - 1
   le(t, m.ls_reserved2, b(index, 8))
end)

-- GET

ignore(101, m) -- GetColour

-- SET

addDissector(102, m, function (t, b, pinfo) -- SetColour
   le(t, m.sc_reserved, b(0, 1))
   le(t, m.sc_hue     , b(1, 2)):append_text(u16Percent(b(1,2)))
   le(t, m.sc_satu    , b(3, 2)):append_text(u16Percent(b(3,2)))
   le(t, m.sc_bright  , b(5, 2)):append_text(u16Percent(b(5,2)))
   le(t, m.sc_kelvin  , b(7, 2)):append_text("K")
   le(t, m.sc_durat   , b(9, 4)):append_text("ms")
end)

addDissector(119, m, function (t, b, pinfo) -- SetWaveformOptional
                le(t, m.swo_reserved1, b(0,1))
                le(t, m.swo_trans, b(1,1))
                le(t, m.swo_hue, b(2,2)):append_text(u16Percent(b(2,2)))
                le(t, m.swo_satu, b(4,2)):append_text(u16Percent(b(4,2)))
                le(t, m.swo_bright, b(6,2)):append_text(u16Percent(b(6,2)))
                le(t, m.swo_kelvin, b(8,2)):append_text("K")
                le(t, m.swo_period, b(10,4)):append_text("ms")
                le(t, m.swo_cycles, b(14,4))
                le(t, m.swo_skrat, b(18, 2))
                le(t, m.swo_wfrm, b(20, 1))
                le(t, m.swo_shue, b(21, 1))
                le(t, m.swo_ssatu, b(22, 1))
                le(t, m.swo_sbright, b(23, 1))
                le(t, m.swo_skelvin, b(24,1))
end)

return m

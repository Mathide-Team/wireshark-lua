-- SPDX-License-Identifier: GPL-3.0-or-later
-- Importé de https://github.com/vortextube/Perfect-Prime-CO2000 (co2000.lua),
-- commit 09c98a03425359b2d8712a0dd5790ae568585638 du 17/01/2017.
-- Licence amont : GPL-3.0-or-later (LICENSE amont) — voir README.md.
-- co2000.lua
-- Wireshark dissector for the C02000 CO2/Temp./RH Data Logger
-- from Perfect Prime.
--     https://perfect-prime.com/collections/data-logger-temperature-humidity-co2/products/co2000-perfectprime
--     https://perfect-prime.com/pages/downloads-perfectprime
--
-- Copyright (c) 2016 Charles Robert Hill <hill.charles.robert@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.
--
-- Usage: wireshark -X lua_script:co2000.lua
--
-- Thanks to these excellent scripts as examples of USB dissectors for
-- Wireshark.
--     https://github.com/danielkitta/sigrok-util/blob/master/debug/sysclk-lwla/sysclk-lwla-dissector.lua
--     https://github.com/karlp/swopy/blob/master/stlink2.ws.lua
--

debug("starting co2000.lua\n")

-- declare the protocol for Wireshark
co2000_proto = Proto("co2000", "HT2000 USB Protocol")
debug("co2000_proto registered\n")

local f_usb_ep_num = Field.new("usb.endpoint_number.endpoint")

local function getstring(fi)
    local ok, val = pcall(tostring, fi)
    if not ok then val = "(unknown)" end
    return val
end

function co2000_proto.dissector(buffer, pinfo, tree)

    debug("co2000_proto dissector called")

	pinfo.cols["protocol"] = "C02000"

	-- create protocol tree
    local tree_c02000 = tree:add(co2000_proto, buffer(),"C02000 Protocol Data")   
    
    -- get the length of the buffer
    -- 32 bytes is the size of the data buffer containing environment data
    local buffer_length = buffer:len()
    
    if buffer_length == 32 then
    
        local temp_buff = buffer(7,2)
        local rh_buff   = buffer(9,2)
        local co2_buff  = buffer(24,2)
        
        local temp  = (temp_buff:uint() / 10) - 40
        local rh    = rh_buff:uint() / 10
        local co2   = co2_buff:uint()
    
        tree_c02000:add(temp_buff,"Temperature: " .. temp)
        tree_c02000:add(rh_buff,"Humidity: " .. rh)
        tree_c02000:add(co2_buff,"C02: " .. co2)
    end

end

function co2000_proto.init()
    debug("co2000_proto init called")

    usb_table_control = DissectorTable.get("usb.control")
    usb_table_control:add(0xff, co2000_proto)
    usb_table_control:add(0xffff, co2000_proto)

end


--[[


data payload
===============================================================================

                           1                     2                          3          
 0 1 2 3 4   5 6   7 8   9 0   1 2 3 4 5 6 7 8 9 0 1 2 3   4 5   6 7   8 9  0 1
--------------------------------------------------------------------------------
05587e365e  02e4  0278  01a9  0190032000640384b0030007d0  050c  0000  07d0  0000
05016a9994  02e4  0292  0210  0190032000640384b0030007d0  058b  0000  03e8  0000
                  temp    rh                               co2       alarm

temperature          = ((half word at bytes 7,   8 lsb last) / 10) - 40
relative humidity    = ((half word at bytes 9,  10 lsb last) / 10
carbon dioxide (ppm) =   half word at bytes 24, 25 lsb last
alarm                =   half word at bytes 30, 31 lsb last

lsusb output
===============================================================================
Bus 002 Device 008: ID 10c4:82cd Cygnal Integrated Products, Inc. 

dmesg output
===============================================================================
[3059462.674079] usb 1-2: USB disconnect, device number 15
[4134065.924027] usb 2-2: new full-speed USB device number 6 using uhci_hcd
[4134066.073545] usb 2-2: New USB device found, idVendor=10c4, idProduct=82cd
[4134066.073550] usb 2-2: New USB device strings: Mfr=1, Product=2,
SerialNumber=0
[4134066.073553] usb 2-2: Product: HT2000
[4134066.073556] usb 2-2: Manufacturer: SLAB
[4134066.088765] hid-generic 0003:10C4:82CD.0005: hiddev0,hidraw3: USB HID
v1.01 Device [SLAB HT2000] on usb-0000:00:1d.0-2/input0

lsusb -D /dev/bus/usb/002/008 output
===============================================================================
Device: ID 10c4:82cd Cygnal Integrated Products, Inc. 
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               1.10
  bDeviceClass            0 
  bDeviceSubClass         0 
  bDeviceProtocol         0 
  bMaxPacketSize0        64
  idVendor           0x10c4 Cygnal Integrated Products, Inc.
  idProduct          0x82cd 
  bcdDevice            0.00
  iManufacturer           1 SLAB
  iProduct                2 HT2000
  iSerial                 0 
  bNumConfigurations      1
  Configuration Descriptor:
    bLength                 9
    bDescriptorType         2
    wTotalLength           41
    bNumInterfaces          1
    bConfigurationValue     1
    iConfiguration          0 
    bmAttributes         0x80
      (Bus Powered)
    MaxPower               64mA
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        0
      bAlternateSetting       0
      bNumEndpoints           2
      bInterfaceClass         3 Human Interface Device
      bInterfaceSubClass      0 
      bInterfaceProtocol      0 
      iInterface              0 
      Warning: Descriptor too short
        HID Device Descriptor:
          bLength                 9
          bDescriptorType        33
          bcdHID               1.01
          bCountryCode            0 Not supported
          bNumDescriptors         2
          bDescriptorType        34 Report
          wDescriptorLength     128
          bDescriptorType       123 (null)
          wDescriptorLength   26135
         Report Descriptors: 
           ** UNAVAILABLE **
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x81  EP 1 IN
        bmAttributes            3
          Transfer Type            Interrupt
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval              10
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x01  EP 1 OUT
        bmAttributes            3
          Transfer Type            Interrupt
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval              10
Device Status:     0x0000
  (Bus Powered)

  
]]--
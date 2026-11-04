-- SPDX-License-Identifier: GPL-3.0-only
-- Importé de https://github.com/schoerg/wattsonic (wattsonic.lua),
-- commit b23b660a3f18370791404ae1dea57ca3c0d0be36 du 06/08/2023.
-- Licence amont : GPL-3.0-only (LICENSE amont) — voir README.md.
-- wattsonic.lua

local wattsonic_proto = Proto("wattsonic", "Wattsonic Protocol")

local fields = {
    serial_number = ProtoField.string("wattsonic.serial_number", "Serial Number"),
    date = ProtoField.string("wattsonic.date", "Date (YY-MM-DD)"),
    soh = ProtoField.int16("wattsonic.soh", "State of Health (SOH)"),
    soc = ProtoField.int16("wattsonic.soc", "State of Charge (SOC)"),

    inverter_runtime = ProtoField.uint32("wattsonic.inverter_runtime", "Runtime"),
    inverter_temp1 = ProtoField.int16("wattsonic.inverter_temp1", "Inverter Temperature 1"),
    inverter_temp2 = ProtoField.int16("wattsonic.inverter_temp2", "Inverter Temperature 2"),
    inverter_temp3 = ProtoField.int16("wattsonic.inverter_temp3", "Inverter Temperature 3"),
    inverter_temp4 = ProtoField.int16("wattsonic.inverter_temp4", "Inverter Temperature 4"),

    pv1_voltage = ProtoField.int16("wattsonic.pv1_voltage", "PV1 Voltage"),
    pv1_current = ProtoField.int16("wattsonic.pv1_current", "PV1 Current"),
    pv2_voltage = ProtoField.int16("wattsonic.pv2_voltage", "PV2 Voltage"),
    pv2_current = ProtoField.int16("wattsonic.pv2_current", "PV2 Current"),

    battery_p = ProtoField.int16("wattsonic.battery_p", "Battery Power"),

    grid_extern = ProtoField.int16("wattsonic.grid_extern", "Grid"),
    pv = ProtoField.int16("wattsonic.pv", "PV input total power"),
    
    t_e_injected_to_grid = ProtoField.uint32("wattsonic.t_e_injected_to_grid", "Total energy injected into grid"),
    t_e_purchased_from_grid = ProtoField.uint16("wattsonic.t_e_purchased_from_grid", "Energy purchased from grid today"),
    t_e_charged_to_battery = ProtoField.uint32("wattsonic.t_e_charged_to_battery", "Total energy charged into battery"),
    t_e_discharged_from_battery = ProtoField.uint32("wattsonic.t_e_discharged_from_battery", "Total energy discharged from battery"),
    t_output_backup_port = ProtoField.uint32("wattsonic.t_output_backup_port", "Total output energy on backup port"),
    pv_generation_energy_today = ProtoField.uint16("wattsonic.pv_generation_energy_today", "PV energy generated today"),
    pv_generation_from_installation = ProtoField.uint32("wattsonic.pv_generation_from_installation", "PV total energy generated since installation"),
    total_pv_generation = ProtoField.uint32("wattsonic.total_pv_generation", "PV total energy generated"),
    loading_energy_today = ProtoField.uint16("wattsonic.loading_energy_today", "Load energy used today"),
    total_loading_energy_consumed_at_grid_side = ProtoField.uint32("wattsonic.total_loading_energy_consumed_at_grid_side", "Total loading consumed energy on grid side"),
    total_energy_purchased_from_grid_from_meter = ProtoField.uint32("wattsonic.total_energy_purchased_from_grid_from_meter", "Total energy purchased from grid from meter"),
    bms_pack_temp = ProtoField.int16("wattsonic.bms_pack_temp", "BMS Pack Temperature"),

}

local function parse_date(buffer, offset)
    local year = buffer(offset, 1):uint()
    local month = buffer(offset + 1, 1):uint()
    local day = buffer(offset + 2, 1):uint()
    
    local hour = buffer(offset + 3, 1):uint()
    local minute = buffer(offset + 4, 1):uint()
    local second = buffer(offset + 5, 1):uint()

    -- YY-MM-DD h:m:s
    local date_string = string.format("%02d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second )
    return date_string
end

wattsonic_proto.fields = fields

-- dissector
function wattsonic_proto.dissector(buffer, pinfo, tree)
    -- parse only large packets
    length = buffer:len()
    if length < 500 then return end

    -- the inverter sends stuff to port 5743
    if pinfo.dst_port == 5743 then
        pinfo.cols.protocol:set("Wattsonic")

        local subtree = tree:add(wattsonic_proto, buffer(), "Wattsonic Protocol Data")
        
        -- serial number
        local serial_number = buffer(10, 16):string()
        subtree:add(fields.serial_number, buffer(10, 16), serial_number)

        local date_string = parse_date(buffer, 26)
        subtree:add(fields.date, buffer(26, 6), date_string)
        
        local grid_extern = buffer(123, 2):int()
        local grid_field = subtree:add(fields.grid_extern, buffer(123, 2), grid_extern)
        grid_field:append_text(" W (negative = purchase)")

        local pv_generation_from_installation = buffer(161, 4):int()    
        local pv_generation_from_installation_float = pv_generation_from_installation / 10.0
        local pv_generation_from_installation_field = subtree:add(fields.pv_generation_from_installation, buffer(161, 4), pv_generation_from_installation)
        pv_generation_from_installation_field:append_text(" (" .. string.format("%.1f", pv_generation_from_installation_float) .. " kWh)")

        local inverter_runtime = buffer(165, 4):uint()
        local inverter_runtime_field = subtree:add(fields.inverter_runtime, buffer(165, 4), inverter_runtime)
        inverter_runtime_field:append_text(" hours")
        
        local pv = buffer(179, 2):int()
        local pv_field = subtree:add(fields.pv, buffer(179, 2), pv)
        pv_field:append_text(" W")

        local inverter_temp = buffer(185, 2):int()  
        local inverter_temp_float = inverter_temp / 10
        local inverter_temp_field = subtree:add(fields.inverter_temp1, buffer(185, 2), inverter_temp)
        inverter_temp_field:append_text(" (" .. string.format("%.1f", inverter_temp_float) .. " °C)")

        local inverter_temp = buffer(187, 2):int()  
        local inverter_temp_float = inverter_temp / 10
        local inverter_temp_field = subtree:add(fields.inverter_temp2, buffer(187, 2), inverter_temp)
        inverter_temp_field:append_text(" (" .. string.format("%.1f", inverter_temp_float) .. " °C)")

        local inverter_temp = buffer(189, 2):int()  
        local inverter_temp_float = inverter_temp / 10
        local inverter_temp_field = subtree:add(fields.inverter_temp3, buffer(189, 2), inverter_temp)
        inverter_temp_field:append_text(" (" .. string.format("%.1f", inverter_temp_float) .. " °C)")

        local inverter_temp = buffer(191, 2):int()  
        local inverter_temp_float = inverter_temp / 10
        local inverter_temp_field = subtree:add(fields.inverter_temp4, buffer(191, 2), inverter_temp)
        inverter_temp_field:append_text(" (" .. string.format("%.1f", inverter_temp_float) .. " °C)")

        local pv1_voltage = buffer(197, 2):int()    
        local pv1_voltage_float = pv1_voltage / 10
        local pv1_voltage_field = subtree:add(fields.pv1_voltage, buffer(197, 2), pv1_voltage)
        pv1_voltage_field:append_text(" (" .. string.format("%.1f", pv1_voltage_float) .. " V)")

        local pv1_current = buffer(199, 2):int()    
        local pv1_current_float = pv1_current / 10
        local pv1_current_field = subtree:add(fields.pv1_current, buffer(199, 2), pv1_current)
        pv1_current_field:append_text(" (" .. string.format("%.1f", pv1_current_float) .. " A)")
        
        local pv2_voltage = buffer(201, 2):int()    
        local pv2_voltage_float = pv2_voltage / 10
        local pv2_voltage_field = subtree:add(fields.pv2_voltage, buffer(201, 2), pv2_voltage)
        pv2_voltage_field:append_text(" (" .. string.format("%.1f", pv2_voltage_float) .. " V)")
        
        local pv2_current = buffer(203, 2):int()    
        local pv2_current_float = pv2_current / 10
        local pv2_current_field = subtree:add(fields.pv2_current, buffer(203, 2), pv2_current)
        pv2_current_field:append_text(" (" .. string.format("%.1f", pv2_current_float) .. " A)")
        
        
        local battery_p = buffer(417, 4):uint()
        local battery_p_field = subtree:add(fields.battery_p, buffer(417, 4), battery_p)
        battery_p_field:append_text(" W (negative = charging)")

        local t_e_purchased_from_grid = buffer(439, 2):int()    
        local t_e_purchased_from_grid_float = t_e_purchased_from_grid / 10.0
        local t_e_purchased_from_grid_field = subtree:add(fields.t_e_purchased_from_grid, buffer(439, 2), t_e_purchased_from_grid)
        t_e_purchased_from_grid_field:append_text(" (" .. string.format("%.1f", t_e_purchased_from_grid_float) .. " kWh)")

        local pv_generation_energy_today = buffer(447, 2):int() 
        local pv_generation_energy_today_float = pv_generation_energy_today / 10.0
        local pv_generation_energy_today_field = subtree:add(fields.pv_generation_energy_today, buffer(447, 2), pv_generation_energy_today)
        pv_generation_energy_today_field:append_text(" (" .. string.format("%.1f", pv_generation_energy_today_float) .. " kWh)")

        local loading_energy_today = buffer(449, 2):int()   
        local loading_energy_today_float = loading_energy_today / 10.0
        local loading_energy_today_field = subtree:add(fields.loading_energy_today, buffer(449, 2), loading_energy_today)
        loading_energy_today_field:append_text(" (" .. string.format("%.1f", loading_energy_today_float) .. " kWh)")

        local t_e_injected_to_grid = buffer(463, 4):int()   
        local t_e_injected_to_grid_float = t_e_injected_to_grid / 10.0
        local t_e_injected_to_grid_field = subtree:add(fields.t_e_injected_to_grid, buffer(463, 4), t_e_injected_to_grid)
        t_e_injected_to_grid_field:append_text(" (" .. string.format("%.1f", t_e_injected_to_grid_float) .. " kWh)")
        
        local total_energy_purchased_from_grid_from_meter = buffer(467, 4):int()    
        local total_energy_purchased_from_grid_from_meter_float = total_energy_purchased_from_grid_from_meter / 10.0
        local total_energy_purchased_from_grid_from_meter_field = subtree:add(fields.total_energy_purchased_from_grid_from_meter, buffer(467, 4), total_energy_purchased_from_grid_from_meter)
        total_energy_purchased_from_grid_from_meter_field:append_text(" (" .. string.format("%.1f", total_energy_purchased_from_grid_from_meter_float) .. " kWh)")
        
        local t_output_backup_port = buffer(471, 4):int()   
        local t_output_backup_port_float = t_output_backup_port / 10.0
        local t_output_backup_port_field = subtree:add(fields.t_output_backup_port, buffer(471, 4), t_output_backup_port)
        t_output_backup_port_field:append_text(" (" .. string.format("%.1f", t_output_backup_port_float) .. " kWh)")
        
        local t_e_charged_to_battery = buffer(475, 4):int() 
        local t_e_charged_to_battery_float = t_e_charged_to_battery / 10.0
        local t_e_charged_to_battery_field = subtree:add(fields.t_e_charged_to_battery, buffer(475, 4), t_e_charged_to_battery)
        t_e_charged_to_battery_field:append_text(" (" .. string.format("%.1f", t_e_charged_to_battery_float) .. " kWh)")
        
        local t_e_discharged_from_battery = buffer(479, 4):int()    
        local t_e_discharged_from_battery_float = t_e_discharged_from_battery / 10.0
        local t_e_discharged_from_battery_field = subtree:add(fields.t_e_discharged_from_battery, buffer(479, 4), t_e_discharged_from_battery)
        t_e_discharged_from_battery_field:append_text(" (" .. string.format("%.1f", t_e_discharged_from_battery_float) .. " kWh)")
        
        local total_pv_generation = buffer(483, 4):int()    
        local total_pv_generation_float = total_pv_generation / 10.0
        local total_pv_generation_field = subtree:add(fields.total_pv_generation, buffer(483, 4), total_pv_generation)
        total_pv_generation_field:append_text(" (" .. string.format("%.1f", total_pv_generation_float) .. " kWh)")
        
        local total_loading_energy_consumed_at_grid_side = buffer(487, 4):int() 
        local total_loading_energy_consumed_at_grid_side_float = total_loading_energy_consumed_at_grid_side / 10.0
        local total_loading_energy_consumed_at_grid_side_field = subtree:add(fields.total_loading_energy_consumed_at_grid_side, buffer(487, 4), total_loading_energy_consumed_at_grid_side)
        total_loading_energy_consumed_at_grid_side_field:append_text(" (" .. string.format("%.1f", total_loading_energy_consumed_at_grid_side_float) .. " kWh)")
        

        local soc_value = buffer(523, 2):int()  
        local soc_float = soc_value / 100.0
        local soc_field = subtree:add(fields.soc, buffer(523, 2), soc_value)
        soc_field:append_text(" (" .. string.format("%.2f", soc_float) .. "%)")

        local soh_value = buffer(525, 2):int()  
        local soh_float = soh_value / 100.0
        local soh_field = subtree:add(fields.soh, buffer(525, 2), soh_value)
        soh_field:append_text(" (" .. string.format("%.2f", soh_float) .. "%)")
        
        local bms_pack_temp = buffer(541, 2):int()  
        local bms_pack_temp_float = bms_pack_temp / 10
        local bms_pack_temp_field = subtree:add(fields.bms_pack_temp, buffer(541, 2), bms_pack_temp)
        bms_pack_temp_field:append_text(" (" .. string.format("%.1f", bms_pack_temp_float) .. " °C)")
        
    end
end

-- register dissector
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(5743, wattsonic_proto)

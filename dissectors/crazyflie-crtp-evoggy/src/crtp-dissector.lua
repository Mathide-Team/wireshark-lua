-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Importé de https://github.com/evoggy/wireshark-crazyflie (dissector/crtp-dissector.lua),
-- commit c707ffa390ad77e69e8525ffc5fa804e4f29dd4b du 21/10/2026 (dernière modification du fichier :
-- commit c707ffa390ad77e69e8525ffc5fa804e4f29dd4b du 21/10/2026).
-- Licence amont : MIT OR Apache-2.0 (README et Cargo.toml amont) — voir README.md.
-- declare our protocol
crtp = Proto("CrazyRealTimeTProtocol", "Crazy Real Time Protocol")

-- General CRTP packet fields
local f_crtp_port = ProtoField.uint8("crtp.port", "Port")
local f_crtp_channel = ProtoField.uint8("crtp.channel", "Channel")
local f_crtp_size = ProtoField.uint8("crtp.size", "Size")
local f_crtp_undecoded = ProtoField.string("crtp.undecoded", "Undecoded")
local f_crtp_safelink_up = ProtoField.uint8("crtp.safelink_up", "SafeLink Up Counter")
local f_crtp_safelink_down = ProtoField.uint8("crtp.safelink_down", "SafeLink Down Counter")

-- Specialized CRTP service fields

-- Console fields
local f_crtp_console_text = ProtoField.string("crtp.console_text", "Text", base.ASCII)

-- Parameter fields
local f_crtp_parameter_varid = ProtoField.uint16("crtp.parameter_varid", "Variable Id")
local f_crtp_parameter_type = ProtoField.string("crtp.parameter_type", "Parameter Type")
local f_crtp_parameter_group = ProtoField.string("crtp.parameter_group", "Parameter Group")
local f_crtp_parameter_name = ProtoField.string("crtp.parameter_name", "Parameter Name")
local f_crtp_parameter_count = ProtoField.uint16("crtp.parameter_count", "Parameter Count")
local f_crtp_parameter_crc = ProtoField.string("crtp.parameter_crc", "Parameter CRC")
local f_crtp_parameter_val_uint = ProtoField.uint32("crtp.parameter_val_uint", "Value uint")
local f_crtp_parameter_val_int = ProtoField.int32("crtp.parameter_val_int", "Value int")
local f_crtp_parameter_val_float = ProtoField.float("crtp.parameter_val_float", "Value float")
local f_crtp_parameter_misc_cmd = ProtoField.string("crtp.parameter_misc_cmd", "Misc Command")

-- Commander fields (Port 3)
local f_crtp_commander_roll = ProtoField.float("crtp.commander_roll", "Roll")
local f_crtp_commander_pitch = ProtoField.float("crtp.commander_pitch", "Pitch")
local f_crtp_commander_yaw = ProtoField.float("crtp.commander_yaw", "Yaw Rate")
local f_crtp_commander_thrust = ProtoField.uint16("crtp.commander_thrust", "Thrust")

-- Memory fields (Port 4)
local f_crtp_memory_cmd = ProtoField.string("crtp.memory_cmd", "Command")
local f_crtp_memory_id = ProtoField.uint8("crtp.memory_id", "Memory ID")
local f_crtp_memory_type = ProtoField.string("crtp.memory_type", "Memory Type")
local f_crtp_memory_size = ProtoField.uint32("crtp.memory_size", "Memory Size")
local f_crtp_memory_addr = ProtoField.uint64("crtp.memory_addr", "Address")
local f_crtp_memory_count = ProtoField.uint8("crtp.memory_count", "Memory Count")

-- Log fields
local f_crtp_log_varid = ProtoField.uint16("crtp.log_varid", "Variable Id")
local f_crtp_log_type = ProtoField.string("crtp.log_type", "Log Type")
local f_crtp_log_group = ProtoField.string("crtp.log_group", "Log Group")
local f_crtp_log_name = ProtoField.string("crtp.log_name", "Log Name")
local f_crtp_log_count = ProtoField.uint16("crtp.log_count", "Log Count")
local f_crtp_log_crc = ProtoField.string("crtp.log_crc", "Log CRC")
local f_crtp_log_block_id = ProtoField.uint8("crtp.log_block_id", "Block ID")
local f_crtp_log_timestamp = ProtoField.uint32("crtp.log_timestamp", "Timestamp")
local f_crtp_log_settings_cmd = ProtoField.string("crtp.log_settings_cmd", "Settings Command")

-- Localization fields (Port 6)
local f_crtp_loc_cmd = ProtoField.string("crtp.loc_cmd", "Command")
local f_crtp_loc_x = ProtoField.float("crtp.loc_x", "X")
local f_crtp_loc_y = ProtoField.float("crtp.loc_y", "Y")
local f_crtp_loc_z = ProtoField.float("crtp.loc_z", "Z")
local f_crtp_loc_qx = ProtoField.float("crtp.loc_qx", "Quaternion X")
local f_crtp_loc_qy = ProtoField.float("crtp.loc_qy", "Quaternion Y")
local f_crtp_loc_qz = ProtoField.float("crtp.loc_qz", "Quaternion Z")
local f_crtp_loc_qw = ProtoField.float("crtp.loc_qw", "Quaternion W")
local f_crtp_loc_bs_id = ProtoField.uint8("crtp.loc_bs_id", "Base Station ID")

-- Generic Setpoint fields (Port 7)
local f_crtp_generic_type = ProtoField.string("crtp.generic_type", "Setpoint Type")
local f_crtp_generic_vx = ProtoField.float("crtp.generic_vx", "Velocity X")
local f_crtp_generic_vy = ProtoField.float("crtp.generic_vy", "Velocity Y")
local f_crtp_generic_vz = ProtoField.float("crtp.generic_vz", "Velocity Z")
local f_crtp_generic_x = ProtoField.float("crtp.generic_x", "X")
local f_crtp_generic_y = ProtoField.float("crtp.generic_y", "Y")
local f_crtp_generic_z = ProtoField.float("crtp.generic_z", "Z")
local f_crtp_generic_yaw = ProtoField.float("crtp.generic_yaw", "Yaw")
local f_crtp_generic_yaw_rate = ProtoField.float("crtp.generic_yaw_rate", "Yaw Rate")
local f_crtp_generic_roll = ProtoField.float("crtp.generic_roll", "Roll")
local f_crtp_generic_pitch = ProtoField.float("crtp.generic_pitch", "Pitch")
local f_crtp_generic_thrust = ProtoField.uint16("crtp.generic_thrust", "Thrust")
local f_crtp_generic_rate_mode = ProtoField.bool("crtp.generic_rate_mode", "Rate Mode")
local f_crtp_generic_zdist = ProtoField.float("crtp.generic_zdist", "Z Distance")

-- Platform fields (Port 13)
local f_crtp_platform_cmd = ProtoField.string("crtp.platform_cmd", "Platform Command")
local f_crtp_platform_version_cmd = ProtoField.string("crtp.platform_version_cmd", "Version Command")
local f_crtp_platform_protocol_version = ProtoField.uint8("crtp.platform_protocol_version", "Protocol Version")
local f_crtp_platform_firmware_version = ProtoField.string("crtp.platform_firmware_version", "Firmware Version")
local f_crtp_platform_device_type = ProtoField.string("crtp.platform_device_type", "Device Type")
local f_crtp_platform_arm_request = ProtoField.bool("crtp.platform_arm_request", "Arm Request")

local f_crtp_setpoint_hl_command = ProtoField.string("crtp.setpoint_hl_command", "Command")
local f_crtp_setpoint_hl_retval = ProtoField.uint8("crtp.setpoint_hl_retval", "Return Value")

local f_crtp_setpoint_hl_groupmask = ProtoField.uint8("crtp.setpoint_hl_groupmask", "Group Mask")
local f_crtp_setpoint_hl_id = ProtoField.uint8("crtp.setpoint_hl_id", "Trajectory Id")

local f_crtp_setpoint_hl_height = ProtoField.float("crtp.setpoint_hl_height", "Height")
local f_crtp_setpoint_hl_yaw = ProtoField.float("crtp.setpoint_hl_yaw", "Yaw")
local f_crtp_setpoint_hl_use_yaw = ProtoField.bool("crtp.setpoint_hl_use_yaw", "Use Current Yaw")
local f_crtp_setpoint_hl_relative = ProtoField.bool("crtp.setpoint_hl_relative", "Relative")
local f_crtp_setpoint_hl_duration = ProtoField.float("crtp.setpoint_hl_duration", "Duration")
local f_crtp_setpoint_hl_timescale = ProtoField.float("crtp.setpoint_hl_timescale", "Timescale")

local f_crtp_setpoint_hl_x = ProtoField.float("crtp.setpoint_hl_x", "X")
local f_crtp_setpoint_hl_y = ProtoField.float("crtp.setpoint_hl_y", "Y")
local f_crtp_setpoint_hl_z = ProtoField.float("crtp.setpoint_hl_z", "Z")

-- Link control fields (Port 15)
local f_crtp_echo_data = ProtoField.uint32("crtp.echo_data", "Echo Data")
local f_crtp_safelink_type = ProtoField.string("crtp.safelink_type", "SafeLink")

-- All possible fields registered
crtp.fields = {
	-- General
	f_crtp_port,
	f_crtp_channel,
	f_crtp_safelink_up,
	f_crtp_safelink_down,
	f_crtp_size,
	f_crtp_undecoded,
	-- Console
	f_crtp_console_text,
	-- Parameters
	f_crtp_parameter_varid,
	f_crtp_parameter_val_uint,
	f_crtp_parameter_val_int,
	f_crtp_parameter_val_float,
	f_crtp_parameter_name,
	f_crtp_parameter_group,
	f_crtp_parameter_type,
	f_crtp_parameter_count,
	f_crtp_parameter_crc,
	f_crtp_parameter_misc_cmd,
	-- Commander
	f_crtp_commander_roll,
	f_crtp_commander_pitch,
	f_crtp_commander_yaw,
	f_crtp_commander_thrust,
	-- Memory
	f_crtp_memory_cmd,
	f_crtp_memory_id,
	f_crtp_memory_type,
	f_crtp_memory_size,
	f_crtp_memory_addr,
	f_crtp_memory_count,
	-- Logging
	f_crtp_log_varid,
	f_crtp_log_name,
	f_crtp_log_group,
	f_crtp_log_type,
	f_crtp_log_count,
	f_crtp_log_crc,
	f_crtp_log_block_id,
	f_crtp_log_timestamp,
	f_crtp_log_settings_cmd,
	-- Localization
	f_crtp_loc_cmd,
	f_crtp_loc_x,
	f_crtp_loc_y,
	f_crtp_loc_z,
	f_crtp_loc_qx,
	f_crtp_loc_qy,
	f_crtp_loc_qz,
	f_crtp_loc_qw,
	f_crtp_loc_bs_id,
	-- Generic Setpoint
	f_crtp_generic_type,
	f_crtp_generic_vx,
	f_crtp_generic_vy,
	f_crtp_generic_vz,
	f_crtp_generic_x,
	f_crtp_generic_y,
	f_crtp_generic_z,
	f_crtp_generic_yaw,
	f_crtp_generic_yaw_rate,
	f_crtp_generic_roll,
	f_crtp_generic_pitch,
	f_crtp_generic_thrust,
	f_crtp_generic_rate_mode,
	f_crtp_generic_zdist,
	-- High-level Setpoint
	f_crtp_setpoint_hl_command,
	f_crtp_setpoint_hl_retval,
	f_crtp_setpoint_hl_use_yaw,
	f_crtp_setpoint_hl_yaw,
	f_crtp_setpoint_hl_groupmask,
	f_crtp_setpoint_hl_duration,
	f_crtp_setpoint_hl_height,
	f_crtp_setpoint_hl_relative,
	f_crtp_setpoint_hl_x,
	f_crtp_setpoint_hl_y,
	f_crtp_setpoint_hl_z,
	f_crtp_setpoint_hl_id,
	f_crtp_setpoint_hl_timescale,
	-- Platform
	f_crtp_platform_cmd,
	f_crtp_platform_version_cmd,
	f_crtp_platform_protocol_version,
	f_crtp_platform_firmware_version,
	f_crtp_platform_device_type,
	f_crtp_platform_arm_request,
	-- Link Control
	f_crtp_echo_data,
	f_crtp_safelink_type,
}

local param_toc = {}
local log_toc = {}

local Links = {
	UNKNOWN = 0,
	RADIO = 1,
	USB = 2,
	UDP = 3,
}

local link = Links.UNKNOWN
local undecoded = 0
local crtp_start = 0

-- Analye port and channel and figure what service (port name / channel name)
-- we are dealing with

local Ports = {
	Console = 0x0,
	Parameters = 0x2,
	Commander = 0x3,
	Memory = 0x4,
	Logging = 0x5,
	Localization = 0x6,
	Commander_Generic = 0x7,
	Setpoint_Highlevel = 0x8,
	Platform = 0xD,
	LinkControl = 0xF,
	ALL = 0xFF
}

function get_crtp_port_channel_names(port, channel)
	local port_name = "Unknown"
	local channel_name = nil

	if port == Ports.Console and channel == 0 then
		port_name = "Console"
	elseif port == 0x02 then
		port_name = "Parameters"
		if channel == 0 then
			channel_name = "Table Of Contents"
		elseif channel == 1 then
			channel_name = "Read"
		elseif channel == 2 then
			channel_name = "Write"
		elseif channel == 3 then
			channel_name = "Misc"
		end
	elseif port == 0x03 then
		port_name = "Commander"
	elseif port == 0x04 then
		port_name = "Memory"
		if channel == 0 then
			channel_name = "Information"
		elseif channel == 1 then
			channel_name = "Read"
		elseif channel == 2 then
			channel_name = "Write"
		end
	elseif port == 0x05 then
		port_name = "Logging"
		if channel == 0 then
			channel_name = "Table Of Contents"
		elseif channel == 1 then
			channel_name = "Settings"
		elseif channel == 2 then
			channel_name = "Log data"
		end
	elseif port == 0x06 then
		port_name = "Localization"
		if channel == 0 then
			channel_name = "Position"
		elseif channel == 1 then
			channel_name = "Generic"
		end
	elseif port == 0x07 then
		port_name = "Commander Generic"
	elseif port == 0x08 then
		port_name = "Setpoint Highlevel"
	elseif port == 0x0D then
		port_name = "Platform"
		if channel == 0 then
			channel_name = "Platform Command"
		elseif channel == 1 then
			channel_name = "Version Command"
		elseif channel == 2 then
			channel_name = "App Layer"
		end
	elseif port == 0x0F then
		port_name = "Link Control"
		if channel == 0 then
			channel_name = "Echo"
		elseif channel == 1 then
			channel_name = "Link Service Source"
		elseif channel == 3 then
			channel_name = "Null Packet"
		end
	elseif port == 0xFF then
		port_name = "ALL"
	end

	return port_name, channel_name
end

function format_address(buffer)
	if link == Links.RADIO then
		addr = buffer(2, 5):bytes():tohex()
		port = buffer(7, 1):uint()

		addr = addr:gsub("..", ":%0"):sub(2)
		port = tostring(port)

		return addr .. " (" .. port .. ")"
	elseif link == Links.USB then
		-- Serial starts at byte 15 (after link_type + direction + address(12) + channel)
		serial = buffer(15, 16):string():gsub("%z+$", "")  -- trim trailing nulls
		if serial == "" then
			return "Crazyflie"
		end
		return serial
	elseif link == Links.UDP then
		-- Peer address (host:port) is in the serial field at byte 15, same layout as USB
		serial = buffer(15, 16):string():gsub("%z+$", "")  -- trim trailing nulls
		return serial
	end
end

function format_device(buffer)
	if link == Links.RADIO then
		-- Serial starts at byte 8 (after link_type + direction + address(5) + channel)
		serial = buffer(8, 16):string():gsub("%z+$", "")  -- trim trailing nulls
		if serial == "" then
			return "Radio"
		end
		return "Radio " .. serial
	elseif link == Links.USB then
		return "USB"
	elseif link == Links.UDP then
		return "UDP"
	end
end

function handle_setpoint_highlevel(tree, receive, buffer, channel, size)
	local Commands = {
		COMMAND_SET_GROUP_MASK = 0,
		COMMAND_TAKEOFF = 1,
		COMMAND_LAND = 2,
		COMMAND_STOP = 3,
		COMMAND_GO_TO = 4,
		COMMAND_START_TRAJECTORY = 5,
		COMMAND_DEFINE_TRAJECTORY = 6,
		COMMAND_TAKEOFF_2 = 7,
		COMMAND_LAND_2 = 8,
		COMMAND_TAKEOFF_WITH_VELOCITY = 9,
		COMMAND_LAND_WITH_VELOCITY = 10,
		COMMAND_SPIRAL = 11,
		COMMAND_GO_TO_2 = 12,
		COMMAND_START_TRAJECTORY_2 = 13,
	}

	local height = nil
	local duration = nil
	local yaw = nil
	local group_mask = nil
	local use_yaw = nil
	local relative = nil
	local x = nil
	local y = nil
	local z = nil
	local id = nil
	local timescale = nil

	local port_tree = tree:add(crtp, port_name)

	local cmd = buffer(crtp_start + 1, 1):uint()
	local cmd_str = "Unknown"

	if cmd == Commands.COMMAND_SET_GROUP_MASK then
		cmd_str = "Set Group Mask"

		-- struct data_set_group_mask {
		--    uint8_t groupMask;        // mask for which CFs this should apply to
		--  } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(11, 1):uint()
		end
	elseif cmd == Commands.COMMAND_TAKEOFF then
		cmd_str = "Take Off (deprecated)"
	elseif cmd == Commands.COMMAND_LAND then
		cmd_str = "Land (deprecated)"
	elseif cmd == Commands.COMMAND_STOP then
		cmd_str = "Stop"

		-- struct data_stop {
		--    uint8_t groupMask;        // mask for which CFs this should apply to
		--  } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(crtp_start + 2, 1):uint()
		end
		undecoded = undecoded - 1
	elseif cmd == Commands.COMMAND_GO_TO then
		cmd_str = "Go To"

		-- struct data_go_to {
		--    uint8_t groupMask; // mask for which CFs this should apply to
		--    uint8_t relative;  // set to true, if position/yaw are relative to current setpoint
		--    float x; // m
		--    float y; // m
		--    float z; // m
		--    float yaw; // rad
		--    float duration; // sec
		--  } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			relative = buffer(crtp_start + 3, 1):uint()
			x = buffer(crtp_start + 4, 4):le_float()
			y = buffer(crtp_start + 8, 4):le_float()
			z = buffer(crtp_start + 12, 4):le_float()
			yaw = buffer(crtp_start + 16, 4):le_float()
			duration = buffer(crtp_start + 20, 4):le_float()
			undecoded = undecoded - 24
		end
	elseif cmd == Commands.COMMAND_START_TRAJECTORY then
		cmd_str = "Start Trajectory"

		-- struct data_start_trajectory {
		--   uint8_t groupMask; // mask for which CFs this should apply to
		--   uint8_t relative;  // set to true, if trajectory should be shifted to current setpoint
		--   uint8_t reversed;  // set to true, if trajectory should be executed in reverse
		--   uint8_t trajectoryId; // id of the trajectory (previously defined by COMMAND_DEFINE_TRAJECTORY)
		--   float timescale; // time factor; 1 = original speed; >1: slower; <1: faster
		--  } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			relative = buffer(crtp_start + 3, 1):uint()
			reversed = buffer(crtp_start + 4, 1):uint()
			id = buffer(crtp_start + 5, 1):uint()
			timescale = buffer(crtp_start + 6):float()
			undecoded = undecoded - 10
		end
	elseif cmd == Commands.COMMAND_DEFINE_TRAJECTORY then
		cmd_str = "Define Trajectory"

		-- struct data_define_trajectory {
		--    uint8_t trajectoryId;
		--    struct trajectoryDescription description;
		--  } __attribute__((packed));
		if receive == 0 then
			id = buffer(crtp_start + 2, 1):uint()
			undecoded = undecoded - 1
		end
	elseif cmd == Commands.COMMAND_TAKEOFF_2 then
		cmd_str = "Take Off"

		-- struct data_takeoff_2 {
		-- uint8_t groupMask;        // mask for which CFs this should apply to
		-- float height;             // m (absolute)
		-- float yaw;                // rad
		-- bool useCurrentYaw;       // If true, use the current yaw (ignore the yaw parameter)
		-- float duration;           // s (time it should take until target height is reached)
		-- } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			height = buffer(crtp_start + 3, 4):le_float()
			yaw = buffer(crtp_start + 7, 4):le_float()
			use_yaw = buffer(crtp_start + 11, 1):uint()
			duration = buffer(crtp_start + 12, 4):le_float()
			undecoded = undecoded - 16
		end
	elseif cmd == Commands.COMMAND_LAND_2 then
		cmd_str = "Land"
		-- struct data_land_2 {
		-- uint8_t groupMask;        // mask for which CFs this should apply to
		-- float height;             // m (absolute)
		-- float yaw;                // rad
		-- bool useCurrentYaw;       // If true, use the current yaw (ignore the yaw parameter)
		-- float duration;           // s (time it should take until target height is reached)
		-- } __attribute__((packed));
		if receive == 0 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			height = buffer(crtp_start + 3, 4):le_float()
			yaw = buffer(crtp_start + 7, 4):le_float()
			use_yaw = buffer(crtp_start + 11, 1):uint()
			duration = buffer(crtp_start + 12, 4):le_float()
			undecoded = undecoded - 16
		end
	elseif cmd == Commands.COMMAND_TAKEOFF_WITH_VELOCITY then
		cmd_str = "Take Off With Velocity"
	elseif cmd == Commands.COMMAND_LAND_WITH_VELOCITY then
		cmd_str = "Land With Velocity"
	elseif cmd == Commands.COMMAND_SPIRAL then
		cmd_str = "Spiral"
		-- struct data_spiral {
		--   uint8_t groupMask;
		--   bool sideways;
		--   bool clockwise;
		--   float phi;       // rad
		--   float r0;        // m (start radius)
		--   float rf;        // m (final radius)
		--   float dz;        // m (altitude change)
		--   float duration;  // s
		-- } __attribute__((packed));
		if receive == 0 and size >= 20 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			-- sideways and clockwise are at +3 and +4
			-- phi at +5, r0 at +9, rf at +13, dz at +17, duration at +21
			undecoded = undecoded - 19
		end
	elseif cmd == Commands.COMMAND_GO_TO_2 then
		cmd_str = "Go To (v2)"
		-- struct data_go_to_2 {
		--   uint8_t groupMask;
		--   uint8_t relative;
		--   uint8_t linear;      // 0 = smooth trajectory, 1 = straight line
		--   float x; float y; float z;
		--   float yaw;
		--   float duration;
		-- } __attribute__((packed));
		if receive == 0 and size >= 24 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			relative = buffer(crtp_start + 3, 1):uint()
			-- linear at +4
			x = buffer(crtp_start + 5, 4):le_float()
			y = buffer(crtp_start + 9, 4):le_float()
			z = buffer(crtp_start + 13, 4):le_float()
			yaw = buffer(crtp_start + 17, 4):le_float()
			duration = buffer(crtp_start + 21, 4):le_float()
			undecoded = undecoded - 24
		end
	elseif cmd == Commands.COMMAND_START_TRAJECTORY_2 then
		cmd_str = "Start Trajectory (v2)"
		-- struct data_start_trajectory_2 {
		--   uint8_t groupMask;
		--   uint8_t relative;
		--   uint8_t reversed;
		--   uint8_t trajectoryId;
		--   float timescale;
		--   float timeOffset;  // s (added in v2)
		-- } __attribute__((packed));
		if receive == 0 and size >= 13 then
			group_mask = buffer(crtp_start + 2, 1):uint()
			relative = buffer(crtp_start + 3, 1):uint()
			-- reversed at +4
			id = buffer(crtp_start + 5, 1):uint()
			timescale = buffer(crtp_start + 6, 4):le_float()
			-- timeOffset at +10
			undecoded = undecoded - 13
		end
	end

	port_tree:add_le(f_crtp_setpoint_hl_command, cmd_str)
	local success = true
	if receive == 1 then
		retval = buffer(crtp_start + 4):uint()
		local success = (retval == 0) and "Success" or "Failure"
		port_tree:add_le(f_crtp_setpoint_hl_retval, retval):append_text(" (" .. success .. ")")
		undecoded = undecoded - 4
	end

	if id then
		port_tree:add_le(f_crtp_setpoint_hl_id, id)
	end
	if timescale then
		port_tree:add_le(f_crtp_setpoint_hl_timescale, timescale)
	end
	if group_mask then
		port_tree:add_le(f_crtp_setpoint_hl_groupmask, group_mask)
	end
	if relative then
		port_tree:add_le(f_crtp_setpoint_hl_relative, relative)
	end
	if height then
		port_tree:add_le(f_crtp_setpoint_hl_height, height):append_text(" (m)")
	end
	if x then
		port_tree:add_le(f_crtp_setpoint_hl_x, x)
	end
	if y then
		port_tree:add_le(f_crtp_setpoint_hl_y, y)
	end
	if z then
		port_tree:add_le(f_crtp_setpoint_hl_z, z)
	end
	if yaw then
		port_tree:add_le(f_crtp_setpoint_hl_yaw, yaw)
	end
	if use_yaw then
		port_tree:add_le(f_crtp_setpoint_hl_use_yaw, use_yaw)
	end
	if duration then
		port_tree:add_le(f_crtp_setpoint_hl_duration, duration):append_text(" (s)")
	end
end

function append_param_type(str, type)
	if #str == 0 then
		return type
	else
		return str .. " | " .. type
	end
end

function get_log_types(byte)
	type = ""

	local core = 0x20
	local byfunc = 0x40
	local group = 0x80

	num_types_map = {
		"LOG_UINT8",
		"LOG_UINT16",
		"LOG_UINT32",
		"LOG_INT8",
		"LOG_INT16",
		"LOG_INT32",
		"LOG_FLOAT",
		"LOG_FP16",
	}

	num_type = bit.band(byte, 0x0F)
	type = num_types_map[num_type]

	if bit.band(byte, core) ~= 0 then
		type = append_param_type(type, "LOG_CORE")
	end

	if bit.band(byte, byfunc) ~= 0 then
		type = append_param_type(type, "LOG_BYFUNC")
	end

	if bit.band(byte, group) ~= 0 then
		type = append_param_type(type, "LOG_GROUP")
	end

	return byte .. " (" .. type .. ")"
end

function get_param_types(byte)
	type = ""

	local ext = bit.lshift(1, 4)
	local core = bit.lshift(1, 5)
	local ronly = bit.lshift(1, 6)
	local group = bit.lshift(1, 7)

	num_type = bit.band(byte, 0x0F)
	if num_type == 0 then
		type = "PARAM_INT8"
	elseif num_type == bit.lshift(0x1, 3) then
		type = "PARAM_UINT8"
	elseif num_type == bit.bor(0x1, bit.lshift(0x1, 3)) then
		type = "PARAM_UINT16"
	elseif num_type == 0x1 then
		type = "PARAM_INT16"
	elseif num_type == 0x2 then
		type = "PARAM_INT32"
	elseif num_type == bit.bor(0x2, bit.lshift(0x1, 3)) then
		type = "PARAM_UINT32"
	elseif num_type == bit.bor(0x2, bit.lshift(0x1, 2)) then
		type = "PARAM_FLOAT"
	end

	if bit.band(byte, core) ~= 0 then
		type = append_param_type(type, "PARAM_CORE")
	end

	if bit.band(byte, ronly) ~= 0 then
		type = append_param_type(type, "PARAM_RONLY")
	end

	if bit.band(byte, group) ~= 0 then
		type = append_param_type(type, "PARAM_GROUP")
	end

	if bit.band(byte, ext) ~= 0 then
		type = append_param_type(type, "PARAM_EXTENDED")
	end

	return byte .. " (" .. type .. ")"
end

function handle_logging_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	local LogSettingsCommands = {
		[0] = "Create Block (V1)",
		[1] = "Append Block (V1)",
		[2] = "Delete Block",
		[3] = "Start Block",
		[4] = "Stop Block",
		[5] = "Reset",
		[6] = "Create Block (V2)",
		[7] = "Append Block (V2)",
	}

	-- TOC (Channel 0)
	if channel == 0 then
		message_id = buffer(crtp_start + 1, 1):le_uint()
		if message_id == 3 and receive == 1 then
			port_tree:add_le(f_crtp_log_count, buffer(crtp_start + 2, 2):le_uint())
			port_tree:add_le(f_crtp_log_crc, buffer(crtp_start + 4):bytes():tohex())
		end
		if message_id == 2 then
			-- GET_ITEM
			item = {}
			item["varid"] = buffer(crtp_start + 2, 2):le_uint()
			port_tree:add_le(f_crtp_log_varid, item["varid"])

			if receive == 1 then
				item["type"] = get_log_types(buffer(crtp_start + 4, 1):le_uint())
				item["group"] = ""
				item["name"] = ""
				full_name = buffer(crtp_start + 5):string()

				stored_group = false
				for i = 1, #full_name do
					local c = full_name:sub(i, i)
					if string.byte(c) == 0 and not stored_group then
						stored_group = true
					else
						if stored_group then
							item["name"] = item["name"] .. c
						else
							item["group"] = item["group"] .. c
						end
					end
				end

				log_toc[item["varid"]] = item
				port_tree:add_le(f_crtp_log_type, item["type"])
				port_tree:add_le(f_crtp_log_group, item["group"])
				port_tree:add_le(f_crtp_log_name, item["name"])
			end
		end
	-- Settings (Channel 1)
	elseif channel == 1 then
		if size >= 2 then
			local cmd = buffer(crtp_start + 1, 1):le_uint()
			local cmd_name = LogSettingsCommands[cmd] or "Unknown"
			port_tree:add_le(f_crtp_log_settings_cmd, cmd_name .. " (" .. cmd .. ")")

			if size >= 3 then
				local block_id = buffer(crtp_start + 2, 1):le_uint()
				port_tree:add_le(f_crtp_log_block_id, block_id)
				undecoded = undecoded - 2

				-- For Create Block V2 (cmd 6) and Append Block V2 (cmd 7)
				if (cmd == 6 or cmd == 7) and size > 3 then
					-- Contains variable IDs and types
					-- Each variable entry is 3 bytes: type (1) + varid (2)
					undecoded = undecoded - (size - 3)
				-- For Start Block (cmd 3)
				elseif cmd == 3 and size >= 4 then
					-- Period in 10ms units
					local period = buffer(crtp_start + 3, 1):le_uint() * 10
					undecoded = undecoded - 1
				end
			else
				undecoded = undecoded - 1
			end
		end
	-- Log data (Channel 2)
	elseif channel == 2 then
		if size >= 4 then
			local block_id = buffer(crtp_start + 1, 1):le_uint()
			-- Timestamp is 24-bit little-endian (3 bytes)
			local ts_low = buffer(crtp_start + 2, 1):le_uint()
			local ts_mid = buffer(crtp_start + 3, 1):le_uint()
			local ts_high = buffer(crtp_start + 4, 1):le_uint()
			local timestamp = ts_low + ts_mid * 256 + ts_high * 65536

			port_tree:add_le(f_crtp_log_block_id, block_id)
			port_tree:add_le(f_crtp_log_timestamp, timestamp):append_text(" ms")
			undecoded = undecoded - 4
			-- Remaining bytes are packed log variable values
		end
	end
end

function handle_parameter_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	local ParamMiscCommands = {
		[0] = "Set By Name",
		[1] = "Value Updated",
		[2] = "Get Extended Type",
		[3] = "Persistent Store",
		[4] = "Persistent Get State",
		[5] = "Persistent Clear",
		[6] = "Get Default Value",
	}

	-- Read or Write
	if (channel == 1 or channel == 2) and size > 2 then
		if channel == 1 then
			value_start = 4
		else
			value_start = 3
		end

		-- Add variable id
		local var_id = buffer(crtp_start + 1, 2):le_uint()
		port_tree:add_le(f_crtp_parameter_varid, var_id)

		item = param_toc[var_id]
		port_tree:add_le(f_crtp_parameter_group, item["group"])
		port_tree:add_le(f_crtp_parameter_name, item["name"])

		-- Add value
		if size > 3 then
			port_tree:add_le(f_crtp_parameter_val_uint, buffer(crtp_start + value_start):le_uint())
			port_tree:add_le(f_crtp_parameter_val_int, buffer(crtp_start + value_start):le_int())
		end
		if size >= 7 then
			port_tree:add_le(f_crtp_parameter_val_float, buffer(crtp_start + value_start):le_float())
		end
		undecoded = 0
	end
	-- TOC
	if channel == 0 then
		message_id = buffer(crtp_start + 1, 1):le_uint()
		if message_id == 3 and receive == 1 then
			port_tree:add_le(f_crtp_parameter_count, buffer(crtp_start + 2, 2):le_uint())
			port_tree:add_le(f_crtp_parameter_crc, buffer(crtp_start + 4):bytes():tohex())
		end
		if message_id == 2 then
			-- GET_ITEM
			item = {}
			item["varid"] = buffer(crtp_start + 2, 2):le_uint()
			port_tree:add_le(f_crtp_parameter_varid, item["varid"])

			if receive == 1 then
				item["type"] = get_param_types(buffer(crtp_start + 4, 1):le_uint())
				item["group"] = ""
				item["name"] = ""
				full_name = buffer(crtp_start + 5):string()

				stored_group = false
				for i = 1, #full_name do
					local c = full_name:sub(i, i)
					if string.byte(c) == 0 and not stored_group then
						stored_group = true
					else
						if stored_group then
							item["name"] = item["name"] .. c
						else
							item["group"] = item["group"] .. c
						end
					end
				end

				param_toc[item["varid"]] = item
				port_tree:add_le(f_crtp_parameter_type, item["type"])
				port_tree:add_le(f_crtp_parameter_group, item["group"])
				port_tree:add_le(f_crtp_parameter_name, item["name"])
			end
		end
	end
	-- Misc channel
	if channel == 3 and size >= 2 then
		local cmd = buffer(crtp_start + 1, 1):le_uint()
		local cmd_name = ParamMiscCommands[cmd] or "Unknown"
		port_tree:add_le(f_crtp_parameter_misc_cmd, cmd_name .. " (" .. cmd .. ")")
		undecoded = undecoded - 1

		-- For Set By Name (cmd 0), the rest is group\0name\0value
		-- For Value Updated (cmd 1), contains varid
		if cmd == 1 and size >= 4 then
			local var_id = buffer(crtp_start + 2, 2):le_uint()
			port_tree:add_le(f_crtp_parameter_varid, var_id)
			undecoded = undecoded - 2
		end
	end
end

function handle_commander_port(tree, receive, buffer, channel, size)
	-- Commander port sends RPYT (Roll, Pitch, Yaw-rate, Thrust) setpoints
	-- Format: 4 floats (roll, pitch, yaw_rate) + 1 uint16 (thrust) = 14 bytes
	local port_tree = tree:add(crtp, port_name)

	if size >= 14 then
		local roll = buffer(crtp_start + 1, 4):le_float()
		local pitch = buffer(crtp_start + 5, 4):le_float()
		local yaw_rate = buffer(crtp_start + 9, 4):le_float()
		local thrust = buffer(crtp_start + 13, 2):le_uint()

		port_tree:add_le(f_crtp_commander_roll, roll):append_text(" (deg)")
		port_tree:add_le(f_crtp_commander_pitch, pitch):append_text(" (deg)")
		port_tree:add_le(f_crtp_commander_yaw, yaw_rate):append_text(" (deg/s)")
		port_tree:add_le(f_crtp_commander_thrust, thrust)

		undecoded = undecoded - 14
	end
end

function handle_memory_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	local MemoryTypes = {
		[0x00] = "I2C",
		[0x01] = "1-Wire",
		[0x10] = "Driver LED",
		[0x11] = "Loco",
		[0x12] = "Trajectory",
		[0x13] = "Loco2",
		[0x14] = "Lighthouse",
		[0x15] = "Memory Tester",
		[0x17] = "Driver LED Timing",
		[0x18] = "App",
		[0x19] = "Deck Memory",
		[0x1A] = "Deck Multiranger",
		[0x1B] = "Deck PAA3905",
		[0x20] = "DeckCtrl DFU",
		[0x21] = "DeckCtrl",
	}

	-- Channel 0: Info/TOC
	if channel == 0 then
		if size >= 2 then
			local cmd = buffer(crtp_start + 1, 1):le_uint()
			if cmd == 1 then
				port_tree:add_le(f_crtp_memory_cmd, "Get Memory Count")
				if receive == 1 and size >= 3 then
					port_tree:add_le(f_crtp_memory_count, buffer(crtp_start + 2, 1):le_uint())
					undecoded = undecoded - 2
				else
					undecoded = undecoded - 1
				end
			elseif cmd == 2 then
				port_tree:add_le(f_crtp_memory_cmd, "Get Memory Info")
				if size >= 3 then
					local mem_id = buffer(crtp_start + 2, 1):le_uint()
					port_tree:add_le(f_crtp_memory_id, mem_id)
					undecoded = undecoded - 2

					if receive == 1 and size >= 12 then
						local mem_type = buffer(crtp_start + 3, 1):le_uint()
						local type_name = MemoryTypes[mem_type] or "Unknown"
						port_tree:add_le(f_crtp_memory_type, mem_type .. " (" .. type_name .. ")")
						local mem_size = buffer(crtp_start + 4, 4):le_uint()
						port_tree:add_le(f_crtp_memory_size, mem_size):append_text(" bytes")
						local mem_addr = buffer(crtp_start + 8, 8):le_uint64()
						port_tree:add_le(f_crtp_memory_addr, mem_addr)
						undecoded = undecoded - 10
					end
				end
			end
		end
	-- Channel 1: Read
	elseif channel == 1 then
		port_tree:add_le(f_crtp_memory_cmd, "Read")
		if size >= 7 then
			local mem_id = buffer(crtp_start + 1, 1):le_uint()
			local addr = buffer(crtp_start + 2, 4):le_uint()
			port_tree:add_le(f_crtp_memory_id, mem_id)
			port_tree:add_le(f_crtp_memory_addr, addr)
			undecoded = undecoded - 5
		end
	-- Channel 2: Write
	elseif channel == 2 then
		port_tree:add_le(f_crtp_memory_cmd, "Write")
		if size >= 7 then
			local mem_id = buffer(crtp_start + 1, 1):le_uint()
			local addr = buffer(crtp_start + 2, 4):le_uint()
			port_tree:add_le(f_crtp_memory_id, mem_id)
			port_tree:add_le(f_crtp_memory_addr, addr)
			undecoded = undecoded - 5
		end
	end
end

function handle_localization_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	local LocalizationTypes = {
		[0] = "Range Stream Report",
		[1] = "Range Stream Report FP16",
		[2] = "LPS Short LPP Packet",
		[3] = "Emergency Stop",
		[4] = "Emergency Stop Watchdog",
		[6] = "GNSS NMEA",
		[7] = "GNSS Proprietary",
		[8] = "External Pose",
		[9] = "External Pose Packed",
		[10] = "Lighthouse Angle Stream",
		[11] = "Lighthouse Persist Data",
	}

	-- Channel 0: External Position
	if channel == 0 then
		port_tree:add_le(f_crtp_loc_cmd, "External Position")
		if size >= 13 then
			local x = buffer(crtp_start + 1, 4):le_float()
			local y = buffer(crtp_start + 5, 4):le_float()
			local z = buffer(crtp_start + 9, 4):le_float()

			port_tree:add_le(f_crtp_loc_x, x):append_text(" (m)")
			port_tree:add_le(f_crtp_loc_y, y):append_text(" (m)")
			port_tree:add_le(f_crtp_loc_z, z):append_text(" (m)")
			undecoded = undecoded - 12
		end
	-- Channel 1: Generic localization
	elseif channel == 1 then
		if size >= 2 then
			local cmd_type = buffer(crtp_start + 1, 1):le_uint()
			local type_name = LocalizationTypes[cmd_type] or "Unknown"
			port_tree:add_le(f_crtp_loc_cmd, type_name .. " (" .. cmd_type .. ")")

			if cmd_type == 3 then
				-- Emergency Stop
				undecoded = undecoded - 1
			elseif cmd_type == 4 then
				-- Emergency Stop Watchdog
				undecoded = undecoded - 1
			elseif cmd_type == 8 and size >= 29 then
				-- External Pose: x, y, z, qx, qy, qz, qw (7 floats)
				local x = buffer(crtp_start + 2, 4):le_float()
				local y = buffer(crtp_start + 6, 4):le_float()
				local z = buffer(crtp_start + 10, 4):le_float()
				local qx = buffer(crtp_start + 14, 4):le_float()
				local qy = buffer(crtp_start + 18, 4):le_float()
				local qz = buffer(crtp_start + 22, 4):le_float()
				local qw = buffer(crtp_start + 26, 4):le_float()

				port_tree:add_le(f_crtp_loc_x, x):append_text(" (m)")
				port_tree:add_le(f_crtp_loc_y, y):append_text(" (m)")
				port_tree:add_le(f_crtp_loc_z, z):append_text(" (m)")
				port_tree:add_le(f_crtp_loc_qx, qx)
				port_tree:add_le(f_crtp_loc_qy, qy)
				port_tree:add_le(f_crtp_loc_qz, qz)
				port_tree:add_le(f_crtp_loc_qw, qw)
				undecoded = undecoded - 28
			elseif cmd_type == 10 and size >= 22 then
				-- Lighthouse Angle Stream
				local bs_id = buffer(crtp_start + 2, 1):le_uint()
				port_tree:add_le(f_crtp_loc_bs_id, bs_id)
				undecoded = undecoded - 2
			elseif cmd_type == 11 and size >= 5 then
				-- Lighthouse Persist Data
				undecoded = undecoded - 4
			end
		end
	end
end

function handle_generic_setpoint_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	local SetpointTypes = {
		[0] = "Stop",
		[1] = "Velocity World (Legacy)",
		[2] = "Z Distance (Legacy)",
		[3] = "CPPM Emulation",
		[4] = "Alt Hold",
		[5] = "Hover (Legacy)",
		[6] = "Full State",
		[7] = "Position",
		[8] = "Velocity World",
		[9] = "Z Distance",
		[10] = "Hover",
		[11] = "Manual",
	}

	-- Channel 0: Setpoint data
	if channel == 0 then
		if size >= 2 then
			local sp_type = buffer(crtp_start + 1, 1):le_uint()
			local type_name = SetpointTypes[sp_type] or "Unknown"
			port_tree:add_le(f_crtp_generic_type, type_name .. " (" .. sp_type .. ")")

			if sp_type == 0 then
				-- Stop
				undecoded = undecoded - 1
			elseif sp_type == 6 and size >= 30 then
				-- Full State: x, y, z (i16 mm), vx, vy, vz (i16 mm/s), ax, ay, az (i16 mm/s^2),
				-- quat (compressed), rollRate, pitchRate, yawRate (i16)
				-- This is a complex compressed format
				local x = buffer(crtp_start + 2, 2):le_int() / 1000.0
				local y = buffer(crtp_start + 4, 2):le_int() / 1000.0
				local z = buffer(crtp_start + 6, 2):le_int() / 1000.0

				port_tree:add_le(f_crtp_generic_x, x):append_text(" (m)")
				port_tree:add_le(f_crtp_generic_y, y):append_text(" (m)")
				port_tree:add_le(f_crtp_generic_z, z):append_text(" (m)")

				local vx = buffer(crtp_start + 8, 2):le_int() / 1000.0
				local vy = buffer(crtp_start + 10, 2):le_int() / 1000.0
				local vz = buffer(crtp_start + 12, 2):le_int() / 1000.0

				port_tree:add_le(f_crtp_generic_vx, vx):append_text(" (m/s)")
				port_tree:add_le(f_crtp_generic_vy, vy):append_text(" (m/s)")
				port_tree:add_le(f_crtp_generic_vz, vz):append_text(" (m/s)")
				undecoded = undecoded - 29
			elseif sp_type == 7 and size >= 18 then
				-- Position: x, y, z, yaw (4 floats)
				local x = buffer(crtp_start + 2, 4):le_float()
				local y = buffer(crtp_start + 6, 4):le_float()
				local z = buffer(crtp_start + 10, 4):le_float()
				local yaw = buffer(crtp_start + 14, 4):le_float()

				port_tree:add_le(f_crtp_generic_x, x):append_text(" (m)")
				port_tree:add_le(f_crtp_generic_y, y):append_text(" (m)")
				port_tree:add_le(f_crtp_generic_z, z):append_text(" (m)")
				port_tree:add_le(f_crtp_generic_yaw, yaw):append_text(" (deg)")
				undecoded = undecoded - 17
			elseif sp_type == 8 and size >= 18 then
				-- Velocity World: vx, vy, vz, yaw_rate (4 floats)
				local vx = buffer(crtp_start + 2, 4):le_float()
				local vy = buffer(crtp_start + 6, 4):le_float()
				local vz = buffer(crtp_start + 10, 4):le_float()
				local yaw_rate = buffer(crtp_start + 14, 4):le_float()

				port_tree:add_le(f_crtp_generic_vx, vx):append_text(" (m/s)")
				port_tree:add_le(f_crtp_generic_vy, vy):append_text(" (m/s)")
				port_tree:add_le(f_crtp_generic_vz, vz):append_text(" (m/s)")
				port_tree:add_le(f_crtp_generic_yaw_rate, yaw_rate):append_text(" (deg/s)")
				undecoded = undecoded - 17
			elseif sp_type == 9 and size >= 18 then
				-- Z Distance: roll, pitch, yaw_rate, z_distance (4 floats)
				local roll = buffer(crtp_start + 2, 4):le_float()
				local pitch = buffer(crtp_start + 6, 4):le_float()
				local yaw_rate = buffer(crtp_start + 10, 4):le_float()
				local zdist = buffer(crtp_start + 14, 4):le_float()

				port_tree:add_le(f_crtp_generic_roll, roll):append_text(" (deg)")
				port_tree:add_le(f_crtp_generic_pitch, pitch):append_text(" (deg)")
				port_tree:add_le(f_crtp_generic_yaw_rate, yaw_rate):append_text(" (deg/s)")
				port_tree:add_le(f_crtp_generic_zdist, zdist):append_text(" (m)")
				undecoded = undecoded - 17
			elseif sp_type == 10 and size >= 18 then
				-- Hover: vx, vy, yaw_rate, z_distance (4 floats)
				local vx = buffer(crtp_start + 2, 4):le_float()
				local vy = buffer(crtp_start + 6, 4):le_float()
				local yaw_rate = buffer(crtp_start + 10, 4):le_float()
				local zdist = buffer(crtp_start + 14, 4):le_float()

				port_tree:add_le(f_crtp_generic_vx, vx):append_text(" (m/s, body)")
				port_tree:add_le(f_crtp_generic_vy, vy):append_text(" (m/s, body)")
				port_tree:add_le(f_crtp_generic_yaw_rate, yaw_rate):append_text(" (deg/s)")
				port_tree:add_le(f_crtp_generic_zdist, zdist):append_text(" (m)")
				undecoded = undecoded - 17
			elseif sp_type == 11 and size >= 18 then
				-- Manual: roll, pitch, yaw_rate, thrust, rate_mode
				local roll = buffer(crtp_start + 2, 4):le_float()
				local pitch = buffer(crtp_start + 6, 4):le_float()
				local yaw_rate = buffer(crtp_start + 10, 4):le_float()
				local thrust = buffer(crtp_start + 14, 2):le_uint()
				local rate_mode = buffer(crtp_start + 16, 1):le_uint()

				port_tree:add_le(f_crtp_generic_roll, roll):append_text(" (deg)")
				port_tree:add_le(f_crtp_generic_pitch, pitch):append_text(" (deg)")
				port_tree:add_le(f_crtp_generic_yaw_rate, yaw_rate):append_text(" (deg/s)")
				port_tree:add_le(f_crtp_generic_thrust, thrust)
				port_tree:add_le(f_crtp_generic_rate_mode, rate_mode)
				undecoded = undecoded - 16
			end
		end
	-- Channel 1: Meta commands
	elseif channel == 1 then
		if size >= 2 then
			local cmd_type = buffer(crtp_start + 1, 1):le_uint()
			if cmd_type == 0 then
				port_tree:add_le(f_crtp_generic_type, "Notify Setpoint Stop")
				undecoded = undecoded - 1
			end
		end
	end
end

function handle_platform_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)

	-- Channel 0: Platform commands
	if channel == 0 then
		if size >= 2 then
			local cmd = buffer(crtp_start + 1, 1):le_uint()
			local PlatformCommands = {
				[0] = "Set Continuous Wave",
				[1] = "Request Arming",
				[2] = "Request Crash Recovery",
				[4] = "Set Crazyflie Name",
			}
			local cmd_name = PlatformCommands[cmd] or "Unknown"
			port_tree:add_le(f_crtp_platform_cmd, cmd_name .. " (" .. cmd .. ")")

			if cmd == 1 and size >= 3 then
				local arm = buffer(crtp_start + 2, 1):le_uint()
				port_tree:add_le(f_crtp_platform_arm_request, arm ~= 0)
				undecoded = undecoded - 2
			else
				undecoded = undecoded - 1
			end
		end
	-- Channel 1: Version commands
	elseif channel == 1 then
		if size >= 2 then
			local cmd = buffer(crtp_start + 1, 1):le_uint()
			local VersionCommands = {
				[0] = "Get Protocol Version",
				[1] = "Get Firmware Version",
				[2] = "Get Device Type",
			}
			local cmd_name = VersionCommands[cmd] or "Unknown"
			port_tree:add_le(f_crtp_platform_version_cmd, cmd_name .. " (" .. cmd .. ")")

			if cmd == 0 and receive == 1 and size >= 3 then
				local version = buffer(crtp_start + 2, 1):le_uint()
				port_tree:add_le(f_crtp_platform_protocol_version, version)
				undecoded = undecoded - 2
			elseif cmd == 1 and receive == 1 and size > 2 then
				local fw_version = buffer(crtp_start + 2):string()
				port_tree:add_le(f_crtp_platform_firmware_version, fw_version)
				undecoded = 0
			elseif cmd == 2 and receive == 1 and size > 2 then
				local device_type = buffer(crtp_start + 2):string()
				port_tree:add_le(f_crtp_platform_device_type, device_type)
				undecoded = 0
			else
				undecoded = undecoded - 1
			end
		end
	-- Channel 2: App channel
	elseif channel == 2 then
		port_tree:add_le(f_crtp_platform_cmd, "App Channel Data")
	end
end

function handle_link_control_port(tree, receive, buffer, channel, size)
	local port_tree = tree:add(crtp, port_name)
	if channel == 0 then -- Echo
		port_tree:add_le(f_crtp_echo_data, buffer(crtp_start + 1):le_uint())
		undecoded = 0
	elseif channel == 3 and size == 3 and buffer(crtp_start + 1, 1):uint() == 0x05 then -- Low level safelink packet
		local safelink_type = (receive == 0) and "Request" or "Acknowledge"
		port_tree:add_le(f_crtp_safelink_type, safelink_type)
		undecoded = 0
	end
end

-- create a function to dissect it, layout:
-- | link_type | receive| address       | channel | serial   | crtp header | crtp data |
-- | 1 byte    | 1 byte | 5 or 12 bytes |  1 byte | 16 bytes |    1 byte   |   n bytes |
function crtp.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CRTP"

	link = buffer(0, 1):uint()
	if link == Links.RADIO then
		crtp_start = 24  -- 1+1+5+1+16
	elseif link == Links.USB or link == Links.UDP then
		crtp_start = 31  -- 1+1+12+1+16
	else
		-- Unknown link type, layout unknown
		return
	end

	if buffer:len() <= crtp_start then
		return
	end

	local receive = buffer(1, 1):uint()
	if receive == 1 then
		pinfo.cols.dst = format_device(buffer)
		pinfo.cols.src = format_address(buffer)
	else
		pinfo.cols.dst = format_address(buffer)
		pinfo.cols.src = format_device(buffer)
	end

	local subtree = tree:add(crtp, "CRTP Packet")
	local raw_header = buffer(crtp_start, 1):uint()
	local header = bit.band(raw_header, 0xF3)
	local crtp_port = bit.rshift(bit.band(header, 0xF0), 4)
	local crtp_channel = bit.band(header, 0x03)
	local safelink_up = bit.rshift(bit.band(raw_header, 0x08), 3)
	local safelink_down = bit.rshift(bit.band(raw_header, 0x04), 2)
	subtree:add_le(f_crtp_safelink_up, safelink_up)
	subtree:add_le(f_crtp_safelink_down, safelink_down)

	-- Add CRTP packet size:
	-- link_type + receive + address + channel + serial = crtp_start
	-- Rest is CRTP packet
	local crtp_size = buffer:len() - crtp_start
	subtree:add_le(f_crtp_size, crtp_size)

	undecoded = crtp_size - 1

	-- Get port and channel name
	port_name, channel_name = get_crtp_port_channel_names(crtp_port, crtp_channel)

	-- Display port in info column
	pinfo.cols.info = port_name

	-- Add to CRTP tree
	subtree:add_le(f_crtp_port, crtp_port):append_text(" (" .. port_name .. ")")
	if channel_name then
		subtree:add_le(f_crtp_channel, crtp_channel):append_text(" (" .. channel_name .. ")")
	else
		subtree:add_le(f_crtp_channel, crtp_channel)
	end

	-- Check for special handling

	-- Console, we can add text
	if crtp_port == Ports.Console then
		local port_tree = tree:add(crtp, port_name)
		port_tree:add_le(f_crtp_console_text, buffer(crtp_start + 1):string())
		undecoded = 0
	end

	if crtp_port == Ports.LinkControl then
		handle_link_control_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Parameters then
		handle_parameter_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Commander then
		handle_commander_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Memory then
		handle_memory_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Logging then
		handle_logging_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Localization then
		handle_localization_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Commander_Generic then
		handle_generic_setpoint_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Setpoint_Highlevel then
		handle_setpoint_highlevel(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if crtp_port == Ports.Platform then
		handle_platform_port(tree, receive, buffer, crtp_channel, crtp_size)
	end

	if undecoded > 0 then
		local from = crtp_start + (crtp_size - undecoded)
		subtree:add_le(f_crtp_undecoded, buffer(from, undecoded):bytes():tohex())
	end
end

wtap_encap = DissectorTable.get("wtap_encap")
wtap_encap:add(wtap.USER15, crtp)

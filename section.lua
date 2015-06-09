--CCP PROTOCOL TABLE
ts_table = DissectorTable.new("TS_TABLE", "Transport Section", FT_STRING)

--Section Table IDs
accept_tables = {0x80, 0x81, 0x82}

--ECM Table IDs
ecm_table_ids = {0x80, 0x81}

--SI Table IDs
NIT_TABLE_IDS = {0x40, 0x41}
SDT_TABLE_IDS = {0x42, 0x46}
BAT_TABLE_IDS = {0x4a}
EIT_PF_TABLE_IDS = {0x4e, 0x4f}
				
local function range(start, ending)
	t = {}
	for i =start, ending do
		table.insert(t, i)
	end
	return t
end		

EIT_ACTUAL_SCHEDULE_TABLE_IDS = range(0x50, 0x60)
EIT_OTHER_SCHEDULE_TABLE_IDS = range(0x60, 0x70)
SI_TABLE_IDS_NOEITS = {0x40, 0x41, 0x42, 0x46, 0x4a, 0x4e, 0x4f}
--------------------------------------------------------
--------------------------------------------------------

local function is_tableid_valid(id, tab)
	local is_valid = false
	for _, v in pairs(tab) do
		if id == v then  
			is_valid = true
		end
	end
	return is_valid
end

local function append_field(tree, tag, value)
	if value ~= nil then
		tree:add(tag, value)
	end
end

local function is_si_table_id(id)
	if is_tableid_valid(id, SI_TABLE_IDS_NOEITS) or 
		is_tableid_valid(id, EIT_ACTUAL_SCHEDULE_TABLE_IDS) or 
		is_tableid_valid(id, EIT_OTHER_SCHEDULE_TABLE_IDS) then
		return true
	else
		return false
	end
end

	--[[

	Transport Stream Packet Message

	--]]

	local TS_PACKET = Proto("TS_PACKET", "TS Packet")
	f_ts_pacekt_sync_byte = ProtoField.uint8("TS_PACKET.sync_byte", "Sync Byte", base.HEX, nil, 0xff)
	f_ts_packet_error_indicator = ProtoField.uint8("TS_PACKET.ts_error_indicator", "TS Error Indicator", base.HEX, nil, 0x80)
	f_ts_packet_pusi = ProtoField.uint8("TS_PACKET.pusi", "Payload Unit Start Indicator", base.HEX, nil, 0x40)
	f_ts_packet_priority = ProtoField.uint8("TS_PACKET.priority", "Transport Priority", base.HEX, nil, 0x20)
	f_ts_packet_pid = ProtoField.uint16("TS_PACKET.pid", "PID", base.HEX, nil, 0x1fff)
	f_ts_packet_scrambling_control = ProtoField.uint8("TS_PACKET.sc", "Scrambling Control", base.HEX, nil, 0xc0)
	f_ts_packet_continuity_counter = ProtoField.uint8("TS_PACKET.cc", "Continuity Counter", base.HEX, nil, 0x0f)
	f_ts_packet_adaptation_field = ProtoField.bytes("TS_PACKET.af", "Adaptation Field", base.HEX)
	f_ts_packet_adaptation_field_length = ProtoField.uint8("TS_PACKET.afL", "Adaptation Field Length", base.DEC)
	f_ts_packet_payload_pointer_field = ProtoField.uint8("TS_PACKET.ppf", "Payload Pointer Field", base.DEC)
	f_ts_packet_adapation_field_flag = ProtoField.uint8("TS_PACKET.aff", "Adaptation Field Flag", base.HEX, nil, 0x20)
	f_ts_packet_adapation_field_payload_flag = ProtoField.uint8("TS_PACKET.afpf", "Adaptation Field Payload Flag", base.HEX, nil, 0x10)
	f_ts_packet_payload = ProtoField.bytes("TS_PACKET.payload", "Payload", base.HEX)
	f_ts_packet_payload_part_previous_section = ProtoField.bytes("TS_PACKET.payloadpps", "Part of section in previous TS packet", base.HEX)

	TS_PACKET.fields = {f_ts_pacekt_sync_byte, f_ts_packet_error_indicator, f_ts_packet_pusi, f_ts_packet_priority, f_ts_packet_pid,
											f_ts_packet_scrambling_control, f_ts_packet_continuity_counter, f_ts_packet_adaptation_field, f_ts_packet_adaptation_field_length,
											f_ts_packet_adapation_field_flag, f_ts_packet_payload, f_ts_packet_adapation_field_payload_flag, f_ts_packet_payload_pointer_field,
											f_ts_packet_payload_part_previous_section}

	function TS_PACKET.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len ~= 188 then
			return false
		end
		
		if buf(0,1):uint() ~= 0x47 then
			return false
		end
		
		local t = root:add(TS_PACKET, buf(0,  buf_len))
		t:add(f_ts_pacekt_sync_byte, buf(0,1))
		t:add(f_ts_packet_error_indicator, buf(1,1))
		t:add(f_ts_packet_pusi, buf(1,1))
		t:add(f_ts_packet_priority, buf(1,1))
		t:add(f_ts_packet_pid, buf(1,2))
		t:add(f_ts_packet_scrambling_control, buf(3,1))
		-- Adapation Field Control
		t:add(f_ts_packet_adapation_field_flag, buf(3,1))
		t:add(f_ts_packet_adapation_field_payload_flag, buf(3,1))
		t:add(f_ts_packet_continuity_counter, buf(3,1))

		local startOfNextSectionAt = 0
		local startIndexPayload = 0
		local af_length = 0
		local payload_pointer = 0
		local pusi = bit:_and(bit:_rshift(buf(1,1):uint(), 6), 1)
		local af_flag = bit:_and(bit:_rshift(buf(3,1):uint(), 5), 1)
		
		if pusi == 1 then
			if af_flag == 1 then
				af_length = buf(4, 1):uint()
				if af_length > 0 then
					t:add(f_ts_packet_adaptation_field_length, buf(4,1))
					t:add(f_ts_packet_adaptation_field, buf(5, af_length))
				end
			end
			
			payload_pointer = buf(4, 1):uint()
			t:add(f_ts_packet_payload_pointer_field, buf(4,1))
			if payload_pointer ~= 0 then
				t:add(f_ts_packet_payload_part_previous_section, buf(5,payload_pointer))
			end
			startIndexPayload = 5 + payload_pointer
			
		else
			startOfNextSectionAt = -1
			startIndexPayload = 4
		
		end

	--   Skip the AF and get the Payload by adding condition pusi == 1
    --   Here we could have one or more Emm Sections..
		-- DO NOT parse, because many section is larger than 188 bytes, they are splited into multiple TS packets.
		local table_id = buf(startIndexPayload, 1):uint()
		if ENABLE_IRDETO_CRYPTO_WORKS == true then
			section_buf = buf(startIndexPayload, buf_len - startIndexPayload):tvb()
			ice_table:get_dissector(0xFF00):call(section_buf, pkt, t)
		else
			if pusi == 1 and is_tableid_valid(table_id, accept_tables) then
				section_buf = buf(startIndexPayload, buf_len - startIndexPayload):tvb()
				ts_table:get_dissector(0xFF00):call(section_buf, pkt, t)
			elseif pusi == 1 and is_si_table_id(table_id) then
				si_section = buf(startIndexPayload, buf_len - startIndexPayload):tvb()
				ts_table:get_dissector(0xFF10):call(si_section, pkt, t)
			else
				t:append_text(' (No section start in this package.)')
				t:add(f_ts_packet_payload, buf(startIndexPayload, buf_len - startIndexPayload))
			end
		end

	end

	ts_table:add(0xFFFF, TS_PACKET)
	
	
--ECM STRUCTURE	
	local ECM_SECTION = Proto("ECM_SECTION", "ECM Section")
	f_ecm_sc_marriage_flag = ProtoField.uint8("ECM_SECTION.sc_marriage_flag", "SC Marriage Flag", base.HEX, nil, 0x80)
	f_ecm_reserved = ProtoField.uint8("ECM_SECTION.reserved", "Reserved", base.HEX, nil, 0x40)
	f_ecm_version_number = ProtoField.uint8("ECM_SECTION.version_number", "Version Number", base.HEX, nil, 0x3e)
	f_ecm_current_next_indicator = ProtoField.uint8("ECM_SECTION.current_next_indicator", "Current Next Indicator", base.HEX, nil, 0x01)	
	f_ecm_page_number = ProtoField.uint8("ECM_SECTION.page_number", "Page Number", base.DEC)	
	f_ecm_last_page = ProtoField.uint8("ECM_SECTION.last_page", "Last Page", base.DEC)
	f_ecm_payload = ProtoField.bytes("ECM_SECTION.payload", "ECM Payload", base.HEX)

	ECM_SECTION.fields = {f_ecm_sc_marriage_flag, f_ecm_reserved, f_ecm_version_number, f_ecm_current_next_indicator, f_ecm_page_number, f_ecm_last_page, f_ecm_payload}	
	
	function ECM_SECTION.dissector(buf, pkt, root)
		local buf_len = buf:len()
		local t= root:add(ECM_SECTION, buf(0, buf_len))
		
		t:add(f_ecm_sc_marriage_flag, buf(0,1))
		t:add(f_ecm_reserved, buf(0,1))
		t:add(f_ecm_version_number, buf(0,1))
		t:add(f_ecm_current_next_indicator, buf(0,1))
		t:add(f_ecm_page_number, buf(1,1))
		t:add(f_ecm_last_page, buf(2,1))
		st = t:add(f_ecm_payload, buf(3, buf_len - 3))
		
		if (buf(3,2):uint() == 0xff48) then
			msp_table:get_dissector(0xFFEE):call(buf(3, buf_len - 3):tvb(), pkt, st)
		end

	end
	
	ts_table:add(0xFF01, ECM_SECTION)
	
	local EMM_SECTION = Proto("EMM_SECTION", "EMM Section")
	f_emm_addr_len = ProtoField.uint8("EMM_SECTION.addr_len", "Address Length", base.HEX)
	f_emm_addr = ProtoField.bytes("EMM_SECTION.addr", "Address", base.HEX)
	f_emm_type = ProtoField.string("EMM_SECTION.emm_type", "EMM Type", base.HEX)
	f_emm_length = ProtoField.uint16("EMM_SECTION.emm_length", "EMM Length", base.DEC)
	f_emm_payload = ProtoField.bytes("EMM_SECTION.emm_payload", "EMM Payload", base.HEX)
	
	EMM_SECTION.fields = {f_emm_addr_len, f_emm_addr, f_emm_type, f_emm_length, f_emm_payload}
	
	local function is_global_emm(buf)
		local byte1 = buf(0,1):uint()
		local bit1 = bit:_and(byte1, 0x80)
		local last3bit = bit:_and(byte1, 0x07)
		if bit1 == 1 and last3bit == 0 then
			return true
		else
			return false
		end
	end
	
	local function is_cam_emm(buf)
		local addr_len = bit:_and(buf(0,1):uint(), 0x07)
		if tostring(buf(2+addr_len, 1)) == '40' then
			return true
		else
			return false
		end
	
	end
	
	local function is_ird_unique_emm(buf)
		local byte0 = buf(0,1):uint()
		local byte1 = buf(6,1)
		local bit1 = bit:_and(byte0, 0x80)
		local bit6 = bit:_and(byte0, 0x04)
		if bit1 == 1 and bit6 == 1 and tostring(byte1) == '80' then
			return true
		else
			return false
		end
	end
	
	local function is_global_ird(buf)
		local byte2 = buf(0,2)
		local bit2 = bit:_rshift(buf(2,1):uint(),6)
		if tostring(byte2) == '0000' and bit2 == 2 then
			return true
		else
			return false
		end
	end
	
	local function get_flow_control_size(buf)
		local fc_size = 0
		local version_syntax = bit:_and(bit:_rshift(buf(0,1):uint(), 7), 0x1)
		local fc_opcode = bit:_and(bit:_rshift(buf(0,1):uint(), 4), 0x7)
		if version_syntax == 0 and fc_opcode == 0 then
			fc_size = 2
		elseif version_syntax == 1 and fc_opcode == 0 then
			fc_size = 6
		end
		return fc_size
	end
	
	local function get_flow_control_routing(buf)
		local version_syntax = bit:_and(bit:_rshift(buf(0,1):uint(), 7), 0x1)
		local fc_opcode = bit:_and(bit:_rshift(buf(0,1):uint(), 4), 0x7)
		local routing = nil
		if version_syntax == 0 and fc_opcode == 0 then
			routing = bit:_and(bit:_rshift(buf(1,1):uint(), 6),3)
		elseif version_syntax == 1 and fc_opcode == 0 then
			routing = bit:_and(bit:_rshift(buf(4,1):uint(), 6),3)
		end
		return routing
	end
	
	function EMM_SECTION.dissector(buf, pkt, root)
		local buf_len = buf:len()
		local t= root:add(EMM_SECTION, buf(0, buf_len))
		local fc_index = 0
		local addr_len = 0
		if is_global_emm(buf) or is_global_ird(buf) then
			fc_index = 1
		else 
			if is_ird_unique_emm(buf) then
				addr_len = 4
			else
				addr_len = bit:_and(buf(0,1):uint(), 7)
			end
			fc_index = 1 + addr_len
		end
		t:add(f_emm_addr_len, addr_len)
		if addr_len ~= 0 then
			t:add(f_emm_addr, buf(1, addr_len))
		end
		-- Parse Flow Control
		fc_size = get_flow_control_size(buf(fc_index, buf_len - fc_index):tvb())
		ts_table:get_dissector(0xFF03):call(buf(fc_index, fc_size):tvb(), pkt, t)
		
		local routing = get_flow_control_routing(buf(fc_index, buf_len - fc_index):tvb())
		if routing == 1 then -- CAM
			cam_table:get_dissector(0xFFFF):call(buf(fc_index+fc_size, buf_len - fc_index - fc_size):tvb(), pkt, t)
		elseif routing == 2 then --IRD
			ird_table:get_dissector(0xFFFF):call(buf(fc_index+fc_size, buf_len - fc_index - fc_size):tvb(), pkt, t)
		elseif routing == 0 then --SC EMM
			t:add(f_emm_payload, buf(fc_index+fc_size, buf_len - fc_index - fc_size))
		else
			return false
		end

	end
	
	ts_table:add(0xFF02, EMM_SECTION)
	
	
	local FLOW_CONTROL = Proto("FLOW_CONTROL", "Flow Control")
	f_emm_fc_version_syntax = ProtoField.uint8("FLOW_CONTROL.version_syntax", "Version Syntax", base.HEX, nil, 0x80)
	f_emm_fc_fc_opcode = ProtoField.uint8("FLOW_CONTROL.fc_opcode", "Flow Control Opcode", base.HEX, nil, 0x70)
	f_emm_fc_flow_section_length = ProtoField.uint8("FLOW_CONTROL.fs_length", "Flow Section Length", base.HEX, nil, 0x0f)
	f_emm_fc_routing = ProtoField.uint8("FLOW_CONTROL.routing", "Routing", base.HEX, {[0]='SC_EMM', [1]='CAM_EMM',[2]='IRD_EMM'}, 0xc0)
	
	f_emm_version_number = ProtoField.uint8("FLOW_CONTROL.version_number", "Version Number", base.HEX, nil, 0x3e)
	f_emm_current_next_indicator = ProtoField.uint8("FLOW_CONTROL.current_next_indicator", "Current Next Indicator", base.HEX, nil, 0x01)	
	f_emm_page_number = ProtoField.uint8("FLOW_CONTROL.page_number", "Page Number", base.DEC)	
	f_emm_last_page = ProtoField.uint8("FLOW_CONTROL.last_page", "Last Page", base.DEC)	
	
	--Linking Control
	f_emm_lc_linked_message_id = ProtoField.uint8("FLOW_CONTROL.lniked_message_id", "Linked Message Id", base.HEX, nil, 0x30)
	f_emm_lc_block_sequence_nr = ProtoField.uint8("FLOW_CONTROL.block_sequece_nr", "Block Sequence Number", base.HEX, nil, 0x0c)
	f_emm_lc_last_block = ProtoField.uint8("FLOW_CONTROL.last_block", "Last Block", base.HEX, nil, 0x03)
	
	FLOW_CONTROL.fields = {f_emm_fc_version_syntax, f_emm_fc_fc_opcode, f_emm_fc_flow_section_length, f_emm_fc_routing, f_emm_lc_linked_message_id, f_emm_lc_block_sequence_nr, f_emm_lc_last_block, f_emm_version_number, f_emm_current_next_indicator, f_emm_page_number, f_emm_last_page}
	
	function FLOW_CONTROL.dissector(buf, pkt, root)
		local buf_len = buf:len()
		local t = root:add(FLOW_CONTROL, buf(0, buf_len))
		
		version_syntax = bit:_and(bit:_rshift(buf(0,1):uint(), 7), 0x1)
		fc_opcode = bit:_and(bit:_rshift(buf(0,1):uint(), 4), 0x7)
		
		t:add(f_emm_fc_version_syntax, buf(0,1))
		t:add(f_emm_fc_fc_opcode, buf(0,1))
		t:add(f_emm_fc_flow_section_length, buf(0,1))
		
		if version_syntax == 0 and fc_opcode == 0 then
			t:add(f_emm_fc_routing, buf(1,1))
			t:add(f_emm_lc_linked_message_id, buf(1,1))
			t:add(f_emm_lc_block_sequence_nr, buf(1,1))
			t:add(f_emm_lc_last_block, buf(1,1))	
		elseif version_syntax == 1 and fc_opcode == 0 then
			t:add(f_emm_version_number, buf(1,1))
			t:add(f_emm_current_next_indicator, buf(1,1))
			t:add(f_emm_page_number, buf(2,1))
			t:add(f_emm_last_page, buf(3,1))
			t:add(f_emm_fc_routing, buf(4,1))
			t:add(f_emm_lc_linked_message_id, buf(4,1))
			t:add(f_emm_lc_block_sequence_nr, buf(4,1))
			t:add(f_emm_lc_last_block, buf(4,1))	
		end

	end
	
	ts_table:add(0xFF03, FLOW_CONTROL)
		
--Section Message	
	
	local SECTION_MESSAGE = Proto("SECTION_MESSAGE", "Section Message")
	local SUB_SECTION = Proto("SUB_SECTION", "Sub Section")
	f_section_table_id = ProtoField.uint8("SECTION_MESSAGE.table_id", "Table Id", base.HEX, nil, 0xff)
	f_section_syntax_indicator = ProtoField.uint16("SECTION_MESSAGE.section_syntax_indicator", "Section Syntax Indicator", base.HEX, nil, 0x8000)
	f_section_dvb_reserved = ProtoField.uint16("SECTION_MESSAGE.dvb_reserved", "DVB Reserved", base.HEX, nil, 0x4000)
	f_section_iso_reserved = ProtoField.uint16("SECTION_MESSAGE.iso_reserved", "ISO Reserved", base.HEX, nil, 0x3000)
	f_section_length = ProtoField.uint16("SECTION_MESSAGE.length", "Section Length", base.DEC, nil, 0x0fff)
	f_section_message = ProtoField.bytes("SECTION_MESSAGE.message", "Section Message", base.HEX)
	f_section_stuffing = ProtoField.bytes("SECTION_MESSAGE.stuffing", "Stuffing Bytes", base.HEX)
	f_section_split_emm = ProtoField.bytes("SECTION_MESSAGE.split_emm", "Splitted EMM Fragement", base.HEX)
	f_section_crc32 = ProtoField.bytes("SECTION_MESSAGE.crc32", "CRC32", base.HEX)
	
	SECTION_MESSAGE.fields = {f_section_table_id, f_section_syntax_indicator, f_section_dvb_reserved, f_section_iso_reserved, f_section_length, f_section_message, f_section_stuffing, f_section_split_emm, f_section_crc32}
	
	function SECTION_MESSAGE.dissector(buf, pkt, root)
		local buf_len = buf:len()
		local t = root:add(SECTION_MESSAGE, buf(0, buf_len))
		local idx = 0
		while idx < buf_len do
			local table_id = buf(idx,1):uint()
			if table_id == 0xff then
				t:add(f_section_stuffing, buf(idx, buf_len-idx))
				return
			end
			local section_length = bit:_and(buf(idx+1,2) : uint(), 0x0fff)
			local temp_len = section_length

			if is_tableid_valid(table_id, accept_tables) then
				-- The packet will be divide into next TS Packet when the length > 188
				if idx + section_length + 3 > buf_len then
					section_length = buf_len - 3 - idx
				end
				local subt = t:add(SUB_SECTION, buf(idx, section_length + 3))
				subt:add(f_section_table_id, buf(idx,1))
				subt:add(f_section_syntax_indicator, buf(idx+1,2))
				subt:add(f_section_dvb_reserved, buf(idx+1,2))
				subt:add(f_section_iso_reserved, buf(idx+1,2))
				if section_length ~= temp_len then
					subt:add(f_section_length, buf(idx+1,2)):append_text(' (Fragment Length is '..section_length..', EMM was splitted due to the packet length limitation)')
				else
					subt:add(f_section_length, buf(idx+1,2))
				end
				subt:add(f_section_message, buf(idx+3, section_length))
				
				-- if we decide to decode the play load as EMM or ECM, remove the 8bytes CRC
				local message_buf = buf(idx+3, section_length):tvb()
				if table_id == 0x82 then
					ts_table:get_dissector(0xFF02):call(message_buf, pkt, subt)
					subt:add(f_section_crc32, buf(idx + section_length - 5, 8))
				elseif is_tableid_valid(table_id, ecm_table_ids) then
					ts_table:get_dissector(0xFF01):call(message_buf, pkt, subt)
					subt:add(f_section_crc32, buf(idx + section_length - 5, 8))
				end
			end		
			
			idx = idx + 3 + section_length
		end
	end
	
	ts_table:add(0xFF00, SECTION_MESSAGE)
	
	
------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------SI Section Interface--------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------

local SI_SECTION = Proto("SI_SECTION", "SI SECTION")
local si_table_id = ProtoField.uint8("SI_SECTION.table_id", "Table Id", base.HEX)
local si_ssi = ProtoField.uint8("SI_SECTION.ssi", "Section Syntax Indicator", base.HEX, nil, 0x80)
local si_rfu = ProtoField.uint8("SI_SECTION.rfu", "RFU", base.HEX, nil, 0x70)
local si_length	= ProtoField.uint16("SI_SECTION.ssi", "Length", base.DEC, nil, 0x0fff)
local si_section_payload = ProtoField.bytes("SI_SECTION.payload", "Stuffing Payload", base.HEX)
local si_crc32 = ProtoField.bytes("SI_SECTION.crc32", "CRC32", base.HEX)

SI_SECTION.fields = {si_table_id, si_ssi, si_rfu, si_length, si_section_payload, si_crc32}

local function parse_si_section(buf, pkt, root)
	local buf_len = buf:len()
	local table_id = buf(0,1):uint()
	root:add(si_table_id, buf(0,1))
	root:add(si_ssi, buf(1,1))
	root:add(si_rfu, buf(1,1))
	root:add(si_length, buf(1,2))

	local section_length = bit:_and(buf(1, 2):uint(), 0x0fff)
	local actual_sec_len = section_length
	if section_length > buf_len-3 then 
		actual_sec_len = buf_len-3
		root:append_text(' (Missing ' .. section_length-actual_sec_len .. ' Bytes.)')
	end
	local section_payload = buf(3, actual_sec_len):tvb()
	local ts_table_parse_result = true
	if is_tableid_valid(table_id, NIT_TABLE_IDS) then
		ts_table_parse_result = ts_table:get_dissector(0xFF11):call(section_payload, pkt, root)
	elseif is_tableid_valid(table_id, BAT_TABLE_IDS) then
		ts_table_parse_result = ts_table:get_dissector(0xFF12):call(section_payload, pkt, root)
	elseif is_tableid_valid(table_id, SDT_TABLE_IDS) then
		ts_table_parse_result = ts_table:get_dissector(0xFF13):call(section_payload, pkt, root)
	elseif is_tableid_valid(table_id, EIT_PF_TABLE_IDS) or is_tableid_valid(table_id, EIT_PF_TABLE_IDS) or is_tableid_valid(table_id, EIT_PF_TABLE_IDS) then
		ts_table_parse_result = ts_table:get_dissector(0xFF14):call(section_payload, pkt, root)
	else
		return false
	end
	
	if not ts_table_parse_result then -- ts table parse error or table is splited.
		return false
	end
	root:add(si_crc32, buf(section_length-1, 4)) -- 1+2+section_length-4
	return true
end

function SI_SECTION.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 3 or buf_len > 1024 then 
		return false
	else
		local index = 0
		while index < buf_len do
			local table_id = buf(index, 1):uint()
			local section_length = bit:_and(buf(index+1, 2):uint(), 0x0fff)
			if is_si_table_id(table_id) then
				local t = root:add(SI_SECTION, buf(index, buf_len - index))
				if section_length > buf_len - index then
					t:append_text(' (Fragment Length is '..section_length..', SI section was truncated)')
				end
				parse_si_section(buf(index, buf_len - index), pkt, t)
				index = index + 3 + section_length
			elseif tostring(buf(index, 1)) == 'ff' then
				root:add(si_section_payload, buf(index, buf_len - index))
				break
			else
				return false
			end
		end
	end

end

ts_table:add(0xFF10, SI_SECTION)
	
------------------------------
--------  NIT SECTION --------
------------------------------

local NIT_SECTION = Proto("NIT_SECTION", "NIT Section")
local nit_network_id = ProtoField.uint16("NIT_SECTION.network_id", "Network Id", base.HEX)
local nit_rfu1 = ProtoField.uint8("NIT_SECTION.rfu1", "RFU", base.HEX, nil, 0xc0)
local nit_version = ProtoField.uint8("NIT_SECTION.version", "Version", base.HEX, nil, 0x3e)
local nit_cn_ind = ProtoField.uint8("NIT_SECTION.cn_ind", "Current Next Indicator", base.HEX, nil, 0x01)
local nit_section_nr = ProtoField.uint8("NIT_SECTION.section_nr", "Section Number", base.HEX)
local nit_last_section_nr = ProtoField.uint8("NIT_SECTION.last_section_nr", "Last Section Number", base.HEX)
local nit_rfu2 = ProtoField.uint8("NIT_SECTION.rfu2", "RFU", base.HEX, nil, 0xf0)
local nit_descriptors_len = ProtoField.uint16("NIT_SECTION.descriptors_len", "Descriptors Length", base.DEC, nil, 0x0fff)
local nit_descriptors = ProtoField.bytes("NIT_SECTION.descriptors", "Descriptors List", base.HEX)
local nit_rfu3 = ProtoField.uint8("NIT_SECTION.rfu3", "RFU", base.HEX, nil, 0xf0)
local nit_ts_stream_loop_length = ProtoField.uint16("TS_STREAM_BLOCKS.stream_loop_len", "Transport Stream Loop Length", base.DEC, nil, 0x0fff)
local nit_crc_32 = ProtoField.uint32("EIT_SECTION.nit_crc_32", "CRC_32", base.HEX)

NIT_SECTION.fields= {nit_network_id, nit_version, nit_cn_ind, nit_section_nr, nit_last_section_nr, nit_descriptors_len, nit_descriptors, nit_rfu1, nit_rfu2, nit_rfu3, nit_ts_stream_loop_length, nit_crc_32}

function NIT_SECTION.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(NIT_SECTION, buf(0, buf_len))
	t:add(nit_network_id, buf(0,2))
	t:add(nit_rfu1, buf(2,1))
	t:add(nit_version, buf(2,1))
	t:add(nit_cn_ind, buf(2,1))
	t:add(nit_section_nr, buf(3,1))
	t:add(nit_last_section_nr, buf(4,1))
	t:add(nit_rfu2, buf(5,1))
	local desc_len = bit:_and(buf(5,2):uint(), 0x0fff)
	if desc_len > 0 then
		t:add(nit_descriptors_len, buf(5,2))
		desc_table:get_dissector(0x00):call(buf(7, desc_len):tvb(), pkt, t)
	end
	t:add(nit_rfu3, bit:_and(buf(7+desc_len, 1):uint(), 0xf0))
	t:add(nit_ts_stream_loop_length, bit:_and(buf(7+desc_len, 2):uint(), 0x0fff))
	local ts_desc_len = bit:_and(buf(7+desc_len, 2):uint(), 0x0fff)
	if ts_desc_len > 0 then
		desc_table:get_dissector(0x01):call(buf(7 + desc_len, ts_desc_len+2):tvb(), pkt, t)
	end
	t:add(nit_crc_32, buf(buf_len-4, 4))
end
    
ts_table:add(0xFF11, NIT_SECTION)	
	
------------------------------
--------  BAT SECTION --------
------------------------------

local BAT_SECTION = Proto("BAT_SECTION","BAT Section")
local bat_bouquet_id = ProtoField.uint8("BAT_SECTION.bouquet_id", "Bouquet Id", base.HEX)
local bat_rfu1 = ProtoField.uint8("BAT_SECTION.rfu1", "RFU", base.HEX, nil, 0xc0)
local bat_version = ProtoField.uint8("BAT_SECTION.version", "Version", base.HEX, nil, 0x3e)
local bat_cn_ind = ProtoField.uint8("BAT_SECTION.cn_ind", "Current Next Indicator", base.HEX, nil, 0x01)
local bat_section_nr = ProtoField.uint8("BAT_SECTION.section_nr", "Section Number", base.HEX)
local bat_last_section_nr = ProtoField.uint8("BAT_SECTION.last_section_nr", "Last Section Number", base.HEX)
local bat_rfu2 = ProtoField.uint8("BAT_SECTION.rfu2", "RFU", base.HEX, nil, 0xf0)
local bat_descriptors_len = ProtoField.uint16("BAT_SECTION.descriptors_len", "Descriptors Length", base.DEC, nil, 0x0fff)
local bat_descriptors = ProtoField.bytes("BAT_SECTION.descriptors", "Descriptors List", base.HEX)
local bat_rfu3 = ProtoField.uint8("BAT_SECTION.rfu3", "RFU", base.HEX, nil, 0xf0)
local bat_ts_stream_loop_length = ProtoField.uint16("TS_STREAM_BLOCKS.stream_loop_len", "Transport Stream Loop Length", base.DEC, nil, 0x0fff)
local bat_crc_32 = ProtoField.uint32("EIT_SECTION.bat_crc_32", "CRC_32", base.HEX)

BAT_SECTION.fields = {bat_bouquet_id, bat_version, bat_cn_ind, bat_section_nr, bat_last_section_nr, bat_descriptors_len, bat_descriptors, bat_rfu1, bat_rfu2, bat_rfu3, bat_ts_stream_loop_length, bat_crc_32}
		
function BAT_SECTION.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(BAT_SECTION, buf(0, buf_len))
	t:add(bat_bouquet_id, buf(0,2))
	t:add(bat_rfu1, buf(2,1))
	t:add(bat_version, buf(2,1))
	t:add(bat_cn_ind, buf(2,1))
	t:add(bat_section_nr, buf(3,1))
	t:add(bat_last_section_nr, buf(4,1))
	t:add(bat_rfu2, buf(5,1))
	local desc_len = bit:_and(buf(5,2):uint(), 0x0fff)
	if desc_len > 0 then
		t:add(bat_descriptors_len, buf(5,2))
		t:add(bat_descriptors, buf(7, desc_len))
		desc_table:get_dissector(0x00):call(buf(7, desc_len):tvb(), pkt, t)
	end
	t:add(bat_rfu3, bit:_and(buf(7+desc_len, 1):uint(), 0xf0))
	t:add(bat_ts_stream_loop_length, bit:_and(buf(7+desc_len, 2):uint(), 0x0fff))
	local ts_desc_len = bit:_and(buf(7+desc_len, 2):uint(), 0x0fff)
	if ts_desc_len > 0 then
                desc_table:get_dissector(0x01):call(buf(7+desc_len, ts_desc_len+2):tvb(), pkt, t)
	end
	t:add(bat_crc_32, buf(buf_len-4, 4))
end	
	
ts_table:add(0xFF12, BAT_SECTION)	
	
------------------------------
--------  SDT SECTION --------
------------------------------

local SDT_SECTION = Proto("SDT_SECTION","SDT Section")
local sdt_ts_id = ProtoField.uint8("SDT_SECTION.ts_id", "Transport Stream Id", base.HEX)
local sdt_rfu1 = ProtoField.uint8("SDT_SECTION.rfu1", "RFU", base.HEX, nil, 0xc0)
local sdt_version = ProtoField.uint8("SDT_SECTION.version", "Version", base.HEX, nil, 0x3e)
local sdt_cn_ind = ProtoField.uint8("SDT_SECTION.cn_ind", "Current Next Indicator", base.HEX, nil, 0x01)
local sdt_section_nr = ProtoField.uint8("SDT_SECTION.section_nr", "Section Number", base.HEX)
local sdt_last_section_nr = ProtoField.uint8("SDT_SECTION.last_section_nr", "Last Section Number", base.HEX)
local sdt_orignal_nwid = ProtoField.uint8("SDT_SECTION.orignal_nwid", "Orignal Network Id", base.HEX)
local sdt_rfu2 = ProtoField.uint8("SDT_SECTION.rfu2", "RFU", base.HEX)
local sdt_service_desc_blocks = ProtoField.bytes("SDT_SECTION.desc_blocks", "Service Descriptor Blocks", base.HEX)

SDT_SECTION.fields = {sdt_ts_id, sdt_version, sdt_cn_ind, sdt_section_nr, sdt_last_section_nr, sdt_orignal_nwid, sdt_service_desc_blocks, sdt_rfu1, sdt_rfu2}

function SDT_SECTION.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(SDT_SECTION, buf(0, buf_len))
	t:add(sdt_ts_id, buf(0,2))
	t:add(sdt_rfu1, buf(2,1))
	t:add(sdt_version, buf(2,1))
	t:add(sdt_cn_ind, buf(2,1))
	t:add(sdt_section_nr, buf(3,1))
	t:add(sdt_last_section_nr, buf(4,1))
	t:add(sdt_orignal_nwid, buf(5,2))
	t:add(sdt_rfu2, buf(7,1))
	t:add(sdt_service_desc_blocks, buf(8, buf_len - 8))
	desc_table:get_dissector(0x02):call(buf(8, buf_len - 8):tvb(), pkt, t)

end

ts_table:add(0xFF13, SDT_SECTION)	

------------------------------
--------  EIT SECTION --------
------------------------------

local EIT_SECTION = Proto("EIT_SECTION","EIT Section")
local eit_service_id = ProtoField.uint8("EIT_SECTION.service_id", "Service Id", base.HEX)
local eit_rfu1 = ProtoField.uint8("EIT_SECTION.rfu1", "RFU", base.HEX, nil, 0xc0)
local eit_version = ProtoField.uint8("EIT_SECTION.version", "Version", base.HEX, nil, 0x3e)
local eit_cn_ind = ProtoField.uint8("EIT_SECTION.cn_ind", "Current Next Indicator", base.HEX, nil, 0x01)
local eit_section_nr = ProtoField.uint8("EIT_SECTION.section_nr", "Section Number", base.HEX)
local eit_last_section_nr = ProtoField.uint8("EIT_SECTION.last_section_nr", "Last Section Number", base.HEX)
local eit_ts_id = ProtoField.uint16("EIT_SECTION.ts_id", "Transport Stream Id", base.HEX)
local eit_original_nwid = ProtoField.uint16("EIT_SECTION.orignal_nwid", "Orignal Network Id", base.HEX)
local eit_segment_last_section_nr = ProtoField.uint8("EIT_SECTION.segment_lsn", "Segment Last Section Number", base.HEX)
local eit_last_table_id = ProtoField.uint8("EIT_SECTION.last_table_id", "Last Table Id", base.HEX)
local eit_event_descriptor_blocks = ProtoField.bytes("EIT_SECTION.desc_blocks", "Event Descriptor Block", base.HEX)
local eit_crc_32 = ProtoField.uint32("EIT_SECTION.eit_crc_32", "CRC_32", base.HEX)

EIT_SECTION.fields = {eit_service_id, eit_version, eit_cn_ind, eit_section_nr, eit_last_section_nr, eit_ts_id, eit_original_nwid, eit_segment_last_section_nr,
					eit_last_table_id, eit_event_descriptor_blocks, eit_rfu1, eit_crc_32}

function EIT_SECTION.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(EIT_SECTION, buf(0, buf_len))
	t:add(eit_service_id, buf(0,2))
	t:add(eit_rfu1, buf(2,1))
	t:add(eit_version, buf(2,1))
	t:add(eit_cn_ind, buf(2,1))
	t:add(eit_section_nr, buf(3,1))
	t:add(eit_last_section_nr, buf(4,1))
	t:add(eit_ts_id, buf(5,2))
	t:add(eit_original_nwid, buf(7,2))
	t:add(eit_segment_last_section_nr, buf(9,1))
	t:add(eit_last_table_id, buf(10,1))
	t:add(eit_event_descriptor_blocks, buf(11, buf_len -11))
	desc_table:get_dissector(0x03):call(buf(11, buf_len - 15):tvb(), pkt, t) 
	t:add(eit_crc_32, buf(buf_len-4, 4))
end

ts_table:add(0xFF14, EIT_SECTION)	
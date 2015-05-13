-- SI.py

local si_table = DissectorTable.new("SI_TABLE", "Service Information", FT_STRING)
local protos = {}


--[[

MUX_STATUS_MSG = 0x0500
MUX_PSI_LOAD = 0x0501
MUX_CLEAR = 0x0502
MUX_PSI_SWITCH = 0x0503
MUX_SI_LOAD = 0x0504
MUX_SI_SWITCH = 0x0505
MUX_SI_INTERSECTION_GAP = 0x0506
MUX_ACK = 0x05FF		

--]]

	--[[

	MUX SI Load Message

	--]]

	local MUX_SI_LOAD = Proto("MUX_SI_LOAD", "SI Load Message")
	local SI_PACKET = Proto("SI_PACKET", "SI Packet")
	f_si_load_stack_id = ProtoField.uint8("MUX_SI_LOAD.stack_id", "Stack Id", base.DEC)
	f_si_load_data_rate = ProtoField.uint16("MUX_SI_LOAD.data_rate", "Data Rate", base.DEC)
	f_si_load_repetition = ProtoField.uint8("MUX_SI_LOAD.repetition", "Repetition", base.DEC)
	f_si_load_packet_count = ProtoField.uint8("MUX_SI_LOAD.packet_count", "Packet Count", base.DEC)
	f_si_load_packet_data = ProtoField.bytes("MUX_SI_LOAD.packet_load", "Packet Load", base.HEX)
	f_si_load_interval = ProtoField.uint16("MUX_SI_LOAD.interval", "Interval", base.DEC)
	f_si_load_si_abort = ProtoField.uint8("MUX_SI_LOAD.si_abort", "SI Abort", base.DEC)
	f_si_load_packet_image = ProtoField.bytes("MUX_SI_LOAD.packet_image", "Packet Image", base.HEX)
	

	MUX_SI_LOAD.fields = {f_si_load_stack_id, f_si_load_data_rate, f_si_load_repetition, f_si_load_packet_count, f_si_load_packet_data,
										f_si_load_interval, f_si_load_si_abort, f_si_load_packet_image}

	function MUX_SI_LOAD.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 6 then
			return false
		end
		--Protocol Info for SI Load Message
		pkt.cols.info = "SI Load Message"
		
		local t = root:add(MUX_SI_LOAD, buf(0,  buf_len))
		t:add(f_si_load_stack_id, buf(0,1))
		t:add(f_si_load_data_rate, buf(1, 2))
		t:add(f_si_load_repetition, buf(3, 1))
		t:add(f_si_load_packet_count, buf(4, 1))
		
		local i = 0
		local packet_count = buf(4,1):uint()
		while i < packet_count do
			local p = t:add(SI_PACKET, buf(5+ i*191,191))
			p:add(f_si_load_interval, buf(5+i*191, 2))
			p:add(f_si_load_si_abort, buf(7+i*191, 1))
			p:add(f_si_load_packet_image, buf(8+i*191, 188))
			
			--Parse the packet image: Mpeg TS packet
			local packet_image = buf(8+i*191, 188):tvb()
			-- if not msp_table:get_dissector(0xFFEB):call(packet_image, pkt, t) then
				-- return false
			-- end	
			ts_table:get_dissector(0xFFFF):call(packet_image, pkt, p)			
			i = i + 1
		end
		
		return true
	end

	si_table:add(0x0504, MUX_SI_LOAD)
	if not protos[0x05] then protos[0x05] = {} end
	protos[0x05][0x04] = si_table:get_dissector(0x0504)


	--[[

	MUX SI Clear Message

	--]]

	local MUX_SI_CLEAR = Proto("MUX_SI_CLEAR", "SI Clear Message")
	f_si_clear_stack_id = ProtoField.uint8("MUX_SI_CLEAR.stack_id", "Stack Id", base.DEC)
	f_si_clear_stack_count = ProtoField.uint8("MUX_SI_CLEAR.stack_count", "Stack Count", base.DEC)

	MUX_SI_CLEAR.fields = {f_si_clear_stack_id, f_si_clear_stack_count}

	function MUX_SI_CLEAR.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		--Protocol Info for SI Clear Message
		pkt.cols.info = "SI Clear Message"
		
		local t = root:add(MUX_SI_CLEAR, buf(0,  buf_len))
		t:add(f_si_clear_stack_count, buf(0,1))
		
		local i = 0
		local statck_count = buf(0,1):uint()
		while i < statck_count do
			t:add(f_si_clear_stack_id, buf(1+i, 1))
			i = i + 1
		end
		
		return true
	end

	si_table:add(0x0502, MUX_SI_CLEAR)
	if not protos[0x05] then protos[0x05] = {} end
	protos[0x05][0x02] = si_table:get_dissector(0x0502)

	--[[

	MUX SI Intersection Gap Message

	--]]

	local MUX_SI_INTERSECTION_GAP = Proto("MUX_SI_INTERSECTION_GAP", "SI Intersection Gap Message")
	f_si_intersection_stack_id = ProtoField.uint8("MUX_SI_INTERSECTION_GAP.stack_id", "Stack Id", base.DEC)
	f_si_intersection_stack_count = ProtoField.uint8("MUX_SI_INTERSECTION_GAP.stack_count", "Stack Count", base.DEC)
	f_si_insersection_section_interval = ProtoField.uint16("MUX_SI_INTERSECTION_GAP.section_interval", "Section Interval", base.DEC)

	MUX_SI_INTERSECTION_GAP.fields = {f_si_intersection_stack_id, f_si_intersection_stack_count, f_si_insersection_section_interval}

	function MUX_SI_INTERSECTION_GAP.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		--Protocol Info for SI Intersection Gap Message
		pkt.cols.info = "SI Intersection Gap Message"
		
		local t = root:add(MUX_SI_INTERSECTION_GAP, buf(0,  buf_len))
		t:add(f_si_intersection_stack_count, buf(0,1))
		
		local i = 0
		local statck_count = buf(0,1):uint()
		while i < statck_count do
			t:add(f_si_intersection_stack_id, buf(1+i*3, 1))
			t:add(f_si_insersection_section_interval, buf(2+i*3, 2))
			i = i + 1
		end
		
		return true
	end

	si_table:add(0x0506, MUX_SI_INTERSECTION_GAP)
	if not protos[0x05] then protos[0x05] = {} end
	protos[0x05][0x06] = si_table:get_dissector(0x0506)
	
		--[[

	MUX SI Switch Message

	--]]

	local MUX_SI_SWITCH = Proto("MUX_SI_SWITCH", "SI Switch Message")
	f_si_switch_stack_id = ProtoField.uint8("MUX_SI_SWITCH.stack_id", "Stack Id", base.DEC)
	f_si_switch_stack_count = ProtoField.uint8("MUX_SI_SWITCH.stack_count", "Stack Count", base.DEC)
	f_si_switch_si_group = ProtoField.uint16("MUX_SI_SWITCH.si_group", "SI Group", base.DEC)

	MUX_SI_SWITCH.fields = {f_si_switch_stack_id, f_si_switch_stack_count, f_si_switch_si_group}

	function MUX_SI_SWITCH.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		--Protocol Info for SI Switch Message
		pkt.cols.info = "SI Switch Message"
		
		local t = root:add(MUX_SI_SWITCH, buf(0,  buf_len))
		t:add(f_si_switch_stack_count, buf(0,1))
		
		local i = 0
		local statck_count = buf(0,1):uint()
		while i < statck_count do
			t:add(f_si_switch_stack_id, buf(1+i*3, 1))
			t:add(f_si_switch_si_group, buf(2+i*3, 2))
			i = i + 1
		end
		
		return true
	end

	si_table:add(0x0505, MUX_SI_SWITCH)
	if not protos[0x05] then protos[0x05] = {} end
	protos[0x05][0x05] = si_table:get_dissector(0x0505)
		
------------------------------------------------
	
	--[[

	SI Protocol

	--]]

	local SI = Proto("SI","Service Information")

	local f_si_version = ProtoField.uint8("SI.VersionFlag", "Version Flag", base.HEX)
	local f_si_length = ProtoField.uint16("SI.Length", "Length", base.DEC)
	local f_si_ackownledge_id = ProtoField.uint8("SI.AcknowledgeId", "Acknowledge Id", base.HEX)
	local f_si_connection = ProtoField.uint8("SI.Connection", "Connection", base.HEX)
	local f_si_type = ProtoField.uint8("SI.Type", "Type", base.HEX)
	local f_si_payload = ProtoField.bytes("SI.payload", "Payload", base.HEX)
	SI.fields = {f_si_version, f_si_length,f_si_ackownledge_id, f_si_connection, f_si_type, f_si_payload}

	-- si dessector function
	function SI.dissector(buf, pkt, root)
		-- check buffer length
        local buf_len = buf:len()
        if buf_len < 7 then
            return false
        end

        --[[
        packet list columns
        --]]
        pkt.cols.protocol = "SI"
        pkt.cols.info = "SI Message"

		local payload_length = buf(1, 2) : uint() - 3
		local connection_type = buf(4,1) : uint()
		local msg_type = buf(5, 1) : uint()
		local offset = 6

        --[[
        dissection tree in packet details
        --]]
        -- tree root
        local t = root:add(SI, buf(0, 6 + payload_length))
        -- child items
        t:add(f_si_version, buf(0,1))
        t:add(f_si_length, buf(1,2))
        t:add(f_si_ackownledge_id, buf(3,1))
		t:add(f_si_connection, buf(4,1))
		t:add(f_si_type, buf(5,1))

		-- call the following dessector depending on the connection_type
		-- the connection_type includes:
		--

		local dissector = nil
		if protos[connection_type] ~= nil then
			dissector = protos[connection_type][msg_type]
		end
		if  dissector ~= nil then
			local payload = buf(offset, payload_length):tvb()
			dissector:call(payload, pkt, t)
			
			if payload_length + offset < buf:len() then
				--proto_table = DissectorTable.get("Protocol Tabel")
				local nextsi = buf(payload_length + offset, buf:len() - payload_length - offset):tvb()
				local parser = proto_table:get_dissector(0x03)
				parser:call(nextsi, pkt, root)
			end
		else
			t:add(f_si_payload, buf(6, buf_len - 6))
		end
		
        return true
	end

	proto_table:add(0x03, SI)
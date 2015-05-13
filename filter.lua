--[[
proto.lua

This file makes msp and dvb dissectors in combination, filter out the msp response message, bind each tcp port
--]]

--PROTOCOL TABLE
proto_table = DissectorTable.new("Protocol Tabel", "Protocol Table", FT_STRING)

do

	function is_send_to_dest_port(cur_port, des_port)
		if cur_port == des_port then
			return true
		else
			return false
		end
	end
	
	function port_need_to_filt(cur_port, src_port, dest_port)
		if cur_port == src_port or cur_port == dest_port then
			return true
		else
			return false
		end
	end
	
	-- data section
	local data_dis = Dissector.get("data")
	
	local IRDETO = Proto("IRDETO", "DVB & MSP Protocol Dissector")
	local unknown = "Unknown Protocol"
	--Bind tcp connection
	local tcp_encap_table = DissectorTable.get("tcp.port")
	f_proto_msp_header = ProtoField.bytes("IRDETO.MSP_Header", "MSP Header", base.HEX)
	f_proto_payload = ProtoField.bytes("IRDETO.Proto_Payload", "Payload", base.HEX)
	
	IRDETO.fields = {f_proto_payload, f_proto_msp_header}
	function irdeto_dessector(buf, pkt, root)
		-- check buffer length
		buf_len = buf:len()
        if buf_len < 1 then
            return false
        end
		-- ignore heading FF
		local buf_len = buf:len()
		local index = 0
		local found = false
		while (not found) and index < buf_len-1 do
			if buf(index,1):uint() == 0xFF then
				index = index + 1
			else
				found = true
			end
		end
		if index ~= 0 then
			if index == buf_len-1 or buf(index,1):uint() ~= 0 then 
				return false 
			end
			index = index + 1
			buf = buf(index, buf_len - index):tvb()
		end
		
		-- check buffer length
		buf_len = buf:len()
        if buf_len < 1 then
            return false
        end
		
		local t= root:add(IRDETO, buf(0, buf_len))
		
		local parse_flag = false
		local version = buf(0,1):uint()		
		
		for key,value in pairs(port_table.key_server_conn_port_table) do
			--Send to Key Server
			if is_send_to_dest_port(value, pkt.dst_port) then
				local parser = proto_table:get_dissector(0x01)
				parser:call(buf, pkt, t)
				parse_flag = true
				
			elseif is_send_to_dest_port(value, pkt.src_port) then
				-- Key Server Response
				pkt.cols.info = "Key Server Response"
				
				t:add("Key Server Response")
				t:add(f_proto_msp_header, buf(0,6))
				if buf_len - 6 > 0 then
					t:add(f_proto_payload, buf(6, buf_len -6))
				end
				parse_flag = true
			end
		end
		
		if parse_flag then
			return true
		--Send to SIG, (if parsed == false and protocal version == 1)
		elseif version == 1 then
			for key,value in pairs(port_table.si_conn_port_table) do
				if is_send_to_dest_port(value, pkt.dst_port) then
					local parser = proto_table:get_dissector(0x03)
					parser:call(buf, pkt, t)	
					parse_flag = true
				elseif is_send_to_dest_port(value, pkt.src) then
					local parser = proto_table:get_dissector(0x03)
					parser:call(buf, pkt, t)	
					parse_flag = true
				end
			end
		end
		
		if parse_flag then
			return true
		--Send to Mux or SCS
		elseif version == 0x1 or version == 0x2 or version == 0x3 or version == 0x5 then
			local parser = proto_table:get_dissector(0x02)
			parser:call(buf, pkt, t)
			parse_flag = true
		end
		
		if parse_flag then
			return true
		elseif version == 0x3 or version == 0x4 then
			--Send to PSIG
			for key,value in pairs(port_table.psi_conn_port_table) do
				if is_send_to_dest_port(pkt.dst_port, value) then
					local parser = proto_table:get_dissector(0x02)
					parser:call(buf, pkt, t)	
					parse_flag = true
				
				elseif is_send_to_dest_port(value, pkt.src_port) then
					local parser = proto_table:get_dissector(0x02)
					parser:call(buf, pkt, t)	
					parse_flag = true
				end
			end
		end
		
		if parse_flag == false then
			t:add(unknown, buf(0, buf_len))
			t:add(f_proto_payload, buf(0, buf_len))
		end

		return true
	end
	
	function IRDETO.dissector(buf, pkt, root)
		if not irdeto_dessector(buf, pkt, root) then
			data_dis:call(buf, pkt, root)
		end
	end
	
	function bindTcpConnection(index, port)
		--Regist the port number
		tcp_encap_table:add(port, IRDETO)
		DissectorTable.get("udp.port"):add(port, IRDETO)
	end
	
	table.foreach(port_table, function(i,v) table.foreach(v, function(i,v) bindTcpConnection(i,v) end) end)

end
--[[

CAM EMM LIBRARY

--]]


	--[[

	CAM EMM Structure

	Now Supported Opcode for CAM EMM List:

	0x0004			-------------			TM Message
	0x0010			-------------			Extened TMS Message
	0x0020			-------------			Global Mapping
	0x0022			-------------			Unique Mapping
	0x0023			-------------			Signed CA
	0x0010			-------------			Tweak Key Download
	0x0025			-------------			Shared Pvrmsk 
	0x0026			-------------			Advanced Proximity Detection 

	... Extend the feature in future

	--]]

	local Cam_EMM = Proto("Cam_EMM", "CamEMM")
	f_cam_opcode = ProtoField.uint16("CamEMM.OpCode", "OpCode", base.HEX)
	f_cam_length = ProtoField.uint16("CamEMM.Length", "Length", base.DEC)
	--3,(N-2)
	f_cam_payload = ProtoField.bytes("CamEMM.Payload", "Payload")
	--4,1
	f_cam_crc = ProtoField.uint16("CamEMM.CRC", "CRC", base.HEX)

	Cam_EMM.fields = {f_cam_opcode, f_cam_length, f_cam_payload, f_cam_crc}

	function Cam_EMM.dissector(buf, pkt, root)

		local buf_len = buf:len()
		local length = buf_len - 4
		local x = buf_len - 6
		local t = root:add(Cam_EMM, buf(0, 4 + length))
		local opcode = buf(0,2) : uint()
		local payload = buf(4,x)
	       t:add( f_cam_opcode, buf(0, 2))
		t:add( f_cam_length, buf(2, 2))

		local parser = nil
		if cam_protos[opcode] ~= nil then
			parser = cam_protos[opcode]
		end

		if parser ~= nil then
			parser:call(payload:tvb(), pkt, t)
		else
			t:add( f_cam_payload, payload)
		end


		t:add( f_cam_crc, buf(4+x, 2))

	end

	cam_table:add(0xFFFF, Cam_EMM)


	--[[

	CAM EMM :  Unique mapping Table  Opcode --> 0x0022

	]]--

	local UniqueMapping = Proto("UniqueMapping", "UniqueMapping")
	--0,2
	f_unique_mapping_lock_id = ProtoField.uint16("UniqueMapping.LockId", "LockId", base.HEX)
	--2,1  0,4
	f_unique_mapping_length_of_native_id_field = ProtoField.uint8("UniqueMapping.LengthofNative", "LengthofNative", base.HEX, nil, 0xf0)
	--2,1  4,4
	f_unique_mapping_rfu= ProtoField.uint8("UniqueMapping.Rfu", "Rfu", base.HEX, nil, 0x0f)
      --3,4
	f_unique_mapping_native_id = ProtoField.bytes("UniqueMapping.NativeID", "NativeID")
	--7,4
	f_unique_mapping_mapped_id = ProtoField.bytes("UniqueMapping.MappedID", "MappedID")

	UniqueMapping.fields = {f_unique_mapping_lock_id, f_unique_mapping_length_of_native_id_field, f_unique_mapping_rfu, f_unique_mapping_native_id, f_unique_mapping_mapped_id}

	function UniqueMapping.dissector(buf, pkt, root)
	    local t = root:add(UniqueMapping, buf(0, 11))
		t:add( f_unique_mapping_lock_id, buf(0, 2))
		t:add( f_unique_mapping_length_of_native_id_field, buf(2,1))
		t:add( f_unique_mapping_rfu, buf(2,1))
		t:add( f_unique_mapping_native_id, buf(3, 4))
		t:add( f_unique_mapping_mapped_id, buf(7, 4))

	end

	--register cam ccp opcode table
	cam_table:add(0x0022, UniqueMapping)
	cam_protos = {
					[0x0022] = cam_table:get_dissector(0x0022)
}

	--[[

	CAM EMM : Global mapping Table   Opcode -->  0x0020

	]]--

	local GlobalMapping = Proto("GlobalMapping", "GlobalMapping")
	--0,1
	f_global_mapping_table_index = ProtoField.uint8("GlobalMapping.TableIndex", "Table Index", base.DEC)
	--1,1
	f_global_mapping_table_count = ProtoField.uint8("GlobalMapping.TableCount", "Table Count", base.DEC)
	--2,1
	f_global_mapping_table_version = ProtoField.uint8("GlobalMapping.TableVersion", "Table Version", base.DEC)
    --3,2
	f_global_mapping_lock_id = ProtoField.uint16("GlobalMapping.LockId", "Lock Id", base.HEX)
	--5,4
	f_global_mapping_start_of_native_range = ProtoField.bytes("GlobalMapping.NativeRange", "Native Range")
	--9,4
	f_global_mapping_start_of_mapped_range = ProtoField.bytes("GlobalMapping.MappedRange", "Mapped Range")

	GlobalMapping.fields = {f_global_mapping_table_index, f_global_mapping_table_count, f_global_mapping_table_version, f_global_mapping_lock_id, f_global_mapping_start_of_native_range, f_global_mapping_start_of_mapped_range}

	function GlobalMapping.dissector(buf, pkt, root)
	    local t = root:add(GlobalMapping, buf(0,  13))
		t:add( f_global_mapping_table_index, buf(0, 1))
		t:add( f_global_mapping_table_count , buf(1, 1))
		t:add( f_global_mapping_table_version, buf(2, 1))
		t:add( f_global_mapping_lock_id, buf(3, 2))
		t:add( f_global_mapping_start_of_native_range, buf(5, 4))
		t:add( f_global_mapping_start_of_mapped_range, buf(9, 4))
	end

	--register cam ccp opcodes table
	cam_table:add(0x0020, GlobalMapping)
	cam_protos[0x0020] = cam_table:get_dissector(0x0020)
	
	
	--[[

	CAM EMM : Global mapping  Table Opcode 0x0021

	]]--

	local Global_Mapping = Proto("Global_Mapping", "Global Mapping Table")
	--0,1
	f_cam_global_mapping_table_index = ProtoField.uint8("Global_Mapping.TableIndex", "Table Index", base.DEC)
	--1,1
	f_cam_global_mapping_table_count = ProtoField.uint8("Global_Mapping.TableCount", "Table Count", base.DEC)
	--2,1
	f_cam_global_mapping_table_version = ProtoField.uint8("Global_Mapping.TableVersion", "Table Version", base.DEC)
    --3,2
	f_cam_global_mapping_lock_id = ProtoField.uint16("Global_Mapping.LockId", "Lock Id", base.HEX)
	--5,1,4
	f_cam_global_mapping_length_native_range = ProtoField.string("Global_Mapping.LNR", "Length of Native Range")
	--5,1,3
	f_cam_global_mapping_length_range_length = ProtoField.string("Global_Mapping.LRL", "Length of Range Length")
	--5,1,1
	f_cam_global_mapping_rfu = ProtoField.string("Global_Mapping.rfu", "RFU")
	--6,4
	f_cam_global_mapping_start_of_native_range = ProtoField.bytes("Global_Mapping.NativeRange", "Native Range")
	--10,4
	f_cam_global_mapping_start_of_mapped_range = ProtoField.bytes("Global_Mapping.MappedRange", "Mapped Range")
	--14,lrl
	f_cam_global_mapping_range_length = ProtoField.bytes("Global_Mapping.RangeLength", "Range Length")

	Global_Mapping.fields = {f_cam_global_mapping_table_index, f_cam_global_mapping_table_count, f_cam_global_mapping_table_version, f_cam_global_mapping_lock_id,
											f_cam_global_mapping_start_of_native_range, f_cam_global_mapping_start_of_mapped_range, f_cam_global_mapping_length_native_range,
											f_cam_global_mapping_length_range_length, f_cam_global_mapping_rfu, f_cam_global_mapping_range_length
											}

	function Global_Mapping.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
	
	    local t = root:add(Global_Mapping, buf(0,  buf_len))
		local len_range_length = bit:_and(bit:_rshift(buf(5,1) : uint(), 1), 0x07)
		t:add( f_cam_global_mapping_table_index, buf(0, 1))
		t:add( f_cam_global_mapping_table_count , buf(1, 1))
		t:add( f_cam_global_mapping_table_version, buf(2, 1))
		t:add( f_cam_global_mapping_lock_id, buf(3, 2))
		t:add(f_cam_global_mapping_length_native_range, bit:_rshift(buf(5,1) : uint(), 4))
		t:add(f_cam_global_mapping_length_range_length, len_range_length)
		t:add(f_cam_global_mapping_rfu, bit:_and(buf(5,1) : uint(), 0x01))	
		t:add( f_cam_global_mapping_start_of_native_range, buf(6, 4))
		t:add( f_cam_global_mapping_start_of_mapped_range, buf(10, 4))
		t:add(f_cam_global_mapping_range_length, buf(14, len_range_length))
	end

	--register cam ccp opcodes table
	cam_table:add(0x0021, Global_Mapping)
	cam_protos[0x0021] = cam_table:get_dissector(0x0021)


	--[[

	CAM EMM : TM Message  Opcode --> 0x0004

	--]]

	local TM_Message = Proto("TM_Message", "TM Message")
	f_tm_message_number = ProtoField.uint8("TM_Message.msg_number", "Message Number", base.DEC, nil, 0xf0)
	f_tm_message_expression_length = ProtoField.uint16("TM_Message.expression_length", "Expression Length", base.DEC, nil, 0xfff)
	f_tm_message_expression = ProtoField.bytes("TM_Message.expression", "Expression", base.HEX)
	f_tm_message_routing = ProtoField.uint8("TM_Message.routing", "Routing", base.HEX, {[0]='SC',[1]='CAM',[2]='IRD'})
	f_tm_message_payload = ProtoField.bytes("TM_Message.payload", "Payload", base.HEX)

	TM_Message.fields = {f_tm_message_number, f_tm_message_expression_length, f_tm_message_expression, f_tm_message_routing, f_tm_message_payload}

	function TM_Message.dissector(buf, pkt ,root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local expression_length = bit:_and(buf(0,2):uint(), 0x0fff)
		local expression = buf(2, expression_length)
		local routing = buf(2+expression_length, 1)
		local t = root:add(TM_Message, buf(0, buf_len))
		t:add(f_tm_message_number, buf(0,1))
		t:add(f_tm_message_expression_length, buf(0,2))
		t:add(f_tm_message_expression, expression)
		t:add(f_tm_message_routing, routing)

		local payload = buf(2+expression_length+1, buf_len-3-expression_length)
		local emmrouting = routing:uint()
		local parser
		if emmrouting == 0 then
			parser = msp_table:get_dissector(0xFFFF)
		elseif emmrouting == 1 then
			parser = cam_table:get_dissector(0xFFFF)
		elseif emmrouting == 2 then
			parser = ird_table:get_dissector(0xFFFF)
		else
			return false
		end

		parser:call(payload:tvb(), pkt, t)

	end

	cam_table:add(0x0004, TM_Message)
	cam_protos[0x0004] = cam_table:get_dissector(0x0004)

	--[[


	CAM EMM : Signed CCP CAM Opcode --> 0x0023

	--]]

	local Signed_Message = Proto("Signed_Message", "Signed CCP CAM Message")
	f_singed_rfu_1 = ProtoField.uint8("Signed_Message.rfu_1", "RFU Byte", base.HEX)
	f_signed_rfu_2 = ProtoField.uint8("Signed_Message.rfu_2", "RFU Bit", base.HEX, nil, 0xc0)
	f_signed_key_version = ProtoField.uint8("Signed_Message.signing_key_version", "Signing Key Version", base.HEX, nil, 0x38)
	f_signed_signature_type = ProtoField.uint8("Signed_Message.signature_type", "Signature Type", base.HEX, nil, 0x07)
	f_signed_address_type = ProtoField.uint8("Signed_Message.address_type", "Address Type", base.HEX, nil, 0xf8)
	f_signed_address_length = ProtoField.uint8("Signed_Message.address_length", "Address Length", base.HEX, nil, 0x07)
	f_signed_address = ProtoField.bytes("Signed_Message.address", "Address", base.HEX)
	f_signed_sc_payload = ProtoField.bytes("Signed_Message.sc_payload", "SC Payload", base.HEX)
	f_signed_signature = ProtoField.bytes("Signed_Message.signature", "Signature", base.HEX)

	Signed_Message.fields = {f_singed_rfu_1, f_signed_rfu_2, f_signed_key_version, f_signed_signature_type, f_signed_address_type,
							f_signed_address_length, f_signed_address, f_signed_sc_payload, f_signed_signature}

	function Signed_Message.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(Signed_Message, buf(0, buf_len))
		t:add(f_singed_rfu_1, buf(0,1):uint())

		t:add(f_signed_rfu_2, buf(1,1))
		t:add(f_signed_key_version, buf(1,1))
		t:add(f_signed_signature_type, buf(1,1))
		t:add(f_singed_rfu_1, buf(2,1):uint())

		local address_length = bit:_and(buf(3,1):uint(), 0x07)
		t:add(f_signed_address_type, buf(3,1))
		t:add(f_signed_address_length, buf(3,1))
		t:add(f_signed_address, buf(4, address_length))

		t:add(f_signed_sc_payload, buf(4+address_length, buf_len -4-address_length- 128)) -- L(BUF_LEN)-4-N(ADDR_LENGTH) - L_SIG(128) - L_CRC(2) (Ignore)
		t:add(f_signed_signature, buf(buf_len -128, 128))


	end

	cam_table:add(0x0023, Signed_Message)
	cam_protos[0x0023] = cam_table:get_dissector(0x0023)


	--[[

	CAM EMM : Extended TMS Message Opcode --> 0x0010

	--]]

	local Extended_TMS = Proto("Extended_TMS", "Extended TMS Message")
	f_extended_tms_reserverd = ProtoField.string("Extended_TMS.reserved", "Reserved")
	f_extended_tms_expression_length = ProtoField.string("Extended_TMS.expression_length", "Expression Length", base.DEC)
	f_extended_tms_expression = ProtoField.bytes("Extended_TMS.expression", "Expression", base.HEX)
	f_extended_tms_routing = ProtoField.uint8("Extended_TMS.routing", "Routing", base.HEX)
	f_extended_tms_total_segments = ProtoField.uint8("Extended_TMS.total_segments", "Total Segments", base.HEX)
	f_extended_tms_segment_number = ProtoField.uint8("Extended_TMS.segment_number", "Segment Number", base.HEX)
	f_extended_tms_secure_ird = ProtoField.bytes("Extended_TMS.secure_ird", "Encrypted IRD", base.HEX)
	f_extended_tms_emm_payload = ProtoField.bytes("Extended_TMS.emm_payload", "EMM Payload", base.HEX)


	Extended_TMS.fields = {f_extended_tms_reserverd, f_extended_tms_expression_length, f_extended_tms_expression, f_extended_tms_routing,
							f_extended_tms_total_segments, f_extended_tms_segment_number, f_extended_tms_emm_payload, f_extended_tms_secure_ird}

	function Extended_TMS.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(Extended_TMS, buf(0, buf_len))
		local reserved = bit:_rshift(buf(0,1):uint(), 4)
		local expression_length = bit:_and(buf(0,2):uint(), 0x0fff)
		t:add(f_extended_tms_reserverd, reserved)
		t:add(f_extended_tms_expression_length, expression_length)
		t:add(f_extended_tms_expression, buf(2, expression_length))
		local routing = buf(2+expression_length, 1) :uint()
		t:add(f_extended_tms_routing, buf(2+expression_length, 1))
		t:add(f_extended_tms_total_segments, buf(2+expression_length+1, 1))
		t:add(f_extended_tms_segment_number, buf(2+expression_length+2, 1))


		local payload = buf(2+expression_length+3, buf_len - 5- expression_length)

		--[[

		Routing

		SC =  0

		CAM = 1

		IRD = 2

		Secure IRD = 3

		IUC Secure IRD =4 parse??

		TODO

		--]]
		
		if routing == 4 then
			t:add(f_extended_tms_secure_ird, payload)
		else
			t:add(f_extended_tms_emm_payload, payload)
		end

	end


	cam_table:add(0x0010, Extended_TMS)
	cam_protos[0x0010] = cam_table:get_dissector(0x0010)
	
	
	--[[


	CAM EMM : Tweak Key Download Opcode --> 0x000A

	--]]

	local TWEAK_KEY_DOWNLOAD = Proto("TWEAK_KEY_DOWNLOAD", "Tweak Key Download EMM")
	f_tweak_key_operator_id = ProtoField.uint16("TWEAK_KEY_DOWNLOAD.operator_id", "Operator Id", base.DEC)
	f_tweak_key_sequence_nr = ProtoField.uint8("TWEAK_KEY_DOWNLOAD.sequence_nr", "Sequence Number", base.DEC)
	f_tweak_key_detweak0 = ProtoField.bytes("TWEAK_KEY_DOWNLOAD.detweak0", "De-Tweak Key 0", base.HEX)
	f_tweak_key_detweak1 = ProtoField.bytes("TWEAK_KEY_DOWNLOAD.detweak1", "De-Tweak Key 1", base.HEX)
	f_tweak_key_magic_number = ProtoField.bytes("TWEAK_KEY_DOWNLOAD.magic_number", "Magic Number", base.HEX)


	TWEAK_KEY_DOWNLOAD.fields = {f_tweak_key_operator_id, f_tweak_key_sequence_nr, f_tweak_key_detweak0, f_tweak_key_detweak1,
							f_tweak_key_magic_number}

	function TWEAK_KEY_DOWNLOAD.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(TWEAK_KEY_DOWNLOAD, buf(0, buf_len))
		t:add(f_tweak_key_operator_id, buf(0,2))
		t:add(f_tweak_key_sequence_nr, buf(2,1))
		t:add(f_tweak_key_detweak0, buf(3,8))
		t:add(f_tweak_key_detweak1, buf(11,8))
		t:add(f_tweak_key_magic_number, buf(19,8))


	end

	cam_table:add(0x000a, TWEAK_KEY_DOWNLOAD)
	cam_protos[0x000a] = cam_table:get_dissector(0x000a)
	
	--[[

	CAM EMM : Shared PVRMSK Opcode --> 0x0025

	--]]
	local SHARED_PVRMSK = Proto("SHARED_PVRMSK", "Shared Pvrmsk opcode")
	f_shared_pvrmsk_clienttype = ProtoField.uint8("SHARED_PVRMSK.clienttype", "Client Type", base.HEX, {[1]="PVR Phase 3", [0]="PVR Phase 2"}, 0x80)
	f_shared_pvrmsk_rfu1 = ProtoField.uint8("SHARED_PVRMSK.rfu", "Reserved", base.HEX, nil, 0x7e)
	f_shared_pvrmsk_pk9include = ProtoField.bool("SHARED_PVRMSK.pk9include", "Pkey 9 included", base.HEX, nil, 0x01)
	f_shared_pvrmsk_ddid = ProtoField.uint32("SHARED_PVRMSK.ddid", "Unique ID of device domain", base.Dec)
	f_shared_pvrmsk_nrPvrmsk = ProtoField.uint8("SHARED_PVRMSK.nrPvrmsk", "Number of PVRMSK EMM", base.HEX)
	f_shared_pvrmsk_pkey9Emm = ProtoField.bytes("SHARED_PVRMSK.pkey9Emm", "Pkey 9 Emm", base.HEX)
	f_shared_pvrmsk_ForEachPvrmsk = Proto("SHARED_PVRMSK.ForEachPvrmsk", "PvrmskBlock")
	f_shared_pvrmsk_idType = ProtoField.uint8("SHARED_PVRMSK.ForEachPvrmsk.idType", "ID Type", base.HEX, {[1]="SN",[2]="UA",[0]="CSSN"}, 0xc0)
	f_shared_pvrmsk_rfu2 = ProtoField.uint8("SHARED_PVRMSK.ForEachPvrmsk.rfu", "Reserved", base.HEX, nil, 0x3f)
	f_shared_pvrmsk_devicdId = ProtoField.uint32("SHARED_PVRMSK.ForEachPvrmsk.devicdId", "Device Identifier", base.Dec)
	f_shared_pvrmsk_pvrmskEmm = ProtoField.bytes("SHARED_PVRMSK.ForEachPvrmsk.pvrmskemm", "Pvrmsk Emm", base.HEX)


	SHARED_PVRMSK.fields = { f_shared_pvrmsk_clienttype, f_shared_pvrmsk_rfu1,
							f_shared_pvrmsk_pk9include,f_shared_pvrmsk_ddid,f_shared_pvrmsk_nrPvrmsk,f_shared_pvrmsk_pkey9Emm}
							
	f_shared_pvrmsk_ForEachPvrmsk.fields = {f_shared_pvrmsk_idType,f_shared_pvrmsk_rfu2,f_shared_pvrmsk_devicdId,f_shared_pvrmsk_pvrmskEmm}

	function SHARED_PVRMSK.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(SHARED_PVRMSK, buf(0, buf_len))
		t:add(f_shared_pvrmsk_clienttype, buf(0,1))
		t:add(f_shared_pvrmsk_rfu1, buf(0,1))
		t:add(f_shared_pvrmsk_pk9include, buf(0,1))
		t:add(f_shared_pvrmsk_ddid, buf(1,4))
		t:add(f_shared_pvrmsk_nrPvrmsk, buf(5,1))
		
		offset = 6
		if bit:_and(buf(0,1):uint(), 0x1) == 0x1 then
			l = buf(offset + 7,1):uint()
			t:add(f_shared_pvrmsk_pkey9Emm, buf(offset,l))
			offset = offset + l
		end
		while offset + 2 < buf_len do
			l = buf(offset + 1 + 4 + 7,1):uint()
			local tt = t:add(f_shared_pvrmsk_ForEachPvrmsk, buf(offset, 1 + 4 + 7 + l + 1))
			tt:add(f_shared_pvrmsk_idType, buf(offset,1))
			tt:add(f_shared_pvrmsk_rfu2, buf(offset,1))
			tt:add(f_shared_pvrmsk_devicdId, buf(offset+1,4))
			tt:add(f_shared_pvrmsk_pvrmskEmm, buf(offset + 1 + 4, l + 7 + 1))
			offset = offset + 1 + 4 + 7 + l + 1
		end
	end

	cam_table:add(0x0025, SHARED_PVRMSK)
	cam_protos[0x0025] = cam_table:get_dissector(0x0025)
	
	
	--[[


	CAM EMM : Advanced Proximity Detection Opcode --> 0x0026

	--]]
	
	local PROXIMITY_DETECTION = Proto("Proximity_Detection", "Proximity Detection EMM")
	f_proximity_detection_length = ProtoField.uint16("PROXIMITY_DETECTION.length", "length", base.DEC)
	f_proximity_detection_enabled = ProtoField.uint8("PROXIMITY_DETECTION.enabled", "enabled", base.DEC, nil, 0x80)
	f_proximity_detection_reserved = ProtoField.bytes("PROXIMITY_DETECTION.reserved", "reserved", base.HEX)
	f_proximity_detection_round_trip_time = ProtoField.bytes("PROXIMITY_DETECTION.RoundTriptime", "round trip time", base.HEX)
	f_proximity_detection_timeout = ProtoField.bytes("PROXIMITY_DETECTION.timeout", "timeout", base.HEX)
	f_proximity_detection_response_timeout = ProtoField.bytes("PROXIMITY_DETECTION.responseTimeout", "response timeout", base.HEX)
	f_proximity_detection_retry_count = ProtoField.bytes("PROXIMITY_DETECTION.retryCount", "retry count", base.HEX)
	
	PROXIMITY_DETECTION.fields = { f_proximity_detection_length, f_proximity_detection_enabled,	f_proximity_detection_reserved,
								f_proximity_detection_round_trip_time,f_proximity_detection_timeout,
								f_proximity_detection_response_timeout,f_proximity_detection_retry_count}
	
	
	function PROXIMITY_DETECTION.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(PROXIMITY_DETECTION, buf(0, buf_len))
		t:add(f_proximity_detection_enabled, buf(0,1))
		t:add(f_proximity_detection_reserved, buf(0,1))
		t:add(f_proximity_detection_round_trip_time, buf(1,1))
		t:add(f_proximity_detection_timeout, buf(2,2))
		t:add(f_proximity_detection_response_timeout, buf(4,2))
		t:add(f_proximity_detection_retry_count, buf(6,1))
		
	end

	cam_table:add(0x0026, PROXIMITY_DETECTION)
	cam_protos[0x0026] = cam_table:get_dissector(0x0026)
	
	--[[

	CAM EMM : SKE Link Protection Opcode --> 0x0027

	--]]
	
	local SKE_LINK_PROTECTION = Proto("SKE_LINK_PROTECTION", "SKE Link Protection")
	f_skelp_msg_skelp_type = ProtoField.uint8("SKE_LINK_PROTECTION.skelp_type", "SKELP Type", base.DEC)
	f_skelp_msg_fragment_nr = ProtoField.uint8("SKE_LINK_PROTECTION.fragment_nr", "Fragment Number", base.HEX, nil, 0xd0)
	f_skelp_msg_total_fragments = ProtoField.uint8("SKE_LINK_PROTECTION.total_fragments", "Total Fragments", base.HEX, nil, 0x1c)
	f_skelp_msg_rfu = ProtoField.uint8("SKE_LINK_PROTECTION.rfu", "Reserved", base.HEX, nil, 0x03)
	f_skelp_msg_sc_emm = ProtoField.bytes("SKE_LINK_PROTECTION.sc_emm", "SC EMM", base.HEX)
	
	SKE_LINK_PROTECTION.fields = {f_skelp_msg_skelp_type, f_skelp_msg_fragment_nr, f_skelp_msg_total_fragments, f_skelp_msg_rfu, f_skelp_msg_sc_emm}
	
	function SKE_LINK_PROTECTION.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local t = root:add(SKE_LINK_PROTECTION, buf(0, buf_len))
		t:add(f_skelp_msg_skelp_type, buf(0,1))
		t:add(f_skelp_msg_fragment_nr, buf(1,1))
		t:add(f_skelp_msg_total_fragments, buf(1,1))
		t:add(f_skelp_msg_rfu, buf(1,1))
		t:add(f_skelp_msg_sc_emm, buf(2,buf_len - 2))
		
	end

	cam_table:add(0x0027, SKE_LINK_PROTECTION)
	cam_protos[0x0027] = cam_table:get_dissector(0x0027)
--------------------------------
----Import Header Structure-----
--------------------------------

--DVB TABLE
dvb_table = DissectorTable.new("DVB_TABLE", "DVB MESSAGE", FT_STRING)

--CAM EMM TABLE
cam_table = DissectorTable.new("CAM_TABLE", "CAM Message", FT_STRING)

--IRD EMM TABLE
ird_table = DissectorTable.new("IRD_TABLE", "IRD Message", FT_STRING)

--DVB PROTOCOL TABLE
--proto_dvb_table = DissectorTable.new("Protocol DVB Tabel", "Protocol DVB Table", FT_STRING)

accepted_dvb_version = {1, 2, 3, 4, 5}

local protos = {}



----------------------------------------------------------------------------------------------------------------------------------------------------

------------------------------

--------  Function -----------

------------------------------


	local function is_version_valid(version)
		local is_valid = false
		for i,v in pairs(accepted_dvb_version) do
			if version == v then
				is_valid = true
				break
			end
		end
		return is_valid
	end
	
	local function check_valid_ts(buf, length)
		local offset = 0
		local ts_flag = true
		
		if length % 188 ~= 0 then
			return false
		end
		
		while offset < length do
			cur_byte = buf(offset, 1):uint()
			if cur_byte ~= 0x47 then
				ts_flag = false
				break
			end
			offset = offset + 188
		end
		return ts_flag
	end
	
	local function append_mux_emmg_para(buf, pkt, tree)
		local idx = 0
		local emm_section = nil
		local buf_len = buf:len()
		while idx < buf_len do
			local tag = buf(idx,2):uint()
			if MUX_EMMG_PARA_DICT[tag] ~= nil then	
				local subTree= nil
				local arg_length = nil
				if MUX_EMMG_PARA_DICT[tag].length ~= nil then
					arg_length = MUX_EMMG_PARA_DICT[tag].length
				else
					arg_length = buf(idx + 2, 2):uint()
				end

				if idx + 4 + arg_length <= buf_len then
					
					local subTree = tree:add(MUX_EMMG_PARA_DICT[tag].proto, buf(idx, arg_length + 4))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', tostring(arg_length))
					subTree:add('VALUE: ', tostring(buf(idx + 4, arg_length)))
					
					if tostring(MUX_EMMG_PARA_DICT[tag].proto) == 'Proto: MUX_EMMG_ERROR_STATUS' then
						local error_info = buf(idx + 4, arg_length):uint()
						subTree:add('Error Info: ', EMMG_ERROR_STATUS_VALUE_MAP[error_info])
					
					elseif tostring(MUX_EMMG_PARA_DICT[tag].proto) == 'Proto: MUX_EMMG_DATAGRAM' then
						emm_section = buf(idx + 4, arg_length)
						if check_valid_ts(emm_section, arg_length) then
							local tsi = 0
							while tsi < arg_length do
								emm_buf = buf(idx + 4 + tsi, 188):tvb()
								ts_table:get_dissector(0xFFFF):call(emm_buf, pkt, subTree)
								tsi = tsi + 188
							end
						else
							emm_buf = emm_section:tvb()
							if ENABLE_IRDETO_CRYPTO_WORKS == true then
								ice_table:get_dissector(0xFF00):call(emm_buf, pkt, subTree)
							else
								ts_table:get_dissector(0xFF00):call(emm_buf, pkt, subTree)
							end
						end
					
					elseif tostring(MUX_EMMG_PARA_DICT[tag].proto) == 'Proto: MUX_EMMG_METADATA' then
						metadata_table:get_dissector(0xFFFF):call(buf(idx+4, arg_length):tvb(), pkt, subTree)
					end
					
				elseif buf_len - idx > 4 and buf_len -idx < 4 + arg_length then
					local subTree = tree:add(MUX_EMMG_PARA_DICT[tag].proto, buf(idx, buf_len - idx))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', tostring(buf(idx+2, 2)))
					subTree:add('VALUE (Fragement): ', tostring(buf(idx + 4, buf_len-idx-4)))
					return true				
				else
					local subTree = tree:add('Fragement Message', buf(buf_len - idx))
					subTree:add('Payload: ', buf(buf_len - idx))
					return true									
				end
				
				idx = idx + arg_length + 4	
			else
				return false
			end
		
		end		
	end
			
	local function append_scs_ecmg_para(buf, pkt, tree)
		local idx = 0
		local buf_len = buf:len()
		while idx < buf_len do
			local tag = buf(idx,2):uint()
			if SCS_ECMG_PARA_DICT[tag] ~= nil then	
				local subTree = nil
				local arg_length = nil
				if SCS_ECMG_PARA_DICT[tag].length ~= nil then
					arg_length = SCS_ECMG_PARA_DICT[tag].length
				else
					arg_length = buf(idx + 2, 2):uint()
				end
				
				if idx + 4 + arg_length <= buf_len then
		
					local subTree = tree:add(SCS_ECMG_PARA_DICT[tag].proto, buf(idx, arg_length + 4))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', tostring(arg_length))
					valTree = subTree:add('VALUE: ', tostring(buf(idx + 4, arg_length)))				
					
					if tostring(SCS_ECMG_PARA_DICT[tag].proto) == 'Proto: SCS_ECMG_ERROR_STATUS' then
						local error_info = buf(idx + 4, arg_length):uint()
						subTree:add('Error Info: ', ECMG_ERROR_STATUS_VALUE_MAP[error_info])
			
					elseif tostring(SCS_ECMG_PARA_DICT[tag].proto) == 'Proto: SCS_ECMG_ECM_DATAGRAM' then
						local ecm_section = buf(idx + 4, arg_length):tvb()
						if check_valid_ts(ecm_section, arg_length) then
							local tsi = 0
							while tsi < arg_length do
								ecm_buf = buf(idx + 4 + tsi, 188):tvb()
								ts_table:get_dissector(0xFFFF):call(ecm_buf, pkt, subTree)
								tsi = tsi + 188
							end
						else
							ecm_buf = ecm_section
							if ENABLE_IRDETO_CRYPTO_WORKS == true then
								ice_table:get_dissector(0xFF00):call(emm_buf, pkt, subTree)
							else
								ts_table:get_dissector(0xFF00):call(emm_buf, pkt, subTree)
							end
						end
					elseif tostring(SCS_ECMG_PARA_DICT[tag].proto) == 'Proto: SCS_ECMG_ACCESS_CRITERIA' then
						local ac = buf(idx + 4, arg_length):tvb()
						--ac_table:get_dissector(0x90FF):call(ac, pkt, subTree)
						local ptype = buf(idx + 4, 2):uint()
						local dissec = ac_protos[ptype]
						if dissec ~= nil then
							dissec:call(ac, pkt, valTree)
						end
					elseif tostring(SCS_ECMG_PARA_DICT[tag].proto) == 'Proto: SCS_ECMG_OLD_ECM' then
						local ecm_buf = buf(idx + 4, arg_length):tvb()
						local dissec = ts_table:get_dissector(0xFF00):call(ecm_buf, pkt, subTree)
					end	

				elseif buf_len - idx > 4 and buf_len -idx < 4 + arg_length then
					local subTree = tree:add(SCS_ECMG_PARA_DICT[tag].proto, buf(idx, buf_len - idx))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', tostring(buf(idx+2, 2)))
					subTree:add('VALUE (Fragement): ', tostring(buf(idx + 4, buf_len-idx-4)))
					return true				
				else
					local subTree = tree:add('Fragement Message', buf(buf_len - idx))
					subTree:add('Payload: ', buf(buf_len - idx))
					return true				
				end
				
				idx = idx + arg_length + 4				
			else
				return false
			end
		
		end		
	end

	--CPSIG <==> PSIG
	local function append_psig_cpsig_para(buf, pkt, tree)
		local idx = 0
		local buf_len = buf:len()
		while idx < buf_len do
			local tag = buf(idx,2):uint()
			if CPSIG_PSIG_PARA_DICT[tag] ~= nil then	
				local subTree = nil
				local arg_length = nil
				if CPSIG_PSIG_PARA_DICT[tag].length ~= nil then
					arg_length = CPSIG_PSIG_PARA_DICT[tag].length
				else
					arg_length = buf(idx + 2, 2):uint()
				end
				
				if idx + 4 + arg_length <= buf_len then
		
					local subTree = tree:add(CPSIG_PSIG_PARA_DICT[tag].proto, buf(idx, arg_length + 4))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', arg_length)
					
					if tostring(CPSIG_PSIG_PARA_DICT[tag].proto) == 'Proto: CPSIG_DESCRIPTOR' then
						desc_table:get_dissector(0x00):call(buf(idx + 4, arg_length):tvb(), pkt, subTree)
					else
						valTree = subTree:add('VALUE: ', tostring(buf(idx + 4, arg_length)))
					end	

				elseif buf_len - idx > 4 and buf_len -idx < 4 + arg_length then
					local subTree = tree:add(CPSIG_PSIG_PARA_DICT[tag].proto, buf(idx, buf_len - idx))
					subTree:add('TAG: ', tostring(buf(idx, 2)))
					subTree:add('LENGTH: ', tostring(buf(idx+2, 2)))
					subTree:add('VALUE (Fragement): ', tostring(buf(idx + 4, buf_len-idx-4)))
					return true				
				else
					local subTree = tree:add('Fragement Message', buf(buf_len - idx))
					subTree:add('Payload: ', buf(buf_len - idx))
					return true				
				end
				
				idx = idx + arg_length + 4				
			else
				return false
			end
		
		end		
	end	

------------------------------------------------------------------------------------------------------------------------------------

-------------------------------------
-------PROTOCOLS DEFINITION----------
-------------------------------------

--[[ 

	EMMG <==> MUX Channel Specific Messages
	
	--  Channel_Setup  				Message
	--  Channel_Test    			Message
	--  Channel_Status 				Message
	--  Channel_Close  				Message
	--  Channel_Error   			Message
	
	EMMG <==> MUX Stream Specific Message:

	-- Stream_Setup  				Message
	-- Stream_Test    				Message
	-- Stream_Status 				Message
	-- Stream_Close_Request 		Message
	-- Stream_Close_Response 		Message
	-- Stream_Error					Message
	-- Stream_BW_request			Message
	-- Stream_BW_allocation			Message
	
	-- Data_Provision
	
--------------------------------------------------
	
	ECMG <==> SCS  Channel Specific Message:
	
	--  Channel_Setup  				Message
	--  Channel_Test    			Message
	--  Channel_Status 				Message
	--  Channel_Close				Message
	--  Channel_Error  				Message
	
	ECMG <==> SCS Stream Specific Message:

	-- Stream_Setup  				Message
	-- Stream_Test    				Message
	-- Stream_Status 				Message
	-- Stream_Close_Request 		Message
	-- Stream_Close_Response 		Message
	-- Stream_Error					Message	
	
	-- CW_Provision
	-- ECM_Response
	-- ECM Replacement Message

]]--	
		
	-- MESSAGE TYPE DEFINITION FOR MUX - EMMG
	local MUX_EMMG_MSG_GENERIC = Proto("MUX_EMMG_MSG_GENERIC", "EMMG <==> MUX Specific Message")
	local EMMG_DATA_PROVISION = Proto("EMMG_DATA_PROVISION", "Data Provision")
	local EMMG_CHANNEL_SETUP = Proto("EMMG_CHANNEL_SETUP", "EMMG Channel Setup Message")
	local EMMG_CHANNEL_TEST = Proto("EMMG_CHANNEL_TEST", "EMMG Channel Test Message")
	local EMMG_CHANNEL_STATUS = Proto("EMMG_CHANNEL_STATUS", "EMMG Channel Status Message")
	local EMMG_CHANNEL_CLOSE = Proto("EMMG_CHANNEL_CLOSE", "EMMG Channel Close Message")
	local EMMG_CHANNEL_ERROR = Proto("EMMG_CHANNEL_ERROR", "EMMG Channel Error Message")
	
	local EMMG_STREAM_SETUP = Proto("EMMG_STREAM_SETUP", "EMMG Stream Setup Message")
	local EMMG_STREAM_TEST = Proto("EMMG_STREAM_TEST", "EMMG Stream Test Message")
	local EMMG_STREAM_STATUS = Proto("EMMG_STREAM_STATUS", "EMMG Stream Status Message")
	local EMMG_STREAM_CLOSE_REQUEST = Proto("EMMG_STREAM_CLOSE_REQUEST", "EMMG Stream Close Request Message")
	local EMMG_STREAM_CLOSE_RESPONSE = Proto("EMMG_STREAM_CLOSE_RESPONSE", "EMMG Stream Close Response Message")
	local EMMG_STREAM_ERROR = Proto("EMMG_STREAM_ERROR", "EMMG Stream Error Message")
	local EMMG_STREAM_BW_REQUEST = Proto("EMMG_STREAM_BW_REQUEST", "EMMG Stream Bandwidth Request Message")
	local EMMG_STREAM_BW_ALLOCATION = Proto("EMMG_STREAM_BW_ALLOCATION", "EMMG Stream Bandwidth Allocation Message")
	
	--MESSAGE TYPE DEFINITION FOR SCS - ECMG
	local SCS_ECMG_MSG_GENERIC = Proto("SCS_ECMG_MSG_GENERIC", "ECMG <==> SCS Specific Message")
	local ECMG_CHANNEL_SETUP = Proto("ECMG_CHANNEL_SETUP", "ECMG Channel Setup Message")
	local ECMG_CHANNEL_TEST = Proto("ECMG_CHANNEL_TEST", "ECMG Channel Test Message")
	local ECMG_CHANNEL_STATUS = Proto("ECMG_CHANNEL_STATUS", "ECMG Channel Status Message")
	local ECMG_CHANNEL_CLOSE = Proto("ECMG_CHANNEL_CLOSE", "ECMG Channel Close Message")
	local ECMG_CHANNEL_ERROR = Proto("ECMG_CHANNEL_ERROR", "ECMG Channel Error Message")
	
	local ECMG_STREAM_SETUP = Proto("ECMG_STREAM_SETUP", "ECMG Stream Setup Message")
	local ECMG_STREAM_TEST = Proto("ECMG_STREAM_TEST", "ECMG Stream Test Message")
	local ECMG_STREAM_STATUS = Proto("ECMG_STREAM_STATUS", "ECMG Stream Status Message")
	local ECMG_STREAM_CLOSE_REQUEST = Proto("ECMG_STREAM_CLOSE_REQUEST", "ECMG Stream Close Request Message")
	local ECMG_STREAM_CLOSE_RESPONSE = Proto("ECMG_STREAM_CLOSE_RESPONSE", "ECMG Stream Close Response Message")
	local ECMG_STREAM_ERROR = Proto("ECMG_STREAM_ERROR", "ECMG Stream Error Message")
	local ECMG_CW_PROVISION = Proto("ECMG_CW_PROVISION", "CW PROVISION Message")
	local ECMG_ECM_RESPONSE = Proto("ECMG_ECM_RESPONSE", "ECM Response Message")
	local ECMG_ECM_REPLACEMENT = Proto("ECMG_ECM_REPLACEMENT", "ECM Replacement Message")
	
	--MESSAGE TYPE DEFINITION FOR CPSIG - PSIG
	local CPSIG_PSIG_MSG_GENERIC = Proto("CPSIG_PSIG_MSG_GENERIC", "CPSIG <==> PSIG Specific Message")
	local CPSIG_CHANNEL_SETUP = Proto("CPSIG_CHANNEL_SETUP", "CPSIG Channel Setup Message")
	local CPSIG_CHANNEL_TEST = Proto("CPSIG_CHANNEL_TEST", "CPSIG Channel Test Message")
	local CPSIG_CHANNEL_STATUS = Proto("CPSIG_CHANNEL_STATUS", "CPSIG Channel Status Message")
	local CPSIG_CHANNEL_CLOSE = Proto("CPSIG_CHANNEL_CLOSE", "CPSIG Channel Close Message")
	local CPSIG_CHANNEL_ERROR = Proto("CPSIG_CHANNEL_ERROR", "CPSIG Channel Error Message")
	
	local CPSIG_STREAM_SETUP = Proto("CPSIG_STREAM_SETUP", "CPSIG Stream Setup Message")
	local CPSIG_STREAM_TEST = Proto("CPSIG_STREAM_TEST", "CPSIG Stream Test Message")
	local CPSIG_STREAM_STATUS = Proto("CPSIG_STREAM_STATUS", "CPSIG Stream Status Message")
	local CPSIG_STREAM_CLOSE = Proto("CPSIG_STREAM_CLOSE", "CPSIG Stream Close")
	local CPSIG_STREAM_CLOSE_REQUEST = Proto("CPSIG_STREAM_CLOSE_REQUEST", "CPSIG Stream Close Request Message")
	local CPSIG_STREAM_CLOSE_RESPONSE= Proto("CPSIG_STREAM_CLOSE_RESPONSE", "CPSIG Stream CLose Response Message")
	local CPSIG_STREAM_ERROR= Proto("CPSIG_STREAM_ERROR", "CPSIG Stream Error MessagE")
	local CPSIG_DESCRIPTOR_INSERT_REQUEST = Proto("CPSIG_DESCRIPTOR_INSERT_REQUEST", "CPSIG Descriptor Insert Request")
	local CPSIG_DESCRIPTOR_INSERT_RESPONSE = Proto("CPSIG_DESCRIPTOR_INSERT_RESPONSE", "CPSIG Descriptor Insert Response")
	
	-- MAP PROTOCOL
	DVB_MSG_TYPE_DICT = {
								--EMMG <==> MUX 	
								[0x0011] =  {proto = EMMG_CHANNEL_SETUP,		 desc = "[EMMG ==> MUX : Channel Setup]"},	
								[0x0012] =  {proto = EMMG_CHANNEL_TEST,			 desc = "[EMMG <==> MUX : Channel Test]"},	
								[0x0013] =  {proto = EMMG_CHANNEL_STATUS,		 desc = "[EMMG <== MUX : Channel Status]"},	
								[0x0014] =  {proto = EMMG_CHANNEL_CLOSE,		 desc = "[EMMG ==> MUX : Channel Close]"}, 
								[0x0015] =  {proto = EMMG_CHANNEL_ERROR,		 desc = "[EMMG <==> MUX : Channel Error]"},	
								[0x0111] =  {proto = EMMG_STREAM_SETUP,			 desc = "[EMMG ==> MUX : Stream Setup]"},	
								[0x0112] =  {proto = EMMG_STREAM_TEST,			 desc = "[EMMG <==> MUX : Stream Test]"},	
								[0x0113] =  {proto = EMMG_STREAM_STATUS,		 desc = "[EMMG <==> MUX : Stream Status]"},	
								[0x0114] =  {proto = EMMG_STREAM_CLOSE_REQUEST,  desc = "[EMMG ==> MUX : Stream Close Request]"},	
								[0x0115] =  {proto = EMMG_STREAM_CLOSE_RESPONSE, desc = "[EMMG <== MUX : Stream Close Response]"},	
								[0x0116] =  {proto = EMMG_STREAM_ERROR, 		 desc = "[EMMG <==> MUX : Stream Error]"},			
								[0x0117] =  {proto = EMMG_STREAM_BW_REQUEST, 	 desc = "[EMMG ==> MUX : Stream BW Request]"},		
								[0x0118] =  {proto = EMMG_STREAM_BW_ALLOCATION,  desc = "[EMMG <== MUX : Stream BW Allocation]"},	
								[0x0211] =  {proto = EMMG_DATA_PROVISION, 		 desc = "[EMMG ==> MUX ] : Data Provision"},	
								
								--ECMG <==> SCS
								[0x0001] =  {proto = ECMG_CHANNEL_SETUP,		 desc = "[ECMG <== SCS : Channel Setup]"},		
								[0x0002] =  {proto = ECMG_CHANNEL_TEST,			 desc = "[ECMG <==> SCS : Channel Test]"},		
								[0x0003] =  {proto = ECMG_CHANNEL_STATUS, 		 desc = "[ECMG <==> SCS : Channel Status]"},			
								[0x0004] =  {proto = ECMG_CHANNEL_CLOSE,		 desc = "[ECMG <== SCS : Channel Close]"},			
								[0x0005] =  {proto = ECMG_CHANNEL_ERROR,		 desc = "[ECMG <==> SCS : Channel Error]"},	
								[0x0101] =  {proto = ECMG_STREAM_SETUP,			 desc = "[ECMG <== SCS : Stream Setup]"},				
								[0x0102] =  {proto = ECMG_STREAM_TEST,			 desc = "[ECMG <==> SCS : Stream Test]"},	
								[0x0103] =  {proto = ECMG_STREAM_STATUS,		 desc = "[ECMG <==> SCS : Stream Status]"},				
								[0x0104] =  {proto = ECMG_STREAM_CLOSE_REQUEST,  desc = "[ECMG <== SCS : Stream Close Request]"},			
								[0x0105] =  {proto = ECMG_STREAM_CLOSE_RESPONSE, desc = "[ECMG ==> SCS : Stream Close Response]"},		
								[0x0106] =  {proto = ECMG_STREAM_ERROR,			 desc = "[ECMG <==> SCS : Stream Error]"},										
								[0x0201] =  {proto = ECMG_CW_PROVISION,			 desc = "[ECMG <== SCS : CW Provision]"}, 								
								[0x0202] =  {proto = ECMG_ECM_RESPONSE,			 desc = "[ECMG ==> SCS : ECM Response]"},
								[0xa001] =  {proto = ECMG_ECM_REPLACEMENT,	     desc = "[ECMG <== SCS : ECM Replacement]"},
								
								--CPSIG <==> PSIG
								[0x0301] =  {proto = CPSIG_CHANNEL_SETUP,		 			desc = "[CPSIG <== PSIG : Channel Setup]"},		
								[0x0303] =  {proto = CPSIG_CHANNEL_TEST,		 			desc = "[CPSIG <==> PSIG : Channel Test]"},		
								[0x0302] =  {proto = CPSIG_CHANNEL_STATUS, 	 			desc = "[CPSIG <==> PSIG : Channel Status]"},			
								[0x0304] =  {proto = CPSIG_CHANNEL_CLOSE,		 			desc = "[CPSIG <== PSIG : Channel Close]"},			
								[0x0305] =  {proto = CPSIG_CHANNEL_ERROR,		 			desc = "[CPSIG <==> PSIG : Channel Error]"},
								[0x0311] =  {proto = CPSIG_STREAM_SETUP,		 			desc = "[CPSIG <== PSIG : Stream Setup]"},				
								[0x0313] =  {proto = CPSIG_STREAM_TEST,		 			desc = "[CPSIG <==> PSIG : Stream Test]"},	
								[0x0312] =  {proto = CPSIG_STREAM_STATUS,		 			desc = "[CPSIG <==> PSIG : Stream Status]"},
								[0x0314] =  {proto = CPSIG_STREAM_CLOSE,  				desc = "[CPSIG <== PSIG : Stream Close]"},							
								[0x0315] =  {proto = CPSIG_STREAM_CLOSE_REQUEST,  		desc = "[CPSIG ==> PSIG : Stream Close Request]"},			
								[0x0316] =  {proto = CPSIG_STREAM_CLOSE_RESPONSE, 		desc = "[CPSIG <== PSIG : Stream Close Response]"},
								[0x0317] =  {proto = CPSIG_STREAM_ERROR,					desc = "[CPSIG <==> PSIG : Stream Error]"},
								[0x031E] =  {proto = CPSIG_DESCRIPTOR_INSERT_REQUEST,		desc = "[CPSIG ==> PSIG : Descriptor Insert Request]"},
								[0x031F] =  {proto = CPSIG_DESCRIPTOR_INSERT_RESPONSE,	desc = "[CPSIG <== PSIG : Descriptor Insert Response]"},
						}
	
--------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------

-------------  FIEILD DEFINITION -----------------

---------------------------------------------------	
	
	-- MUX_EMMG PARAMETER
	local MUX_EMMG_CLIENT_ID  = Proto("MUX_EMMG_CLIENT_ID", "Client ID")
	local MUX_EMMG_SECTION_TSPKT_FLAG = Proto("MUX_EMMG_SECTION_TSPKT_FLAG", "MUX Section TSpkt Flag")
	local MUX_EMMG_DATA_CHANNEL_ID = Proto("MUX_EMMG_DATA_CHANNEL_ID", "Data Channel ID")
	local MUX_EMMG_DATA_STREAM_ID = Proto("MUX_EMMG_DATA_STREAM_ID", "Data Stream ID")
	local MUX_EMMG_DATAGRAM = Proto("MUX_EMMG_DATAGRAM", "EMM Datagram")
	local MUX_EMMG_BANDWITH = Proto("MUX_EMMG_BANDWITH", "Bandwidth")
	local MUX_EMMG_DATA_TYPE = Proto("MUX_EMMG_DATA_TYPE", "Data Type")
	local MUX_EMMG_DATA_ID = Proto("MUX_EMMG_DATA_ID", "Data ID")
	local MUX_EMMG_ERROR_STATUS = Proto("MUX_EMMG_ERROR_STATUS", "MUX Error Status")	
	local MUX_EMMG_METADATA = Proto("MUX_EMMG_METADATA", "MetaData")
	
	
	-- SCS_ECMG PARAMETER
	local SCS_ECMG_SUPER_CAS_ID = Proto("SCS_ECMG_SUPER_CAS_ID", "Super CAS ID")
	local SCS_ECMG_SECTION_TSPKT_FLAG = Proto("SCS_ECMG_SECTION_TSPKT_FLAG", "ECM Section TSpkt Flag")
	local SCS_ECMG_DELAY_START = Proto("SCS_ECMG_DELAY_START", "Delay Start")
	local SCS_ECMG_DELAY_STOP = Proto("SCS_ECMG_DELAY_STOP", "Delay Stop")
	local SCS_ECMG_TRANSITION_DELAY_START = Proto("SCS_ECMG_TRANSITION_DELAY_START", "Transition Delay Start")
	local SCS_ECMG_TRANSITION_DELAY_STOP = Proto("SCS_ECMG_TRANSITION_DELAY_STOP", "Transition Delay Stop")
	local SCS_ECMG_ECM_REP_PERIOD = Proto("SCS_ECMG_ECM_REP_PERIOD", "ECM Rep Period")
	local SCS_ECMG_MAX_STREAMS = Proto("SCS_ECMG_MAX_STREAMS", "Max Streams")
	local SCS_ECMG_MIN_CP_DURATION = Proto("SCS_ECMG_MIN_CP_DURATION", "Min CP Duration")
	local SCS_ECMG_LEAD_CW = Proto("SCS_ECMG_LEAD_CW", "LEAD CW")
	local SCS_ECMG_CW_PER_MSG = Proto("SCS_ECMG_CW_PER_MSG", "CW Per Msg")
	local SCS_ECMG_MAX_COMP_TIME = Proto("SCS_ECMG_MAX_COMP_TIME", "Max Comp Time")
	local SCS_ECMG_ACCESS_CRITERIA = Proto("SCS_ECMG_ACCESS_CRITERIA", "Access Criteria")
	local SCS_ECMG_ECM_CHANNEL_ID = Proto("ECM_CHANNEL_ID", "ECM Channel ID")
	local SCS_ECMG_ECM_STREAM_ID = Proto("ECM_STREAM_ID", "ECM Stream ID")
	local SCS_ECMG_NOMINAL_CP_DURATION = Proto("SCS_ECMG_NOMINAL_CP_DURATION", "Nominal CP Duration")
	local SCS_ECMG_AC_TRANSFER_MODE = Proto("SCS_ECMG_AC_TRANSFER_MODE", "Access Criteria Transfer Mode")
	local SCS_ECMG_CP_NUMBER = Proto("SCS_ECMG_CP_NUMBER", "CP Number")
	local SCS_ECMG_CP_DURATION = Proto("SCS_ECMG_CP_DURATION", "CP Duration")
	local SCS_ECMG_CP_CW_COMBINATION = Proto("SCS_ECMG_CP_CW_COMBINATION", "CP CW Combination")
	local SCS_ECMG_ECM_DATAGRAM = Proto("SCS_ECMG_ECM_DATAGRAM", "ECM Datagram")
	local SCS_ECMG_AC_DELAY_START = Proto("SCS_ECMG_AC_DELAY_START", "AC Delay Start")
	local SCS_ECMG_AC_DELAY_STOP = Proto("SCS_ECMG_AC_DELAY_STOP", "AC Delay Stop")
	local SCS_ECMG_CW_ENCRYPTION = Proto("SCS_ECMG_CW_ENCRYPTION", "CW Encryption")
	local SCS_ECMG_ECM_ID = Proto("SCS_ECMG_ECM_ID", "ECM ID")
	local SCS_ECMG_ERROR_STATUS = Proto("SCS_ECMG_ERROR_STATUS", "SCS Error Status")	
	local SCS_ECMG_OLD_ECM = Proto("SCS_ECMG_OLD_ECM", "Old ECM")	

	-- CPSIG_PSIG PARAMETER
	local CPSIG_PSIG_BOUQUET_ID = Proto("CPSIG_BOUQUET_ID", "bouquet ID")
	local CPSIG_PSIG_CA_DESCRIPTOR_INSERTION_MODE = Proto("CPSIG_CA_DESCRIPTOR_INSERTION_MODE", "CA_descriptor_insertion_mode")
	local CPSIG_PSIG_CUSTOM_CAS_ID = Proto("CPSIG_CUSTOM_CAS_ID", "custom_CAS_id")	
	local CPSIG_PSIG_CUSTOM_CHANNEL_ID = Proto("CPSIG_CUSTOM_CHANNEL_ID", "custom_channel_id")
	local CPSIG_PSIG_CUSTOM_STREAM_ID = Proto("CPSIG_CUSTOM_STREAM_ID", "custom_stream_id")
	local CPSIG_PSIG_DESCRIPTOR = Proto("CPSIG_DESCRIPTOR", "Descriptors Block")
	local CPSIG_PSIG_DESCRIPTOR_INSERT_STATUS = Proto("CPSIG_DESCRIPTOR_INSERT_STATUS", "descriptor_insert_status")
	local CPSIG_PSIG_ES_ID = Proto("CPSIG_ES_ID", "ES_id")
	local CPSIG_PSIG_EVENT_ID = Proto("CPSIG_EVENT_ID", "event_id")
	local CPSIG_PSIG_INSERTION_DELAY = Proto("CPSIG_INSERTION_DELAY", "insertion_delay")
	local CPSIG_PSIG_INSERTION_DELAY_TYPE = Proto("CPSIG_INSERTION_DELAY_TYPE", "insertion_delay_type")
	local CPSIG_PSIG_LOCATION_ID = Proto("CPSIG_LOCATION_ID", "location_id")
	local CPSIG_PSIG_MAX_STREAMS = Proto("CPSIG_MAX_STREAMS", "max_streams")
	local CPSIG_PSIG_NETWORK_ID = Proto("CPSIG_NETWORK_ID", "network_id")
	local CPSIG_PSIG_ORIGINAL_NETWORK_ID = Proto("CPSIG_ORIGINAL_NETWORK_ID", "original_network_id")
	local CPSIG_PSIG_PRIVATE_DATA_SPECIFER = Proto("CPSIG_PRIVATE_DATA_SPECIFER", "private_data_specifier")
	local CPSIG_PSIG_PSIG_TYPE = Proto("CPSIG_PSIG_TYPE", "PSIG_type")
	local CPSIG_PSIG_SERVICE_ID = Proto("CPSIG_SERVICE_ID", "service_id")
	local CPSIG_PSIG_TRIGGER_LIST = Proto("CPSIG_TRIGGER_LIST", "trigger_list")
	local CPSIG_PSIG_TRIGGER_ID = Proto("CPSIG_TRIGGER_ID", "trigger_id")
	local CPSIG_PSIG_ERROR_STATUS = Proto("CPSIG_ERROR_STATUS", "error_status")
	local CPSIG_PSIG_ERROR_INFORMATION = Proto("CPSIG_ERROR_INFORMATION", "error_information")
	local CPSIG_PSIG_TRANSPORT_STREAM_ID = Proto("CPSIG_TRANSPORT_STREAM_ID", "transport_stream_id")
	local CPSIG_PSIG_TRANSACTION_ID = Proto("CPSIG_TRANSACTION_ID", "transaction_id")
	
	
	-- PARAMETER MAP DICTIONARY
	MUX_EMMG_PARA_DICT = {
							[0x0001] = {proto = MUX_EMMG_CLIENT_ID, length = 4},
							[0x0002] = {proto = MUX_EMMG_SECTION_TSPKT_FLAG, length = 1},
							[0x0003] = {proto = MUX_EMMG_DATA_CHANNEL_ID, length = 2},
							[0x0004] = {proto = MUX_EMMG_DATA_STREAM_ID, length = 2},
							[0x0005] = {proto = MUX_EMMG_DATAGRAM, length = nil},
							[0x0006] = {proto = MUX_EMMG_BANDWITH, length = 2},
							[0x0007] = {proto = MUX_EMMG_DATA_TYPE, length = 1},
							[0x0008] = {proto = MUX_EMMG_DATA_ID, length = 2},
							[0x7000] = {proto = MUX_EMMG_ERROR_STATUS, length = 2},
							[0x9200] = {proto = MUX_EMMG_METADATA, length = nil}
	}	
	
	
	SCS_ECMG_PARA_DICT = {
							[0x0001] = {proto = SCS_ECMG_SUPER_CAS_ID, length = 4},
							[0x0002] = {proto = SCS_ECMG_SECTION_TSPKT_FLAG, length = 1},
							[0x0003] = {proto = SCS_ECMG_DELAY_START, length = 2},
							[0x0004] = {proto = SCS_ECMG_DELAY_STOP, length = 2},
							[0x0005] = {proto = SCS_ECMG_TRANSITION_DELAY_START, length = 2},
							[0x0006] = {proto = SCS_ECMG_TRANSITION_DELAY_STOP, length = 2},
							[0x0007] = {proto = SCS_ECMG_ECM_REP_PERIOD, length = 2},
							[0x0008] = {proto = SCS_ECMG_MAX_STREAMS, length = 2},
							[0x0009] = {proto = SCS_ECMG_MIN_CP_DURATION, length = 2},
							[0x000a] = {proto = SCS_ECMG_LEAD_CW, length = 1},
							[0x000b] = {proto = SCS_ECMG_CW_PER_MSG, length = 1},
							[0x000c] = {proto = SCS_ECMG_MAX_COMP_TIME, length = 2},
							[0x000d] = {proto = SCS_ECMG_ACCESS_CRITERIA, length = nil},
							[0x000e] = {proto = SCS_ECMG_ECM_CHANNEL_ID, length = 2},
							[0x000f] = {proto = SCS_ECMG_ECM_STREAM_ID, length = 2},
							[0x0010] = {proto = SCS_ECMG_NOMINAL_CP_DURATION, length = 2},
							[0x0011] = {proto = SCS_ECMG_AC_TRANSFER_MODE, length = 1},
							[0x0012] = {proto = SCS_ECMG_CP_NUMBER, length = 2},
							[0x0013] = {proto = SCS_ECMG_CP_DURATION, length = 2},
							[0x0014] = {proto = SCS_ECMG_CP_CW_COMBINATION, length = nil},
							[0x0015] = {proto = SCS_ECMG_ECM_DATAGRAM, length = nil},
							[0x0016] = {proto = SCS_ECMG_AC_DELAY_START, length = 2},
							[0x0017] = {proto = SCS_ECMG_AC_DELAY_STOP, length = 2},
							[0x0018] = {proto = SCS_ECMG_CW_ENCRYPTION, length = nil},
							[0x0019] = {proto = SCS_ECMG_ECM_ID, length = 2},
							[0x7000] = {proto = SCS_ECMG_ERROR_STATUS, length = 2},
							[0x9103] = {proto = SCS_ECMG_OLD_ECM, length = nil}
	}
	
	
	CPSIG_PSIG_PARA_DICT = {
							[0x0100] = {proto = CPSIG_PSIG_BOUQUET_ID, length = 2},
							[0x0101] = {proto = CPSIG_PSIG_CA_DESCRIPTOR_INSERTION_MODE, length = 1},
							[0x0102] = {proto = CPSIG_PSIG_CUSTOM_CAS_ID, length = 4},
							[0x0103] = {proto = CPSIG_PSIG_CUSTOM_CHANNEL_ID, length = 2},
							[0x0104] = {proto = CPSIG_PSIG_CUSTOM_STREAM_ID , length = 2},
							[0x0105] = {proto = CPSIG_PSIG_DESCRIPTOR, length = nil},
							[0x0106] = {proto = CPSIG_PSIG_DESCRIPTOR_INSERT_STATUS, length = 1},
							[0x010B] = {proto = CPSIG_PSIG_ES_ID, length = 2},
							[0x010C] = {proto = CPSIG_PSIG_EVENT_ID, length = 2},
							[0x0113] = {proto = CPSIG_PSIG_INSERTION_DELAY, length = 2},
							[0x0114] = {proto = CPSIG_PSIG_INSERTION_DELAY_TYPE, length = 1},
							[0x0116] = {proto = CPSIG_PSIG_LOCATION_ID, length = 1},
							[0x0118] = {proto = CPSIG_PSIG_MAX_STREAMS, length = 2},
							[0x011A] = {proto = CPSIG_PSIG_NETWORK_ID, length = 2},
							[0x011B] = {proto = CPSIG_PSIG_ORIGINAL_NETWORK_ID, length = 2},
							[0x011D] = {proto = CPSIG_PSIG_PRIVATE_DATA_SPECIFER, length = 4},
							[0x011E] = {proto = CPSIG_PSIG_PSIG_TYPE, length = 1},
							[0x0120] = {proto = CPSIG_PSIG_SERVICE_ID, length = 2},
							[0x0129] = {proto = CPSIG_PSIG_TRIGGER_LIST, length = 4},
							[0x0128] = {proto = CPSIG_PSIG_TRIGGER_ID, length = 2},
							[0x7000] = {proto = CPSIG_PSIG_ERROR_STATUS, length = nil},
							[0x7001] = {proto = CPSIG_PSIG_ERROR_INFORMATION, length = nil},
							[0x0127] = {proto = CPSIG_PSIG_TRANSPORT_STREAM_ID, length = 2},
							[0x0126] = {proto = CPSIG_PSIG_TRANSACTION_ID, length = 2}
	}
	
	
--------------------------------------------------------------------------------------------------------------

----------------------------------------------------

---------  PROTOCOL DISSECTOR FUNCTION -------------

----------------------------------------------------	

	function MUX_EMMG_MSG_GENERIC.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 2 then
			return false
		end
		append_mux_emmg_para(buf, pkt, root)

	end
	
	function SCS_ECMG_MSG_GENERIC.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 2 then
			return false
		end
		append_scs_ecmg_para(buf, pkt, root)
	end
	
	function CPSIG_PSIG_MSG_GENERIC.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 2 then
			return false
		end
		append_psig_cpsig_para(buf, pkt, root)
	end
	
-----------------------------------------------------------------------------------------------

-----------------------------------

------  REGISTER PROTOCOL ---------

-----------------------------------

	dvb_table:add(0x0011, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0012, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0014, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0013, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0015, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0111, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0112, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0113, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0114, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0115, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0116, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0117, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0118, MUX_EMMG_MSG_GENERIC)
	dvb_table:add(0x0211, MUX_EMMG_MSG_GENERIC)
	
	protos[0x0011] = dvb_table:get_dissector(0x0011)	
	protos[0x0012] = dvb_table:get_dissector(0x0012)		
	protos[0x0014] = dvb_table:get_dissector(0x0014)		
	protos[0x0013] = dvb_table:get_dissector(0x0013)		
	protos[0x0015] = dvb_table:get_dissector(0x0015)
	protos[0x0111] = dvb_table:get_dissector(0x0111)	
	protos[0x0112] = dvb_table:get_dissector(0x0112)		
	protos[0x0113] = dvb_table:get_dissector(0x0113)			
	protos[0x0114] = dvb_table:get_dissector(0x0114)			
	protos[0x0115] = dvb_table:get_dissector(0x0115)	
	protos[0x0116] = dvb_table:get_dissector(0x0116)	
	protos[0x0117] = dvb_table:get_dissector(0x0117)		
	protos[0x0118] = dvb_table:get_dissector(0x0118)
	protos[0x0211] = dvb_table:get_dissector(0x0211)
	
	
	dvb_table:add(0x0001, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0002, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0003, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0004, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0005, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0101, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0102, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0103, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0104, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0105, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0106, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0201, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0x0202, SCS_ECMG_MSG_GENERIC)
	dvb_table:add(0xa001, SCS_ECMG_MSG_GENERIC)

	protos[0x0001] = dvb_table:get_dissector(0x0001)
	protos[0x0002] = dvb_table:get_dissector(0x0002)	
	protos[0x0003] = dvb_table:get_dissector(0x0003)	
	protos[0x0004] = dvb_table:get_dissector(0x0004)	
	protos[0x0005] = dvb_table:get_dissector(0x0005)	
	protos[0x0101] = dvb_table:get_dissector(0x0101)	
	protos[0x0102] = dvb_table:get_dissector(0x0102)	
	protos[0x0103] = dvb_table:get_dissector(0x0103)	
	protos[0x0104] = dvb_table:get_dissector(0x0104)
	protos[0x0105] = dvb_table:get_dissector(0x0105)
	protos[0x0106] = dvb_table:get_dissector(0x0106)	
	protos[0x0201] = dvb_table:get_dissector(0x0201)	
	protos[0x0202] = dvb_table:get_dissector(0x0202)	
	protos[0xa001] = dvb_table:get_dissector(0xa001)
	
	--CPSIG <==> PSIG
	dvb_table:add(0x0301, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0303, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0302, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0304, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0305, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0311, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0313, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0312, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0314, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0315, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0316, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x0317, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x031E, CPSIG_PSIG_MSG_GENERIC)
	dvb_table:add(0x031F, CPSIG_PSIG_MSG_GENERIC)
               
	protos[0x0301] = dvb_table:get_dissector(0x0301)
	protos[0x0303] = dvb_table:get_dissector(0x0303)	
	protos[0x0302] = dvb_table:get_dissector(0x0302)	
	protos[0x0304] = dvb_table:get_dissector(0x0304)	
	protos[0x0305] = dvb_table:get_dissector(0x0305)	
	protos[0x0311] = dvb_table:get_dissector(0x0311)	
	protos[0x0313] = dvb_table:get_dissector(0x0313)	
	protos[0x0312] = dvb_table:get_dissector(0x0312)	
	protos[0x0314] = dvb_table:get_dissector(0x0314)
	protos[0x0315] = dvb_table:get_dissector(0x0315)
	protos[0x0316] = dvb_table:get_dissector(0x0316)	
	protos[0x0317] = dvb_table:get_dissector(0x0317)	
	protos[0x031E] = dvb_table:get_dissector(0x031E)	
	protos[0x031F] = dvb_table:get_dissector(0x031F)
---------------------------------------------------------------------------------------------------------------


	local DVBS = Proto("DVBS", "Irdeto DVB Simulcrypt")

	local f_dvb_version = ProtoField.uint8("DVBS.VersionFlag", "Version Flag", base.HEX)
	local f_dvb_msg_type = ProtoField.uint16("DVBS.MsgType", "Message Type", base.HEX)
	local f_dvb_length = ProtoField.uint16("DVBS.Length", "Length", base.DEC)
	local f_dvb_payload = ProtoField.bytes("DVBS.Payload", "Payload")
	local f_dvb_unknown_payload = ProtoField.bytes("DVBS.unknown_payload", "Unknown DVB Version or Splited Message", base.HEX)
	DVBS.fields = {f_dvb_version, f_dvb_msg_type, f_dvb_length, f_dvb_payload, f_dvb_unknown_payload}

	function DVBS.dissector(buf, pkt, root)
	-- check buffer length
		local buf_len = buf:len()
		if buf_len < 5 then
			return false
		end

	--- packet list columns
		pkt.cols.protocol = "DVB"
		pkt.cols.info = "DVB Simulcrypt Protocol"
		
		local start_index = 0
		local t = nil
		while start_index < buf_len do
		
			local msg_version = buf(start_index, 1):uint()
			local msg_type = buf(start_index+1,2):uint()
			local msg_length = buf(start_index+3,2):uint()
			if start_index + msg_length + 5 > buf_len then
				msg_length = buf_len - start_index - 5
			end
			
			if is_version_valid(msg_version) then

				--dissection tree in packet details
				t = root:add(DVBS, buf(start_index, msg_length + 5))
				
				-- child items
				t:add(f_dvb_version, buf(start_index,1))
				t:add(f_dvb_msg_type, buf(start_index+1,2))
				t:add(f_dvb_length, buf(start_index+3,2))

				--call the following dessector depending on the msg_type

				local dessector = nil
				if protos[msg_type] ~= nil then
					dessector = protos[msg_type]
					proto_name = DVB_MSG_TYPE_DICT[msg_type].proto
					proto_info = DVB_MSG_TYPE_DICT[msg_type].desc
				end
				if dessector ~= nil then
					pkt.cols.info = proto_info
					subTree = t:add(proto_name, buf(start_index+5, msg_length))
					local payload = buf(start_index+5, msg_length):tvb()
					dessector:call(payload,pkt,subTree)
				else
					t:add(f_dvb_payload, buf(start_index+5, msg_length))
				end
			
				start_index = start_index + msg_length + 5
				
			else
				t = root:add(DVBS, buf(start_index, buf_len))
				t:add(f_dvb_unknown_payload, buf(start_index, buf_len))
				start_index = start_index + buf_len
			end

		end -- end while
		
	end -- end function

	proto_table:add(0x02, DVBS)
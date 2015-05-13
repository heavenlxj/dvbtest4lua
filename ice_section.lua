--ICE Section
ice_table = DissectorTable.new("ICE_TABLE", "ICE Section", FT_STRING)

--ICE Section Table IDs
ice_accept_tables = {0x80, 0x81, 0x82, 0x84, 0x86, 0x88, 0x89}

-- ICE ECM Accepted Length List
ice_ecm_len_list = {0x65, 0x60, 0x98, 0xd8}

-- ICE ECM
ice_ecm_table_ids = {0x80, 0x81}

-- ICE Global EMM
ice_global_msg = {0x88, 0x89}

-- ICE Shared EMM
ice_shared_msg = 0x84

-- ICE Global Shared Msg
ice_global_shared_msg = 0x86

-- ICE Unique Msg
ice_unique_msg = 0x82

---------------------------------------------------
------------		ICE TLV		 ------------------
---------------------------------------------------

local ICE_TLV_UNIQUE_ADDRESS = Proto("ICE_TLV_UNIQUE_ADDRESS", "ICE UNIQUE ADDRESS TLV")
local ICE_TLV_SHARED_ADDRESS = Proto("ICE_TLV_SHARED_ADDRESS", "ICE SHARED ADDRESS TLV")
local ICE_TLV_IRDETO_ECM = Proto("ICE_TLV_IRDETO_ECM", "ICE IRDETO ECM TLV")
local ICE_TLV_KEY_SET_ID = Proto("ICE_TLV_KEY_SET_ID", "ICE KEY SET ID TLV")
local ICE_TLV_ISSUER_ID = Proto("ICE_TLV_ISSUER_ID", "ICE ISSUER ID TLV")
local ICE_TLV_TRANSPORT_KEY = Proto("ICE_TLV_TRANSPORT_KEY", "ICE TRANSPORT KEY TLV")
local ICE_TLV_CONTROL_ECM = Proto("ICE_TLV_CONTROL_ECM", "ICE CONTROL ECM TLV")
local ICE_TLV_SERVICE_NUMBER = Proto("ICE_TLV_SERVICE_NUMBER", "ICE SERVICE NUMBER TLV")
local ICE_TLV_CURRENT_DATE = Proto("ICE_TLV_CURRENT_DATE", "ICE CURRENT DATE TLV")
local ICE_TLV_IRDETO_EMM = Proto("ICE_TLV_IRDETO_EMM", "ICE IRDETO EMM TLV")
local ICE_TLV_DECODER_DATA = Proto("ICE_TLV_DECODER_DATA", "ICE DECODER DATA TLV")
local ICE_TLV_HASH = Proto("ICE_TLV_HASH", "ICE HASH TLV")


ICE_PARA_TLV_DICT = {
					[0x83] = ICE_TLV_KEY_SET_ID,
					[0x8A] = ICE_TLV_CONTROL_ECM,
					[0x8C] = ICE_TLV_SERVICE_NUMBER,
					[0x8E] = ICE_TLV_CURRENT_DATE,
					[0xC0] = ICE_TLV_IRDETO_EMM,
					[0xC4] = ICE_TLV_DECODER_DATA,
					[0xDF] = ICE_TLV_HASH
}

----------------------------------------------------------
---------------- Dissector for TLV -----------------------
----------------------------------------------------------

local f_ice_tlv_current_year = ProtoField.uint8("ICE_TLV_CURRENT_DATE.year", "Year", base.DEC)
local f_ice_tlv_current_month = ProtoField.uint8("ICE_TLV_CURRENT_DATE.month", "Month", base.DEC, nil, 0xf0)
local f_ice_tlv_current_day = ProtoField.uint8("ICE_TLV_CURRENT_DATE.day", "Day", base.DEC, nil, 0x0f)

ICE_TLV_CURRENT_DATE.fields = {f_ice_tlv_current_year, f_ice_tlv_current_month, f_ice_tlv_current_day}

function ICE_TLV_CURRENT_DATE.dissector(buf, pkt, root)
	root:add(f_ice_tlv_current_year, buf(0, 1))
	root:add(f_ice_tlv_current_month, buf(1, 1))
	root:add(f_ice_tlv_current_day, buf(1, 1))
end

ice_table:add(0x8E, ICE_TLV_CURRENT_DATE)


local function is_tableid_valid(id, tab)
	local is_valid = false
	for _, v in pairs(tab) do
		if id == v then  
			is_valid = true
		end
	end
	return is_valid
end

local function append_ice_section_tlv(buf,pkt,root)
 local buf_len = buf:len()
 local idx = 0
 while idx < buf_len do
	local tag = buf(idx, 1):uint()
	local length = buf(idx+1, 1):uint()
	local t = nil
	if ICE_PARA_TLV_DICT[tag] ~= nil then	
		t = root:add(ICE_PARA_TLV_DICT[tag], buf(idx, 2 + length))
		t:add('TAG: ', tostring(buf(idx,1)))
		t:add('LENGTH: ', tostring(length))
		local par_dis = ice_table:get_dissector(tag)
		if par_dis ~= nil then
			local ice_payload = buf(idx+2, length):tvb()
			par_dis:call(ice_payload, pkt, t)
		else
			t:add('VALUE: ', tostring(buf(idx+2, length)))
		end
		
	elseif tag == 0x80 then
		if length == 5 then
			t = root:add(ICE_TLV_UNIQUE_ADDRESS, buf(idx, 2 + length))
		elseif length == 4 then
			t = root:add(ICE_TLV_SHARED_ADDRESS, buf(idx, 2 + length))
		elseif is_tableid_valid(length, ice_ecm_len_list) then
			t = root:add(ICE_TLV_IRDETO_ECM, buf(idx, 2 + length))
		else
			return false
		end
		t:add('TAG: ', tostring(buf(idx,1)))
		t:add('LENGTH: ', tostring(length))
		t:add('VALUE: ', tostring(buf(idx+2, length)))
		
	elseif tag == 0x84 then
		if length == 1 then
			t = root:add(ICE_TLV_ISSUER_ID, buf(idx, 2 + length))
		elseif length == 2 then
			t = root:add(ICE_TLV_TRANSPORT_KEY, buf(idx, 2 + length))
		else
			return false
		end
		t:add('TAG: ', tostring(buf(idx,1)))
		t:add('LENGTH: ', tostring(length))
		t:add('VALUE: ', tostring(buf(idx+2, length)))
	else
		return false
	end
	
	idx = idx + 2 + length
 end
end


--Section Message	
	
	local ICE_SECTION_MESSAGE = Proto("ICE_SECTION_MESSAGE", "ICE Section Message")
	local ICE_SUB_SECTION = Proto("ICE_SUB_SECTION", "ICE Sub Section")
	f_ice_section_table_id = ProtoField.uint8("ICE_SECTION_MESSAGE.table_id", "Table Id", base.HEX, nil, 0xff)
	f_ice_section_syntax_indicator = ProtoField.uint16("ICE_SECTION_MESSAGE.section_syntax_indicator", "Section Syntax Indicator", base.HEX, nil, 0x8000)
	f_ice_section_dvb_reserved = ProtoField.uint16("ICE_SECTION_MESSAGE.dvb_reserved", "DVB Reserved", base.HEX, nil, 0x4000)
	f_ice_section_iso_reserved = ProtoField.uint16("ICE_SECTION_MESSAGE.iso_reserved", "ISO Reserved", base.HEX, nil, 0x3000)
	f_ice_section_length = ProtoField.uint16("ICE_SECTION_MESSAGE.length", "Section Length", base.DEC, nil, 0x0fff)
	f_ice_section_toggle_bit = ProtoField.uint8("ICE_SECTION_MESSAGE.toggle_bit", "Toggle Bit", base.HEX, nil, 0x80)
	f_ice_section_cryptalgo_family = ProtoField.uint8("ICE_SECTION_MESSAGE.crypt_algo_family", "Crypto Algorithm Family", base.HEX, nil, 0x7f)
	f_ice_section_reserved = ProtoField.uint8("ICE_SECTION_MESSAGE.reserved", "Reserved", base.HEX)
	f_ice_section_message = ProtoField.bytes("ICE_SECTION_MESSAGE.message", "Section Message", base.HEX)
	f_ice_section_stuffing = ProtoField.bytes("ICE_SECTION_MESSAGE.stuffing", "Stuffing Bytes", base.HEX)

	ICE_SECTION_MESSAGE.fields = {f_ice_section_table_id, f_ice_section_syntax_indicator, f_ice_section_dvb_reserved, f_ice_section_iso_reserved, f_ice_section_length, f_ice_section_message, f_ice_section_toggle_bit, f_ice_section_cryptalgo_family, f_ice_section_reserved, f_ice_section_stuffing}
	
	function ICE_SECTION_MESSAGE.dissector(buf, pkt, root)
		local buf_len = buf:len()
		local t = root:add(ICE_SECTION_MESSAGE, buf(0, buf_len))
		local idx = 0
		while idx < buf_len do
			local table_id = buf(idx,1):uint()		
			local section_length = bit:_and(buf(idx+1,2) : uint(), 0x0fff)
			local temp_len = section_length

			if is_tableid_valid(table_id, ice_accept_tables) then
				-- The packet will be divide into next TS Packet when the length > 188
				if idx + section_length + 3 > buf_len then
					section_length = buf_len - 3 - idx
				end
				local subt = t:add(ICE_SUB_SECTION, buf(idx, section_length + 3))
				subt:add(f_ice_section_table_id, buf(idx,1))
				subt:add(f_ice_section_syntax_indicator, buf(idx+1,2))
				subt:add(f_ice_section_dvb_reserved, buf(idx+1,2))
				subt:add(f_ice_section_iso_reserved, buf(idx+1,2))

				if section_length ~= temp_len then
					subt:add(f_ice_section_length, buf(idx+1,2)):append_text(' (Fragment Length is '..section_length..', EMM was splitted due to the packet length limitation)')
				else
					subt:add(f_ice_section_length, buf(idx+1,2))
				end
				subt:add(f_ice_section_toggle_bit, buf(idx+3, 1))
				subt:add(f_ice_section_cryptalgo_family, buf(idx+3, 1))
				subt:add(f_ice_section_reserved, buf(idx+4, 1))
				subt:add(f_ice_section_message, buf(idx+5, section_length - 2))
			
				local message_buf = buf(idx+5, section_length - 2):tvb()
				if is_tableid_valid(table_id, ice_ecm_table_ids) then
					-- ICE ECM
					ice_table:get_dissector(0xFF02):call(message_buf, pkt, subt)
				elseif is_tableid_valid(table_id, ice_global_msg) then
					-- ICE Global Msg
					ice_table:get_dissector(0xFF03):call(message_buf, pkt, subt)
				elseif table_id == ice_shared_msg then
					-- ICE Shared Msg
					ice_table:get_dissector(0xFF04):call(message_buf, pkt, subt)
				elseif table_id == ice_global_shared_msg then
					-- ICE Global Shared Msg
					ice_table:get_dissector(0xFF05):call(message_buf, pkt, subt)
				elseif table_id == ice_unique_msg then
					-- ICE Unique Msg
					ice_table:get_dissector(0xFF06):call(message_buf, pkt, subt)
				end
			elseif tostring(buf(idx, 1)) == 'ff' then
				t:add(f_section_stuffing, buf(idx, buf_len-idx))	
			end	
			
			idx = idx + 3 + section_length
		end
	end
	
	ice_table:add(0xFF00, ICE_SECTION_MESSAGE)
	

------------------------------------------------
-- ICE ECM
-- ICE GLOBAL MSG
-- ICE SHARED MSG
-- ICE GLOBAL SHARED MSG
-- ICE UNIQUE MSG
------------------------------------------------

local ICE_ECM_MSG = Proto("ICE_ECM_MSG", "ICE ECM")
local ICE_GLOBAL_MSG = Proto("ICE_GLOBAL_MSG", "ICE GLOBAL MSG")
local ICE_SHARED_MSG = Proto("ICE_SHARED_MSG", "ICE SHARED MSG")
local ICE_GLOBAL_SHARED_MSG = Proto("ICE_GLOBAL_SHARED_MSG", "ICE GLOBAL SHARED MSG")
local ICE_UNIQUE_MSG = Proto("ICE_UNIQUE_MSG", "ICE UNIQUE MSG")

------------------------------------------------
local f_ice_ecm_ci = ProtoField.uint8("ICE_ECM_MSG.ci", "CI", base.HEX)
local f_ice_ecm_cli = ProtoField.uint16("ICE_ECM_MSG.cli", "CLI", base.HEX)
local f_ice_global_msg_ci = ProtoField.uint8("ICE_GLOBAL_MSG.ci", "CI", base.HEX)
local f_ice_global_msg_cli = ProtoField.uint16("ICE_GLOBAL_MSG.cli", "CLI", base.HEX)
local f_ice_shared_msg_address = ProtoField.bytes("ICE_SHARED_MSG.address", "Address", base.HEX)
local f_ice_shared_msg_ci = ProtoField.uint8("ICE_SHARED_MSG.ci", "CI", base.HEX)
local f_ice_shared_msg_cli = ProtoField.uint16("ICE_SHARED_MSG.cli", "CLI", base.HEX)
local f_ice_unique_msg_address = ProtoField.bytes("ICE_UNIQUE_MSG.address", "Address", base.HEX)
local f_ice_unique_msg_ci = ProtoField.uint8("ICE_UNIQUE_MSG.ci", "CI", base.HEX)
local f_ice_unique_msg_cli = ProtoField.uint16("ICE_UNIQUE_MSG.cli", "CLI", base.HEX)

ICE_ECM_MSG.fields = {f_ice_ecm_ci, f_ice_ecm_cli}
ICE_GLOBAL_MSG.fields = {f_ice_global_msg_ci, f_ice_global_msg_cli}
ICE_SHARED_MSG.fields = {f_ice_shared_msg_address, f_ice_shared_msg_ci, f_ice_shared_msg_cli}
ICE_UNIQUE_MSG.fields = {f_ice_unique_msg_address, f_ice_unique_msg_ci, f_ice_unique_msg_cli}

function ICE_ECM_MSG.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 1 then
		return false
	end
	t = root:add(ICE_ECM_MSG, buf(0, buf_len))
	t:add(f_ice_ecm_ci, buf(0, 1))
	t:add(f_ice_ecm_cli, buf(1, 2))
	ice_tlv_section = buf(3, buf_len - 3):tvb()
	append_ice_section_tlv(ice_tlv_section, pkt, t)
end

function ICE_GLOBAL_MSG.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 1 then
		return false
	end
	t = root:add(ICE_GLOBAL_MSG, buf(0, buf_len))
	t:add(f_ice_global_msg_ci, buf(0, 1))
	t:add(f_ice_global_msg_cli, buf(1, 2))
	ice_tlv_section = buf(3, buf_len - 3):tvb()
	append_ice_section_tlv(ice_tlv_section, pkt, t)
end

function ICE_SHARED_MSG.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 1 then
		return false
	end
	t = root:add(ICE_SHARED_MSG, buf(0, buf_len))
	t:add(f_ice_shared_msg_address, buf(0,4))
	t:add(f_ice_shared_msg_ci, buf(4, 1))
	t:add(f_ice_shared_msg_cli, buf(5, 2))
	ice_tlv_section = buf(7, buf_len - 7):tvb()
	append_ice_section_tlv(ice_tlv_section, pkt, t)
end

function ICE_GLOBAL_SHARED_MSG.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 1 then
		return false
	end
	t = root:add(ICE_GLOBAL_SHARED_MSG, buf(0, buf_len))
	ice_tlv_section = buf(0, buf_len):tvb()
	append_ice_section_tlv(ice_tlv_section, pkt, t)
end

function ICE_UNIQUE_MSG.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 1 then
		return false
	end
	t = root:add(ICE_UNIQUE_MSG, buf(0, buf_len))
	t:add(f_ice_unique_msg_address, buf(0,5))
	t:add(f_ice_unique_msg_ci, buf(5, 1))
	t:add(f_ice_unique_msg_cli, buf(6, 2))
	ice_tlv_section = buf(8, buf_len - 8):tvb()
	append_ice_section_tlv(ice_tlv_section, pkt, t)
end

ice_table:add(0xFF02, ICE_ECM_MSG)
ice_table:add(0xFF03, ICE_GLOBAL_MSG)
ice_table:add(0xFF04, ICE_SHARED_MSG)
ice_table:add(0xFF05, ICE_GLOBAL_SHARED_MSG)
ice_table:add(0xFF06, ICE_UNIQUE_MSG)

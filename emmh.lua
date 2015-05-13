--EMM TABLE
emm_table = DissectorTable.new("EMM_TABLE", "EMM Table", FT_STRING)
EMM_OPCODES = Proto("EMM_OPCODES", "EMM Opcodes")
ECM_OPCODES = Proto("ECM_OPCODES", "ECM Opcodes")

--Function

local function get_addr_len(buf)
	return bit:_and(buf(0,1):uint(), 7)
end

local function get_super_group_sector_number(buf)
	return bit:_and(bit:_rshift(buf(0,1):uint(), 3), 0x7)
end

local function get_group_sector_number(buf)
	return bit:_and(bit:_rshift(buf(0,1):uint(), 3), 0xf)
end

local function get_global_sector_number(buf)
	return bit:_and(bit:_rshift(buf(0,1):uint(), 3), 0x7)
end

local function	is_unique_bit(buf)
	local addr_type_bit = bit:_rshift(buf(0,1):uint(), 7)
	if addr_type_bit == 0 then
		return false
	else
		return true
	end
end	

local function is_super_group_bit(buf)
	local addr_type_bit = bit:_and(bit:_rshift(buf(0,1):uint(), 6), 1)
	if addr_type_bit == 1 then
		return true
	else
		return false
	end
end

local function get_filter_field(buf)
	return bit:_and(bit:_rshift(buf(0,1):uint(), 3), 0x0f)
end	

local function append_field(tree, tag, value)
	if value ~= nil then
		tree:add(tag, value)
	end
end

local function emmh_generic_pasrse(buf, emm_type)
	local emmh = {}
	emmh.address_len = get_addr_len(buf)

	if emmh.address_len == 4 then
		emm_type = 'CAM'
	end
	
	if emm_type == 'CA3' then
		emmh.header_size = 1 + emmh.address_len
	elseif emmh.emm_type == 'CA2' then
		emmh.header_size = 4 -- 1 + 3 bytes of fixed address
	elseif emm_type == 'CAM' then
		emmh.header_size = 1 + emmh.address_len
	else
		emmh.header_size = 4 --default as CA2
	end
		
	if is_unique_bit(buf) then
		emmh.emm_filter = get_filter_field(buf) + 0x10
		if emmh.address_len == 3 then
			emmh.address = buf(1,3) --get 3 bytes address
			emmh.address_type = 'UNIQUE'
			
		elseif emmh.address_len == 4 then
			emmh.address = buf(1,4) --get 4 bytes address
			emmh.address_type = 'UNIQUE'
		
		elseif emmh.address_len == 0 then
			emmh.address_type = 'GLOBAL'
			if tostring(buf(1,4)) == '00000000' then
				emmh.header_size = 4
			else
				emmh.header_size = 1
			end
		end
	else -- Unique bit = 0
		if emmh.address_len == 2 and is_super_group_bit(buf) then
			emmh.address_type = 'SUPER-GROUP'
			emmh.sector_number = get_super_group_sector_number(buf)
			emmh.address = buf(1,2)
		elseif emmh.address_len == 3 or emmh.address_len == 2 then
			emmh.address_type = 'GROUP'
			if emmh.address_len == 3 then
				emmh.address_type = 'GROUP-UINQUE'
			end
			
			emmh.sector_number = get_group_sector_number(buf)
			if emmh.address_len == 3 then
				emmh.address = buf(1,3)
			else
				emmh.address = buf(1,2)
			end
			
		elseif emmh.address_len == 0 then
			emmh.address_type = 'GLOBAL-SECTOR'
			emmh.sector_number = get_global_sector_number(buf)
			emmh.address = buf(1,3)
			
			if buf(1,3):le_uint() ~= 0 then -- CAN BE CAM EMM
				emmh.address_type = 'GLOBAL-CAM'
				emmh.header_size = 1
			end
		else
			return false
		end
		
	end
	
	return emmh
		
end


-- EMM for CA3 --
local EMM_CA3 = Proto("EMM_CA3", "CA3 EMM Structure")
local EMM_HEADER_CA3 = Proto("EMM_HEADER_CA3", "CA3 EMM Header")
f_emmh_ca3_addr_type_bit = ProtoField.uint8("EMM_CA3.addr_type_bit", "Address Type Bit", base.HEX)
f_emmh_ca3_addr_type = ProtoField.string("EMM_CA3.addr_type", "Address Type")
f_emmh_ca3_emm_filter_nr = ProtoField.uint8("EMM_CA3.emm_filter_nr", "EMM Filter Number", base.HEX)
f_emmh_ca3_sector_nr = ProtoField.uint8("EMM_CA3.sector_nr", "Sector Number", base.HEX)
f_emmh_ca3_addr = ProtoField.bytes("EMM_CA3.addr", "Address", base.HEX)
f_emmh_ca3_group_key = ProtoField.uint8("EMM_CA3.group_key", "Group Key", base.HEX)
f_emmh_ca3_addr_len = ProtoField.uint8("EMM_CA3.addr_len", "Address Length", base.HEX)
f_emmh_ca3_split_flag = ProtoField.uint8("EMM_CA3.split_flag", "Split Flag", base.HEX)
f_emmh_ca3_ovk_index = ProtoField.uint8("EMM_CA3.ovk_index", "OVK Index", base.HEX)
f_emmh_ca3_tkc_gen = ProtoField.uint8("EMM_CA3.tkc_gen", "TKc Generation", base.HEX)
f_emmh_ca3_super_group_indicator = ProtoField.uint8("EMM_CA3.super_group_indicator", "Super Group Indicator", base.HEX)
f_emmh_ca3_pk_index = ProtoField.uint8("EMM_CA3.pk_index", "PKey Index", base.HEX)

-- Segment Data
f_emm_ca3_seg_headend_id = ProtoField.uint8("EMM_CA3.seg_headend_id", "Headend ID", base.HEX)
f_emm_ca3_seg_last_nr = ProtoField.uint8("EMM_CA3.last_nr", "Last Segment Number", base.HEX)
f_emm_ca3_seg_nr = ProtoField.uint8("EMM_CA3.seg_nr", "Segment Number", base.HEX)
f_emm_ca3_emm_len = ProtoField.uint8("EMM_CA3.emm_len", "EMM Length", base.DEC)
f_emm_ca3_payload = ProtoField.bytes("EMM_CA3.payload", "EMM Payload", base.HEX)

EMM_CA3.fields = {f_emmh_ca3_addr_type_bit, f_emmh_ca3_addr_type, f_emmh_ca3_emm_filter_nr, f_emmh_ca3_sector_nr, f_emmh_ca3_addr, f_emmh_ca3_group_key,
				f_emmh_ca3_addr_len, f_emmh_ca3_split_flag, f_emmh_ca3_ovk_index, f_emmh_ca3_tkc_gen, f_emmh_ca3_super_group_indicator, f_emmh_ca3_pk_index, f_emm_ca3_seg_headend_id, f_emm_ca3_seg_last_nr, f_emm_ca3_seg_nr, f_emm_ca3_emm_len, f_emm_ca3_payload}
						
local function emmh_ca3_dissect(buf)
	local emmh = {}
	emmh.addr_type_bit = bit:_rshift(buf(0,1):uint(), 7)
	emmh.addr_len = bit:_and(buf(0,1):uint(), 7)
	emmh.header_size = emmh.addr_len + 2
	local last_Hbyte_indx = emmh.addr_len + 1
	emmh.last_Hbyte = buf(last_Hbyte_indx, 1):uint()
	emmh.split_flag = bit:_and(emmh.last_Hbyte, 1)
	
	if is_unique_bit(buf) then
		emmh.filter_number = 0x10 + get_filter_field(buf)
		if emmh.addr_len > 0 then
			emmh.address_type = 'UNIQUE'
			emmh.address_extension = bit:_and( bit:_rshift(buf(0,1):uint(), 3), 7)
			emmh.address = buf(1, emmh.addr_len)
			emmh.ovk_index = bit:_and(bit:_rshift(emmh.last_Hbyte, 3), 7)
		else -- Global, address length = 0
			emmh.address_type = 'GLOBAL'
		end
		
	else -- Unique bit =0 (Group or Global Sector EMM)
		emmh.sector_number = bit:_and( bit:_rshift(buf(0,1):uint(), 3), 7)
		if emmh.addr_len > 0 then
			if is_super_group_bit(buf) then
				emmh.address_type = 'SUPER-GROUP'
				emmh.super_group_indicator = bit:_and( bit:_rshift(buf(0,1):uint(), 6), 1)
			else
				emmh.address_type = 'GROUP'
			end
			--Commen Field Here
			emmh.address = buf(1, emmh.addr_len)
			emmh.tkc_generation = bit:_and(bit:_rshift(emmh.last_Hbyte, 5), 1)
			emmh.group_key = bit:_and(bit:_rshift(emmh.last_Hbyte, 4), 1)
		else -- address length = 0
			emmh.address_type = 'GLOBAL-SECTOR'
			emmh.pkey_index = bit:_and(bit:_rshift(emmh.last_Hbyte, 3), 0x1f)
		end

	end

	
	return emmh
end			
						
function EMM_CA3.dissector(buf,pkt,root)
	local buf_len = buf:len()
	local t = root:add(EMM_CA3, buf(0, buf_len))
	local ca3_emmh = emmh_ca3_dissect(buf)
	if not ca3_emmh then
		return false
	end
	
	local subt = t:add(EMM_HEADER_CA3, buf(0, ca3_emmh.header_size))
	append_field(subt, f_emmh_ca3_addr_type_bit, ca3_emmh.addr_type_bit)
	append_field(subt, f_emmh_ca3_super_group_indicator, ca3_emmh.super_group_indicator)
	append_field(subt, f_emmh_ca3_addr_type, ca3_emmh.address_type)
	append_field(subt, f_emmh_ca3_addr_len, ca3_emmh.addr_len)
	append_field(subt, f_emmh_ca3_addr, ca3_emmh.address)
	append_field(subt, f_emmh_ca3_emm_filter_nr, ca3_emmh.filter_number)
	append_field(subt, f_emmh_ca3_sector_nr, ca3_emmh.sector_number)
	append_field(subt, f_emmh_ca3_group_key, ca3_emmh.group_key)
	append_field(subt, f_emmh_ca3_split_flag, ca3_emmh.split_flag)
	append_field(subt, f_emmh_ca3_ovk_index, ca3_emmh.ovk_index)
	append_field(subt, f_emmh_ca3_tkc_gen, ca3_emmh.tkc_generation)
	append_field(subt, f_emmh_ca3_pk_index, ca3_emmh.pkey_index)
	
	t:add(f_emm_ca3_emm_len, buf(ca3_emmh.header_size, 1))
	if ca3_emmh.split_flag == 1 then
		t:add(f_emm_ca3_seg_headend_id, buf(ca3_emmh.header_size + 1, 1))
		t:add(f_emm_ca3_seg_last_nr, buf(ca3_emmh.header_size + 1, 1))
		t:add(f_emm_ca3_seg_nr, buf(ca3_emmh.header_size + 1, 1))
		t:add(f_emm_ca3_payload, buf(ca3_emmh.header_size + 2, buf_len - 2 - ca3_emmh.header_size))
	else
		opt = t:add(EMM_OPCODES, buf(ca3_emmh.header_size + 1, buf_len - 1 - ca3_emmh.header_size))
		opcodes_payload = buf(ca3_emmh.header_size + 1, buf_len - 1 - ca3_emmh.header_size):tvb()
		local dis = ccp_table:get_dissector(0xFFFF)
		if not dis:call(opcodes_payload, pkt, opt) then
			return false
		end
	end
	
	return true
end

emm_table:add(0x01, EMM_CA3)


-- EMM Header for CA2 --
local EMM_CA2 = Proto("EMM_CA2", "CA2 EMM Structure")
local EMM_HEADER_CA2 = Proto("EMM_HEADER_CA2", "CA2 EMM Header")
f_emmh_ca2_addr_type = ProtoField.string("EMM_HEADER_CA2.addr_type", "Address Type")
f_emmh_ca2_emm_filter_nr = ProtoField.uint8("EMM_HEADER_CA2.emm_filter_nr", "EMM Filter Number", base.HEX)
f_emmh_ca2_sector_nr = ProtoField.uint8("EMM_HEADER_CA2.sector_nr", "Sector Number", base.HEX)
f_emmh_ca2_addr = ProtoField.bytes("EMM_HEADER_CA2.addr", "Address", base.HEX)
f_emmh_ca2_group_key = ProtoField.uint8("EMM_HEADER_CA2.group_key", "Group Key", base.HEX)
f_emmh_ca2_addr_len = ProtoField.uint8("EMM_HEADER_CA2.addr_len", "Address Length", base.HEX)
f_emmh_ca2_emm_len = ProtoField.uint8("EMM_HEADER_CA2.emm_len", "EMM Length", base.DEC)

EMM_CA2.fields = {f_emmh_ca2_addr_type, f_emmh_ca2_emm_filter_nr, f_emmh_ca2_sector_nr, f_emmh_ca2_addr, f_emmh_ca2_group_key, f_emmh_ca2_addr_len, f_emmh_ca2_emm_len}

function EMM_CA2.dissector(buf,pkt,root)
	local buf_len = buf:len()
	local ca2_emmh = emmh_generic_pasrse(buf, 'CA2')
	if not ca2_emmh then
		return false
	end
	local t = root:add(EMM_CA2, buf(0, buf_len))
	local subt = t:add(EMM_HEADER_CA2, buf(0, ca2_emmh.header_size + 1))
	append_field(subt, f_emmh_ca2_addr_type, ca2_emmh.address_type)
	append_field(subt, f_emmh_ca2_addr_len, ca2_emmh.address_len)
	append_field(subt, f_emmh_ca2_addr, ca2_emmh.address)
	append_field(subt, f_emmh_ca2_emm_filter_nr, ca2_emmh.emm_filter)
	append_field(subt, f_emmh_ca2_sector_nr, ca2_emmh.sector_number)
	
	local idx_Byte_Group_Key = ca2_emmh.header_size
	local group_key = bit:_and(bit:_rshift(buf(ca2_emmh.header_size, 1):uint(),4), 0x1)
	append_field(subt, f_emmh_ca2_group_key, group_key)
	
	local emm_len = buf(ca2_emmh.header_size + 1, 1):uint()
	t:add(f_emmh_ca2_emm_len, buf(ca2_emmh.header_size + 1, 1))
	opt = t:add(EMM_OPCODES, buf(ca2_emmh.header_size + 2, buf_len - 2 - ca2_emmh.header_size))
	opcodes_payload = buf(ca2_emmh.header_size + 2, buf_len - 2 - ca2_emmh.header_size):tvb()
		local dis = ccp_table:get_dissector(0xFFFF)
		if not dis:call(opcodes_payload, pkt, opt) then
			return false
		end

	return true
end

emm_table:add(0x02, EMM_CA2)


-- EMM Header for CCA --
local EMM_CCA = Proto("EMM_CCA", "CCA EMM Structure")
local EMM_HEADER_CCA = Proto("EMM_HEADER_CCA", "CCA EMM Header")
f_emmh_cca_addr_type = ProtoField.string("EMM_CCA.addr_type", "Address Type")
f_emmh_cca_emm_filter_nr = ProtoField.uint8("EMM_CCA.emm_filter_nr", "EMM Filter Number", base.HEX)
f_emmh_cca_sector_nr = ProtoField.uint8("EMM_CCA.sector_nr", "Sector Number", base.HEX)
f_emmh_cca_addr = ProtoField.uint8("EMM_CCA.addr", "Address", base.HEX)
f_emmh_cca_group_key = ProtoField.uint8("EMM_CCA.group_key", "Group Key", base.HEX)
f_emmh_cca_addr_len = ProtoField.uint8("EMM_CCA.addr_len", "Address Length", base.HEX)
f_emmh_cca_split_flag = ProtoField.uint8("EMM_CCA.split_flag", "Split Flag", base.HEX)
f_emmh_cca_emm_len = ProtoField.uint8("EMM_CCA.emm_len", "EMM Length", base.DEC)
f_emmh_cca_emm_extended_size = ProtoField.uint8("EMM_CCA.emm_extend_size", "EMM Extended Size", base.DEC)

EMM_CCA.fields = {f_emmh_cca_addr_type, f_emmh_cca_emm_filter_nr, f_emmh_cca_sector_nr, f_emmh_cca_addr, f_emmh_cca_group_key, f_emmh_cca_addr_len, f_emmh_cca_split_flag, f_emmh_cca_emm_len, f_emmh_cca_emm_extended_size}

local function emmh_cca_dissect(buf)
	local emmh = {}
	emmh.addr_type_bit = bit:_rshift(buf(0,1):uint(), 7)
	emmh.addr_len = bit:_and(buf(0,1):uint(), 7)
	emmh.header_size = emmh.addr_len + 1 + 3
	
	local last_Hbyte_indx = emmh.addr_len + 1
	emmh.last_Hbyte = buf(last_Hbyte_indx, 1):uint()
	emmh.group_key = bit:_and(bit:_rshift(emmh.last_Hbyte, 4), 1)
	emmh.split_flag = bit:_and(bit:_rshift(emmh.last_Hbyte, 3), 1)
	emmh.emm_extended_size = bit:_and(bit:_rshift(emmh.last_Hbyte, 2), 1)
	emmh.sc_emm_length = buf(last_Hbyte_indx+1, 2)
	
	if is_unique_bit(buf)  then
		emmh.emm_filter = 0x10 + get_filter_field(buf)
		if emmh.addr_len == 4 then
			emmh.address_type = 'UNIQUE'
			emmh.address = buf(1,4)
		end
		
		if emmh.addr_len == 5 then
			emmh.address_type = 'UNIQUE'
			emmh.address = buf(1,5)
		elseif emmh.addr_len == 0 then
			emmh.address_type = 'GLOBAL'
			emmh.address = 0
		end
	else  -- Unique Bit = 0
		if emmh.addr_len == 3 then
			emmh.address_type = 'GROUP-UNIQUE'
			emmh.sector_number = get_group_sector_number(buf)
			emmh.address = buf(1,3)
		elseif emmh.addr_len == 2 and is_super_group_bit(buf) then
			emmh.address_type = 'SUPER-GROUP'
			emmh.sector_number = get_super_group_sector_number(buf)
			emmh.address = buf(1,2)
		elseif emmh.addr_len == 2 then
			emmh.address_type  = 'GROUP'
			emmh.sector_number = get_group_sector_number(buf)
			emmh.address = buf(1,2)
		elseif emmh.addr_len == 0 then
			emmh.address_type = 'GLOBAL-SECTOR'
			emmh.sector_number = get_global_sector_number(buf)
			emmh.address = 0
			
			--if buf(1,2):le_uint() ~= 0 then -- CAN BE CAM EMM
				--emmh.address_type = 'GLOBAL-CAM'
			--end	
		end	
	end
	
	return emmh
end

function EMM_CCA.dissector(buf,pkt,root)
	local buf_len = buf:len()
	local cca_emmh = emmh_cca_dissect(buf, cca_emmh)
	if not cca_emmh then
		return false 
	end
	pkt.cols.info = 'CCA ' .. cca_emmh.address_type .. ' EMM'
	local t = root:add(EMM_CCA, buf(0, buf_len))
	local subt = t:add(EMM_HEADER_CCA, buf(0, cca_emmh.header_size))
	append_field(subt, f_emmh_cca_addr_type, cca_emmh.address_type)
	append_field(subt, f_emmh_cca_addr_len, cca_emmh.addr_len)
	append_field(subt, f_emmh_cca_addr, cca_emmh.address)
	append_field(subt, f_emmh_cca_emm_filter_nr, cca_emmh.emm_filter)
	append_field(subt, f_emmh_cca_sector_nr, cca_emmh.sector_number)
	append_field(subt, f_emmh_cca_group_key, cca_emmh.group_key)
	append_field(subt, f_emmh_cca_split_flag, cca_emmh.split_flag)
	append_field(subt, f_emmh_cca_emm_extended_size, cca_emmh.emm_extended_size)
	append_field(subt, f_emmh_cca_emm_len, cca_emmh.sc_emm_length)

	opt = t:add(EMM_OPCODES, buf(cca_emmh.header_size, buf_len - cca_emmh.header_size))
	opcodes_payload = buf(cca_emmh.header_size, buf_len - cca_emmh.header_size):tvb()
		--local dis = ccp_table:get_dissector(0x00FF)
		--if not dis:call(opcodes_payload, pkt, opt) then
			--return false
		--end
		ccp_table:try(0xffff, opcodes_payload, pkt, opt)
	
	return true
end

emm_table:add(0x03, EMM_CCA)

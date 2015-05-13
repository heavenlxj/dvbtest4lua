--METADATA TABLE
metadata_table = DissectorTable.new("METADATA_TABLE", "METADATA", FT_STRING)

METADATA = Proto("METADATA", "DVB MetaData")

-----------------------------------------------

------------- METADATA PARAMETER --------------

-----------------------------------------------

METADATA_UNKNOWN = Proto("METADATA_UNKNOWN", "Unknown Type")
METADATA_EMM_LINK = Proto("METADATA_EMM_LINK", "EMM Link")
METADATA_EMM_DELAY = Proto("METADATA_EMM_DELAY", "EMM Delay")
METADATA_EMM_PRIORITY = Proto("METADATA_EMM_PRIORITY", "EMM Priority")
METADATA_EMM_ACK = Proto("METADATA_EMM_ACK", "EMM Acknowledgment")
METADATA_EMM_FILTER = Proto("METADATA_EMM_FILTER", "EMM Filter")
METADATA_EMM_TIMEOUT = Proto("METADATA_EMM_TIMEOUT", "EMM Timeout")
METADATA_CDMA_DEVICE_ID = Proto("METADATA_CDMA_DEVICE_ID", "CDMA Device Id")
METADATA_SERIAL_NUMBER = Proto("METADATA_SERIAL_NUMBER", "Serial Number")
METADATA_EMM_BATCH = Proto("METADATA_EMM_BATCH", "EMM Batch")
METADATA_SCTYPE_ID = Proto("METADATA_SCTYPE_ID", "SC Type Id")
METADATA_EMM_GLOBAL = Proto("METADATA_EMM_GLOBAL", "EMM Global")
METADATA_EMM_MAX_SIZE = Proto("METADATA_EMM_MAX_SIZE", "Max EMM Size")
METADATA_ENCRYPTOR_TYPE = Proto("METADATA_ENCRYPTOR_TYPE", "Encryptor Type")
METADATA_EMM_GLOBAL_SHARED = Proto("METADATA_EMM_GLOBAL_SHARED", "EMM Global Shared")
METADATA_SECURE_CLIENT_TYPE = Proto("METADATA_SECURE_CLIENT_TYPE", "Secure Client Type")
METADATA_KS_ENCRYPTOR_TYPE = Proto("METADATA_KS_ENCRYPTOR_TYPE", "KS Encryptor Type")
METADATA_ADDITIONAL_PRIMES_TS = Proto("METADATA_ADDITIONAL_PRIMES_TS", "Additional Primes TS")
METADATA_PKEY_HASH_REQUEST = Proto("METADATA_PKEY_HASH_REQUEST", "PKey Hash Request")
METADATA_EMM_THREAD_ID = Proto("METADATA_EMM_THREAD_ID", "EMM Thread Id")
METADATA_EMM_INSERTION_TS = Proto("METADATA_EMM_INSERTION_TS", "EMM Insertion TS")
METADATA_IGNORE_LENGTH = Proto("METADATA_IGNORE_LENGTH", "Ignore Length")
METADATA_lOCATION_ID = Proto("METADATA_lOCATION_ID", "Location Id")

--metadata arg
f_meta_data_length = ProtoField.uint16("METADATA.length", "Metadata Length", base.DEC)

--metadata emm link arg
f_meta_data_el_link_type = ProtoField.uint8("METADATA_EMM_LINK.link_type", "Link Type", base.DEC, {[0]='Not Linked', 
																					[1] = 'Unique Address', 
																					[2] = 'Group Address', 
																					[3] = 'Sector Global', 
																					[4] = 'Global', 																						
																					[5] = 'Global ICE'})
f_meta_data_el_unique_address = ProtoField.bytes("METADATA_EMM_LINK.ua", "Unique Address", base.HEX)
f_meta_data_el_group_address = ProtoField.bytes("METADATA_EMM_LINK.ga", "Group Address", base.HEX)
f_meta_data_el_sector_number = ProtoField.uint8("METADATA_EMM_LINK.sector_n", "Sector Number", base.DEC)
f_meta_data_el_emm_filter = ProtoField.uint8("METADATA_EMM_LINK.emm_filter", "EMM Filter", base.HEX)
f_meta_data_el_thread_id = ProtoField.uint16("METADATA_EMM_LINK.thread_id", "Thread Id", base.HEX)
f_meta_data_el_sc_model = ProtoField.bytes("METADATA_EMM_LINK.sc_model", "SC Model", base.HEX)
f_meta_data_el_reserved = ProtoField.bytes("METADATA_EMM_LINK.reserved", "Reserved", base.HEX)
f_meta_data_el_link_id = ProtoField.bytes("METADATA_EMM_LINK.link_id", "Link Id", base.HEX)

--metadata emm priority arg
f_meta_data_ep_priority = ProtoField.uint8("METADATA_EMM_PRIORITY.priority", "EMM Priority", base.DEC, {[0]='Low', 
																					[1] = 'Medium', 
																					[2] = 'High', 
																					[3] = 'Express'})
																					
--metadata emm batch arg
f_meta_data_eb_batch_id = ProtoField.bytes("METADATA_EMM_BATCH.batch_id", "Batch Id", base.HEX)
f_meta_data_eb_position = ProtoField.uint8("METADATA_EMM_BATCH.position", "Position", base.DEC, {[0]='First', 
																					[1] = 'Middle', 
																					[2] = 'Last'}, 0xf0)
f_meta_data_eb_one_packet = ProtoField.uint8("METADATA_EMM_BATCH.one_packet", "One Packet", base.HEX, nil, 0x01)


--metadata emm size arg
f_meta_data_es_max_ccp_size = ProtoField.uint16("METADATA_EMM_MAX_SIZE.max_ccp_size", "Max CCP EMM Size", base.DEC)
f_meta_data_es_check_ccp_size = ProtoField.uint8("METADATA_EMM_MAX_SIZE.check_ccp_size", "Check CCP EMM Size", base.HEX)
f_meta_data_es_max_stb_size = ProtoField.uint16("METADATA_EMM_MAX_SIZE.max_stb_size", "Max STB EMM Size", base.DEC)
f_meta_data_es_check_stb_size = ProtoField.uint8("METADATA_EMM_MAX_SIZE.check_stb_size", "Check STB EMM Size", base.HEX)
f_meta_data_es_split_emm_length	= ProtoField.uint16("METADATA_EMM_MAX_SIZE.split_emm_length", "Split EMM Length", base.DEC)
f_meta_data_es_split_emm = ProtoField.uint8("METADATA_EMM_MAX_SIZE.split_emm", "Split EMM", base.HEX)
																					

METADATA.fields = {f_meta_data_length}

METADATA_EMM_LINK.fields = {f_meta_data_el_link_type, f_meta_data_el_unique_address, f_meta_data_el_group_address, f_meta_data_el_sector_number, f_meta_data_el_emm_filter, 					f_meta_data_el_thread_id, f_meta_data_el_sc_model, f_meta_data_el_reserved, f_meta_data_el_link_id}

METADATA_EMM_PRIORITY.fields = {f_meta_data_ep_priority}

METADATA_EMM_BATCH.fields = {f_meta_data_eb_batch_id, f_meta_data_eb_position, f_meta_data_eb_one_packet}

METADATA_EMM_MAX_SIZE.fields = {f_meta_data_es_max_ccp_size, f_meta_data_es_check_ccp_size, f_meta_data_es_max_stb_size, f_meta_data_es_check_stb_size, f_meta_data_es_split_emm_length, f_meta_data_es_split_emm}

METADATA_PARA_DICT = {
					[0x0000] = METADATA_UNKNOWN,
					[0x0001] = METADATA_EMM_LINK,
					[0x0002] = METADATA_EMM_DELAY,
					[0x0003] = METADATA_EMM_PRIORITY,
					[0x0004] = METADATA_EMM_ACK,
					[0x0005] = METADATA_EMM_FILTER,
					[0x0006] = METADATA_EMM_TIMEOUT,
					[0x0200] = METADATA_CDMA_DEVICE_ID,
					[0x8000] = METADATA_SERIAL_NUMBER,
					[0x8001] = METADATA_EMM_BATCH,
					[0x8003] = METADATA_SCTYPE_ID,
					[0x8004] = METADATA_EMM_GLOBAL,
					[0x8005] = METADATA_EMM_MAX_SIZE,
					[0x8006] = METADATA_ENCRYPTOR_TYPE,
					[0x8007] = METADATA_EMM_GLOBAL_SHARED,
					[0x8008] = METADATA_SECURE_CLIENT_TYPE,
					[0x8009] = METADATA_KS_ENCRYPTOR_TYPE,
					[0x800a] = METADATA_ADDITIONAL_PRIMES_TS,
					[0x800b] = METADATA_PKEY_HASH_REQUEST,
					[0x800c] = METADATA_EMM_THREAD_ID,
					[0x800d] = METADATA_EMM_INSERTION_TS,
					[0x800e] = METADATA_IGNORE_LENGTH,
					[0x800f] = METADATA_lOCATION_ID
					}

----------------------------------------------------
local function append_meta_data_tlv(buf,pkt,root)
 local buf_len = buf:len()
 local idx = 0
 while idx < buf_len do
	local tag = buf(idx, 2):uint()
	if METADATA_PARA_DICT[tag] ~= nil then
		local length = buf(idx+2, 2):uint()
		local t = root:add(METADATA_PARA_DICT[tag], buf(idx, 4 + length))
		t:add('TAG: ', tostring(buf(idx,2)))
		t:add('LENGTH: ', tostring(length))
		local par_dis = metadata_table:get_dissector(tag)
		if par_dis ~= nil then
			local md_payload = buf(idx+4, length):tvb()
			par_dis:call(md_payload, pkt, t)
		else
			t:add('VALUE: ', tostring(buf(idx+4, length)))
		end
		idx = idx + 4 + length
	else
		return false
	end
 end
end

function METADATA.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(METADATA, buf(0, buf_len))
	t:add(f_meta_data_length, buf(0,2))
	append_meta_data_tlv(buf(2, buf_len -2):tvb(), pkt, t)
end

metadata_table:add(0xFFFF, METADATA)

--------------------------------------------------------

---------  Dissector Function for Parameter ------------

--------------------------------------------------------
function METADATA_EMM_LINK.dissector(buf,pkt,root)
	local buf_len = buf:len()
	local link_type = buf(0,1):uint()
	local idx = 1
	root:add(f_meta_data_el_link_type, buf(0,1))
	if link_type == 1 then
		root:add(f_meta_data_el_unique_address, buf(1, 8))
		idx = 9
	elseif link_type == 2 then
		root:add(f_meta_data_el_group_address, buf(1, 6)) -- only 4 bytes are relevant; returning all 6 forces the other 2 to 0
		idx = 7
	elseif link_type == 3 then
		root:add(f_meta_data_el_sector_number, buf(1, 6)) -- only 1 bytes is relevant; returning all 6 forces the other 5 to 0
		idx = 7
	elseif link_type == 4 then
		root:add(f_meta_data_el_emm_filter, buf(1, 1))
		root:add(f_meta_data_el_thread_id, buf(2,  2))
		root:add(f_meta_data_el_sc_model, buf(4,  3))
		idx = 7
	else
		root:add(f_meta_data_el_link_id, buf(1, buf_len - 1))
		idx = buf_len
	end
	
	if buf_len - idx > 0 then
		root:add(f_meta_data_el_reserved, buf(idx, buf_len - idx))
	end
end
metadata_table:add(0x0001, METADATA_EMM_LINK)

function METADATA_EMM_PRIORITY.dissector(buf, pkt, root)
	root:add(f_meta_data_ep_priority, buf(0,1))
end
metadata_table:add(0x0003, METADATA_EMM_PRIORITY)

function METADATA_EMM_MAX_SIZE.dissector(buf, pkt, root)
	root:add(f_meta_data_es_max_ccp_size, buf(0,2))
	root:add(f_meta_data_es_check_ccp_size, buf(2,1))
	root:add(f_meta_data_es_max_stb_size, buf(3,2))
	root:add(f_meta_data_es_check_stb_size, buf(5,1))
	root:add(f_meta_data_es_split_emm_length, buf(6,2))
	root:add(f_meta_data_es_split_emm, buf(8,1))
end
metadata_table:add(0x8005, METADATA_EMM_MAX_SIZE)

function METADATA_EMM_BATCH.dissector(buf, pkt, root)
	root:add(f_meta_data_eb_batch_id, buf(0,4))
	root:add(f_meta_data_eb_position, buf(4,1))
	root:add(f_meta_data_eb_one_packet, buf(4,1))
end
metadata_table:add(0x8001, METADATA_EMM_BATCH)
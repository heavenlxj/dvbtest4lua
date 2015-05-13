--ac.lua

--This file contains the dissetors funtion for different ac

--How to add an AC:
--	1. add  local Proto and ProtoField
--		1.1. if the ac is complicate (like 0x9011), add protoFields and dissector function
--	2. add the proto into AC_VALUE_DICT
--		2.1. if the ac is a compound (like 0x9016), set compound = true in the dict
--		2.2. if the length of the ac is fixed, set the value to correct, else, set to nil

--Access Criteria Table
ac_table = DissectorTable.new("AC_TABLE", "Access Criteria Message", FT_STRING)

-- AC protocal table
ac_protos = {}

--parse unicode
local function parse_unicode(unicodeRaw)
	ulen = unicodeRaw:len()
	if ulen % 2 == 1 then
		return nil
	else
		local asciiBytes = ByteArray.new()
		asciiBytes:set_size(ulen/2)
		local idx = 0
		while idx < asciiBytes:len() do
			asciiBytes:set_index(idx, unicodeRaw(2*idx,1):uint())
			idx = idx + 1
		end
		local t = asciiBytes:tvb()
		return t(0,t:len()):string()
	end
end


--parse ac	
local function parse_ac(buf, pkt, tree)
	local idx = 0
	local buf_len = buf:len()
	while idx < buf_len do
		local ptype = buf(idx,2):uint()
		local subTree = nil
		local dissector = nil
		local proto = nil
		local arg_length = nil
		
		-- determine proto and dissector
		if AC_VALUE_DICT[ptype] ~= nil then	
			proto = AC_VALUE_DICT[ptype].proto
			dissector = ac_protos[ptype]
		else
			proto = Unknow_AC
			dissector = nil
		end	
		-- determine length
		if ptype == 0x9029 then
			arg_length = -2
		else
			arg_length = buf(idx + 2, 2):uint()
		end
		
		if idx + 4 + arg_length <= buf_len then
			if dissector ~= nil then
				dissector:call(buf(idx, arg_length + 4):tvb(),pkt, tree)
			else
				local subTree = tree:add(proto, buf(idx, arg_length + 4))
				--subTree:add('TAG: ', tostring(buf(idx, 2)))
				--subTree:add('LENGTH: ', tostring(arg_length))
				--if arg_length <= 4 then
					--subTree:append_text(' : '..tostring(buf(idx + 4, arg_length)))
				--end
				
				if AC_VALUE_DICT[ptype] ~= nil and AC_VALUE_DICT[ptype].compound == true then
					local acTvb = buf(idx+4, arg_length):tvb()
					-- parse compound
					-- call self recursively. parsing next level
					parse_ac(acTvb, pkt, subTree)
				else 
					subTree:add('VALUE: ', tostring(buf(idx + 4, arg_length)))
				end
			end			
		else
			local subTree = tree:add('Fragement AC', buf(buf_len - idx))
			subTree:add('Payload: ', buf(buf_len - idx))
			return true				
		end
		
		idx = idx + arg_length + 4
	
	end	
end

-- 9011
local AC_VAL_VERSION = Proto("AC_VAL_VERSION", "Version")
	f_ac_version = ProtoField.uint8("AC_VAL_VERSION.ver", "Version")
	AC_VAL_VERSION.fields = {f_ac_version}
	function AC_VAL_VERSION.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_VERSION, buf(0, buf:len()))
		t:add(f_ac_version, buf(4,1))
	end
	ac_table:add(0x9011, AC_VAL_VERSION)
	ac_protos[0x9011] = ac_table:get_dissector(0x9011)

-- 9001
local AC_VAL_SERVICE_INDENTIFIER = Proto("AC_VAL_SERVICE_INDENTIFIER", "service identifer")
	service_id_onid = ProtoField.uint16("AC_VAL_SERVICE_INDENTIFIER.orig_networkid", "Original Network Id")
	service_id_transportId = ProtoField.uint16("AC_VAL_SERVICE_INDENTIFIER.transportId", "Transport Id")
	service_id_serviceId = ProtoField.uint16("AC_VAL_SERVICE_INDENTIFIER.serviceId", "Service Id")
	AC_VAL_SERVICE_INDENTIFIER.fields = {service_id_onid, service_id_transportId, service_id_serviceId}
	function AC_VAL_SERVICE_INDENTIFIER.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SERVICE_INDENTIFIER, buf(0, buf:len()))
		t:add(service_id_onid, buf(4, 2))
		t:add(service_id_transportId, buf(6, 2))
		t:add(service_id_serviceId, buf(8, 2))
	end
	ac_table:add(0x9001, AC_VAL_SERVICE_INDENTIFIER)
	ac_protos[0x9001] = ac_table:get_dissector(0x9001)

-- 9002
local AC_VAL_SERVICE_TAG = Proto("AC_VAL_SERVICE_TAG", "service tag")
	f_ac_serTag = ProtoField.string("AC_VAL_SERVICE_TAG.serTag", "service tag")
	AC_VAL_SERVICE_TAG.fields = {f_ac_serTag}
	function AC_VAL_SERVICE_TAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SERVICE_TAG, buf(0, buf:len()))
		t:add(f_ac_serTag, buf(4,buf:len()-4))
	end
	ac_table:add(0x9002, AC_VAL_SERVICE_TAG)
	ac_protos[0x9002] = ac_table:get_dissector(0x9002)

-- 9012	
local AC_VAL_SERVICE_ID = Proto("AC_VAL_SERVICE_ID", "service id")
	f_ac_serId = ProtoField.uint16("AC_VAL_SERVICE_ID.serId", "service id")
	AC_VAL_SERVICE_ID.fields = {f_ac_serId}
	function AC_VAL_SERVICE_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SERVICE_ID, buf(0, buf:len()))
		t:add(f_ac_serId, buf(4,2))
	end
	ac_table:add(0x9012, AC_VAL_SERVICE_ID)
	ac_protos[0x9012] = ac_table:get_dissector(0x9012)

-- 9013	
local AC_VAL_TRANSPORT_STREAM_ID = Proto("AC_VAL_TRANSPORT_STREAM_ID", "transport stream id")
	f_ac_ts = ProtoField.uint16("AC_VAL_TRANSPORT_STREAM_ID.ts", "transport id")
	AC_VAL_TRANSPORT_STREAM_ID.fields = {f_ac_ts}
	function AC_VAL_TRANSPORT_STREAM_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_TRANSPORT_STREAM_ID, buf(0, buf:len()))
		t:add(f_ac_ts, buf(4,2))
	end
	ac_table:add(0x9013, AC_VAL_TRANSPORT_STREAM_ID)
	ac_protos[0x9013] = ac_table:get_dissector(0x9013)

-- 9014	
local AC_VAL_NETWORK_ID = Proto("AC_VAL_NETWORK_ID", "network id")
	f_ac_networkId = ProtoField.uint16("AC_VAL_NETWORK_ID.networkid", "network id")
	AC_VAL_NETWORK_ID.fields = {f_ac_networkId}
	function AC_VAL_NETWORK_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_NETWORK_ID, buf(0, buf:len()))
		t:add(f_ac_networkId, buf(4,2))
	end
	ac_table:add(0x9014, AC_VAL_NETWORK_ID)
	ac_protos[0x9014] = ac_table:get_dissector(0x9014)

-- 9015	
local AC_VAL_COMPONENT_ID = Proto("AC_VAL_COMPONENT_ID", "component id")
	f_ac_comId = ProtoField.uint16("AC_VAL_COMPONENT_ID.componentId", "component id")
	AC_VAL_COMPONENT_ID.fields = {f_ac_comId}
	function AC_VAL_COMPONENT_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_COMPONENT_ID, buf(0, buf:len()))
		t:add(f_ac_comId, buf(4,2))
	end
	ac_table:add(0x9015, AC_VAL_COMPONENT_ID)
	ac_protos[0x9015] = ac_table:get_dissector(0x9015)

-- 9016
local AC_SET = Proto("AC_SET", "ac set")

-- 9017	
local AC_VAL_SECTOR = Proto("AC_VAL_SECTOR", "sector")
	f_ac_sector= ProtoField.uint8("AC_VAL_SECTOR.sector", "sector number")
	AC_VAL_SECTOR.fields = {f_ac_sector}
	function AC_VAL_SECTOR.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SECTOR, buf(0, buf:len()))
		t:add(f_ac_sector, buf(4,1))
	end
	ac_table:add(0x9017, AC_VAL_SECTOR)
	ac_protos[0x9017] = ac_table:get_dissector(0x9017)

-- 9018
local AC_VAL_PRODUCT_ID = Proto("AC_VAL_PRODUCT_ID", "product id")
	f_ac_pid = ProtoField.uint16("AC_VAL_PRODUCT_ID.pid", "product id")
	AC_VAL_PRODUCT_ID.fields = {f_ac_pid}
	function AC_VAL_PRODUCT_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PRODUCT_ID, buf(0, buf:len()))
		t:add(f_ac_pid, buf(4,2))
	end
	ac_table:add(0x9018, AC_VAL_PRODUCT_ID)
	ac_protos[0x9018] = ac_table:get_dissector(0x9018)

-- 9019
local AC_VAL_SPOTBEAM_ID = Proto("AC_VAL_SPOTBEAM_ID", "spotbeam id")
	f_ac_spotbeamId = ProtoField.uint16("AC_VAL_SPOTBEAM_ID.spotbeamId", "spotbeam id")
	AC_VAL_SPOTBEAM_ID.fields = {f_ac_spotbeamId}
	function AC_VAL_SPOTBEAM_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SPOTBEAM_ID, buf(0, buf:len()))
		t:add(f_ac_spotbeamId, buf(4,2))
	end
	ac_table:add(0x9019, AC_VAL_SPOTBEAM_ID)
	ac_protos[0x9019] = ac_table:get_dissector(0x9019)

--901A
local AC_VAL_BLOCKOUT_ID = Proto("AC_VAL_BLOCKOUT_ID", "blockout id")
	f_ac_blockoutId = ProtoField.uint16("AC_VAL_BLOCKOUT_ID.blockoutId", "blockout id")
	AC_VAL_BLOCKOUT_ID.fields = {f_ac_blockoutId}
	function AC_VAL_BLOCKOUT_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_BLOCKOUT_ID, buf(0, buf:len()))
		t:add(f_ac_blockoutId, buf(4,2))
	end
	ac_table:add(0x901A, AC_VAL_BLOCKOUT_ID)
	ac_protos[0x901A] = ac_table:get_dissector(0x901A)

-- 901B
local AC_VAL_PVR_FLAG = Proto("AC_VAL_PVR_FLAG", "pvr flag")
	f_ac_pvrFlag = ProtoField.uint8("AC_VAL_PVR_FLAG.pvrFlag", "pvr flag")
	AC_VAL_PVR_FLAG.fields = {f_ac_pvrFlag}
	function AC_VAL_PVR_FLAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PVR_FLAG, buf(0, buf:len()))
		t:add(f_ac_pvrFlag, buf(4,1))
	end
	ac_table:add(0x901B, AC_VAL_PVR_FLAG)
	ac_protos[0x901B] = ac_table:get_dissector(0x901B)

-- 901C
local AC_VAL_MARRIAGE_FLAG = Proto("AC_VAL_MARRIAGE_FLAG", "marriage flag")
	f_ac_marriageFlag = ProtoField.uint8("AC_VAL_MARRIAGE_FLAG.marriageFlag", "marriage flag")
	AC_VAL_MARRIAGE_FLAG.fields = {f_ac_marriageFlag}
	function AC_VAL_MARRIAGE_FLAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_MARRIAGE_FLAG, buf(0, buf:len()))
		t:add(f_ac_marriageFlag, buf(4,1))
	end
	ac_table:add(0x901C, AC_VAL_MARRIAGE_FLAG)
	ac_protos[0x901C] = ac_table:get_dissector(0x901C)

-- 901D
local AC_VAL_IPPV = Proto("AC_VAL_IPPV", "IPPV")
	preview_flag = ProtoField.uint8("AC_VAL_IPPV.preview_flag", "preview flag")
	event_ID = ProtoField.uint16("AC_VAL_IPPV.event_ID", "event ID")
	token_cost8 = ProtoField.uint8("AC_VAL_IPPV.token_cost8", "tokencost")
	token_cost16 = ProtoField.uint16("AC_VAL_IPPV.token_cost16", "tokencost")
	purchase_duration_unit = ProtoField.uint8("AC_VAL_IPPV.purchase_duration_unit", "purchase duration unit",base.HEX,{[1] = "Minutes", [0] = "Hours"}, 0x80)
	purchase_duration = ProtoField.uint16("AC_VAL_IPPV.purchase_duration", "purchase duration",base.DEC,nil,0x7fff)
	AC_VAL_IPPV.fields = {preview_flag, event_ID, token_cost8, token_cost16, purchase_duration_unit, purchase_duration}
	function AC_VAL_IPPV.dissector(buf, pkt,root)
		local t = root:add(AC_VAL_IPPV, buf(0, buf:len()))
		t:add(preview_flag, buf(4, 1))
		t:add(event_ID, buf(5, 2))
		
		local tokencostlen = 1
		local purchasedurationlen = 0
		if buf(2, 2):uint() == 4 then 
			-- tokencostlen = 1, purchasedurationlen = 0
			t:add(token_cost8, buf(7, 1))
		else
			t:add(token_cost16, buf(7, 2))
			if buf(2, 2):uint()  == 7 then
				-- tokencostlen = 2, purchasedurationlen = 2
				t:add(purchase_duration_unit, buf(9,1))
				t:add(purchase_duration, buf(9, 2))
			end
		end
	end
	ac_table:add(0x901D, AC_VAL_IPPV)
	ac_protos[0x901D] = ac_table:get_dissector(0x901D)

-- 901E
local AC_VAL_COPY_CONTROL = Proto("AC_VAL_COPY_CONTROL", "Copy Control")
	cci_analogue = ProtoField.uint8("AC_VAL_COPY_CONTROL.cci_analogue", "CCI-analogue", base.dec)
	cci_digital= ProtoField.uint8("AC_VAL_COPY_CONTROL.cci_digital", "CCI-digital", base.dec)
	AC_VAL_COPY_CONTROL.fields = {cci_analogue, cci_digital}
	function AC_VAL_COPY_CONTROL.dissector(buf, pkt,root)
		local t = root:add(AC_VAL_COPY_CONTROL, buf(0, buf:len()))
		t:add(cci_analogue, buf(4, 1))
		t:add(cci_digital, buf(5, 1))
	end
	ac_table:add(0x901E, AC_VAL_COPY_CONTROL)
	ac_protos[0x901E] = ac_table:get_dissector(0x901E)

-- 901F
local AC_VAL_MACROVISION = Proto("AC_VAL_MACROVISION", "Macrovision")
	f_ac_macrovision = ProtoField.uint8("AC_VAL_MACROVISION.macrovision", "Macrovision")
	AC_VAL_MACROVISION.fields = {f_ac_macrovision}
	function AC_VAL_MACROVISION.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_MACROVISION, buf(0, buf:len()))
		t:add(f_ac_macrovision, buf(4,1))
	end
	ac_table:add(0x901F, AC_VAL_MACROVISION)
	ac_protos[0x901F] = ac_table:get_dissector(0x901F)
	
--9020
local AC_VAL_CONTENT_RIGHT = Proto("AC_VAL_CONTENT_RIGHT", "content right")

--9021
local AC_VAL_EXTENDED_EVENT_ID = Proto("AC_VAL_EXTENDED_EVENT_ID", "extended event id")
	f_ac_exEventId = ProtoField.bytes("AC_VAL_EXTENDED_EVENT_ID.exEventId", "extended event id")
	AC_VAL_EXTENDED_EVENT_ID.fields = {f_ac_exEventId}
	function AC_VAL_EXTENDED_EVENT_ID.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_EXTENDED_EVENT_ID, buf(0, buf:len()))
		t:add(f_ac_exEventId, buf(4,buf:len()-4))
	end
	ac_table:add(0x9021, AC_VAL_EXTENDED_EVENT_ID)
	ac_protos[0x9021] = ac_table:get_dissector(0x9021)
	
--9022
local AC_VAL_PLAYBACK_WINDOW = Proto("AC_VAL_PLAYBACK_WINDOW", "playback window")
	playbackwindow_windowtype = ProtoField.uint8("AC_VAL_PLAYBACK_WINDOW.windowtype", "window type", base.HEX)
	playbackwindow_start_time = ProtoField.bytes("AC_VAL_PLAYBACK_WINDOW.starttime", "start time")
	playbackwindow_duration = ProtoField.bytes("AC_VAL_PLAYBACK_WINDOW.duration", "duration")
	AC_VAL_PLAYBACK_WINDOW.fields = {playbackwindow_windowtype, playbackwindow_start_time, playbackwindow_duration}
	function AC_VAL_PLAYBACK_WINDOW.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PLAYBACK_WINDOW, buf(0, buf:len()))
		t:add(playbackwindow_windowtype, buf(4, 1))
		t:add(playbackwindow_start_time, buf(5, 12))
		t:add(playbackwindow_duration, buf(17, 12))
	end
	ac_table:add(0x9022, AC_VAL_PLAYBACK_WINDOW)
	ac_protos[0x9022] = ac_table:get_dissector(0x9022)
	
--9023
local AC_VAL_NR_OF_PLAYBACKS = Proto("AC_VAL_NR_OF_PLAYBACKS", "nr of playbacks")
	f_ac_nrplayback = ProtoField.uint8("AC_VAL_NR_OF_PLAYBACKS.nrplayback", "nr of playbacks")
	AC_VAL_NR_OF_PLAYBACKS.fields = {f_ac_nrplayback}
	function AC_VAL_NR_OF_PLAYBACKS.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_NR_OF_PLAYBACKS, buf(0, buf:len()))
		t:add(f_ac_nrplayback, buf(4,1))
	end
	ac_table:add(0x9023, AC_VAL_NR_OF_PLAYBACKS)
	ac_protos[0x9023] = ac_table:get_dissector(0x9023)
	
--9024
local AC_VAL_MUST_EXPIRE_FLAG = Proto("AC_VAL_MUST_EXPIRE_FLAG", "must expire flag")
	f_ac_mustExpireFlag = ProtoField.uint8("AC_VAL_MUST_EXPIRE_FLAG.mustExpireFlag", "must expire flag")
	AC_VAL_MUST_EXPIRE_FLAG.fields = {f_ac_mustExpireFlag}
	function AC_VAL_MUST_EXPIRE_FLAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_MUST_EXPIRE_FLAG, buf(0, buf:len()))
		t:add(f_ac_mustExpireFlag, buf(4,1))
	end
	ac_table:add(0x9024, AC_VAL_MUST_EXPIRE_FLAG)
	ac_protos[0x9024] = ac_table:get_dissector(0x9024)
	
--9025
local AC_VAL_PRODUCT_RECORD_FLAG = Proto("AC_VAL_PRODUCT_RECORD_FLAG", "product record flag")
	f_ac_productRecordFlag = ProtoField.uint8("AC_VAL_PRODUCT_RECORD_FLAG.productRecordFlag", "product record flag")
	AC_VAL_PRODUCT_RECORD_FLAG.fields = {f_ac_productRecordFlag}
	function AC_VAL_PRODUCT_RECORD_FLAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PRODUCT_RECORD_FLAG, buf(0, buf:len()))
		t:add(f_ac_productRecordFlag, buf(4,1))
	end
	ac_table:add(0x9025, AC_VAL_PRODUCT_RECORD_FLAG)
	ac_protos[0x9025] = ac_table:get_dissector(0x9025)

--9026
local AC_VAL_CA_EXPRESSION = Proto("AC_VAL_CA_EXPRESSION", "ca expression")

--9027
local AC_VAL_PRODUCT_FILTER = Proto("AC_VAL_PRODUCT_FILTER", "product filter")

--9028
local AC_VAL_FILTER_TYPE = Proto("AC_VAL_FILTER_TYPE", "filter type")
	f_ac_filtertype = ProtoField.uint8("AC_VAL_FILTER_TYPE.filtertype", "filter type")
	AC_VAL_FILTER_TYPE.fields = {f_ac_filtertype}
	function AC_VAL_FILTER_TYPE.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_FILTER_TYPE, buf(0, buf:len()))
		t:add(f_ac_filtertype, buf(4,1))
	end
	ac_table:add(0x9026, AC_VAL_FILTER_TYPE)
	ac_protos[0x9026] = ac_table:get_dissector(0x9026)
	
--9029
local AC_VAL_OR_OPERATOR = Proto("AC_VAL_OR_OPERATOR", "Or Operator")

--902A
local EXTENDED_AC_SET = Proto("EXTENDED_AC_SET", "extended ac set")

--902B
local AC_VAL_PRODUCT_TAG = Proto("AC_VAL_PRODUCT_TAG", "product tag")
	f_ac_productTag = ProtoField.bytes("AC_VAL_PRODUCT_TAG.productTag", "product tag")
	AC_VAL_PRODUCT_TAG.fields = {f_ac_productTag}
	function AC_VAL_PRODUCT_TAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PRODUCT_TAG, buf(0, buf:len()))
		asciiStr = parse_unicode(buf(4,buf:len()-4):tvb())
		t:add(f_ac_productTag, buf(4,buf:len()-4), asciiStr)
	end
	ac_table:add(0x902B, AC_VAL_PRODUCT_TAG)
	ac_protos[0x902B] = ac_table:get_dissector(0x902B)
	
--902C
local AC_VAL_SPOTBEAM_TAG = Proto("AC_VAL_SPOTBEAM_TAG", "spotbeam tag")
	f_ac_spotbeamTag = ProtoField.string("AC_VAL_SPOTBEAM_TAG.spotbeamTag", "spotbeam tag")
	AC_VAL_SPOTBEAM_TAG.fields = {f_ac_spotbeamTag}
	function AC_VAL_SPOTBEAM_TAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_SPOTBEAM_TAG, buf(0, buf:len()))
		asciiStr = parse_unicode(buf(4,buf:len()-4):tvb())
		t:add(f_ac_spotbeamTag, buf(4,buf:len()-4), asciiStr)
	end
	ac_table:add(0x902C, AC_VAL_SPOTBEAM_TAG)
	ac_protos[0x902C] = ac_table:get_dissector(0x902C)
	
--902D
local AC_VAL_BLOCKOUT_TAG = Proto("AC_VAL_BLOCKOUT_TAG", "blockout tag")
	f_ac_blockoutTag = ProtoField.bytes("AC_VAL_BLOCKOUT_TAG.blockoutTag", "blockout tag")
	AC_VAL_BLOCKOUT_TAG.fields = {f_ac_blockoutTag}
	function AC_VAL_BLOCKOUT_TAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_BLOCKOUT_TAG, buf(0, buf:len()))
		asciiStr = parse_unicode(buf(4,buf:len()-4):tvb())
		t:add(f_ac_blockoutTag, buf(4,buf:len()-4), asciiStr)
	end
	ac_table:add(0x902D, AC_VAL_BLOCKOUT_TAG)
	ac_protos[0x902D] = ac_table:get_dissector(0x902D)	
	
--902E
local AC_VAL_MATURITY_RATING = Proto("AC_VAL_MATURITY_RATING", "maturity rating")
	f_ac_maturityRating = ProtoField.uint32("AC_VAL_MATURITY_RATING.maturityRating", "maturity rating", base.HEX, nil, 0xffffff)
	f_ac_rating_level = ProtoField.uint8("AC_VAL_MATURITY_RATING.ratingLevel", "rating level")
	AC_VAL_MATURITY_RATING.fields = {f_ac_maturityRating, f_ac_rating_level}
	function AC_VAL_MATURITY_RATING.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_MATURITY_RATING, buf(0, buf:len()))
		t:add(f_ac_maturityRating, buf(4,3))
		t:add(f_ac_rating_level, buf(7,1))
	end
	ac_table:add(0x902E, AC_VAL_MATURITY_RATING)
	ac_protos[0x902E] = ac_table:get_dissector(0x902E)	
	
--902F
local AC_VAL_COMPRESSED_COMPOUND = Proto("AC_VAL_COMPRESSED_COMPOUND", "compressed compound")
	f_ac_compression_type = ProtoField.uint8("AC_VAL_COMPRESSED_COMPOUND.compressionType", "compression type")
	f_ac_parameter_data = ProtoField.bytes("AC_VAL_COMPRESSED_COMPOUND.parameterdata", "parameter data")
	AC_VAL_COMPRESSED_COMPOUND.fields = {f_ac_compression_type, f_ac_parameter_data}
	function AC_VAL_COMPRESSED_COMPOUND.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_COMPRESSED_COMPOUND, buf(0, buf:len()))
		t:add(f_ac_compression_type, buf(4,1))
		t:add(f_ac_parameter_data, buf(5,buf:len()-5))
	end
	ac_table:add(0x902F, AC_VAL_COMPRESSED_COMPOUND)
	ac_protos[0x902F] = ac_table:get_dissector(0x902F)	
	
--9030
local AC_VAL_CIPLUS_COPY_CONTROL = Proto("AC_VAL_CIPLUS_COPY_CONTROL", "CI+ copy control")
	f_ac_ciplus_ict = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL.ict", "ict copy control")
	f_ac_ciplus_rct = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL.rct", "rct copy control info")
	f_ac_ciplus_rl = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL.rl", "rl copy control info")
	AC_VAL_CIPLUS_COPY_CONTROL.fields = {f_ac_ciplus_ict,f_ac_ciplus_rct,f_ac_ciplus_rl}
	function AC_VAL_CIPLUS_COPY_CONTROL.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_CIPLUS_COPY_CONTROL, buf(0, buf:len()))
		t:add(f_ac_ciplus_ict, buf(4,1))
		t:add(f_ac_ciplus_rct, buf(5,1))
		t:add(f_ac_ciplus_rl, buf(6,1))
	end
	ac_table:add(0x9030, AC_VAL_CIPLUS_COPY_CONTROL)
	ac_protos[0x9030] = ac_table:get_dissector(0x9030)

--9031
local AC_VAL_REQUIRED_CILAYER_LEVEL = Proto("AC_VAL_REQUIRED_CILAYER_LEVEL", "Required Ci Layer Level")
	f_ac_secure_chipset_pairing = ProtoField.uint8("AC_VAL_REQUIRED_CILAYER_LEVEL.secure_chipset_pairing", "secure_chipset_pairing", base.Hex, nil, 0xc0)
	f_ac_ci_layer = ProtoField.uint8("AC_VAL_REQUIRED_CILAYER_LEVEL.cilayer", "Ci Layer", base.Hex, nil, 0x30)
	f_ac_ipr = ProtoField.uint8("AC_VAL_REQUIRED_CILAYER_LEVEL.ipr", "IPR", base.Hex, nil, 0x0f)
	AC_VAL_REQUIRED_CILAYER_LEVEL.fields = {f_ac_secure_chipset_pairing,f_ac_ci_layer,f_ac_ipr}
	function AC_VAL_REQUIRED_CILAYER_LEVEL.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_REQUIRED_CILAYER_LEVEL, buf(0, buf:len()))
		t:add(f_ac_secure_chipset_pairing, buf(4,1))
		t:add(f_ac_ci_layer, buf(4,1))
		t:add(f_ac_ipr, buf(4,1))
	end
	ac_table:add(0x9031, AC_VAL_REQUIRED_CILAYER_LEVEL)
	ac_protos[0x9031] = ac_table:get_dissector(0x9031)
	
-- 9032
local AC_VAL_TRACEMARK_INDICATOR = Proto("AC_VAL_TRACEMARK_INDICATOR", "Tracemart Indicator")
	f_ac_tm_len = ProtoField.uint16("AC_VAL_TRACEMARK_INDICATOR.tmlen", "tracemark length", base.DEC)
	f_ac_tm_id_bitpos = ProtoField.uint8("AC_VAL_TRACEMARK_INDICATOR.id_bitpos", "id bit position")
	f_ac_tm_nr_of_cw = ProtoField.uint8("AC_VAL_TRACEMARK_INDICATOR.nr_of_cw", "number of CWs")
	f_ac_tm_cw = ProtoField.bytes("AC_VAL_TRACEMARK_INDICATOR.cw", "CW in Tracemark")
	AC_VAL_TRACEMARK_INDICATOR.fields = {f_ac_tm_len,f_ac_tm_id_bitpos,f_ac_tm_nr_of_cw, f_ac_tm_cw}
	function AC_VAL_TRACEMARK_INDICATOR.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_TRACEMARK_INDICATOR, buf(0, buf:len()))
		t:add(f_ac_tm_len, buf(4,2))
		t:add(f_ac_tm_id_bitpos, buf(6,1))
		t:add(f_ac_tm_nr_of_cw, buf(7,1))
		
		local tmLen = buf(4,2):uint()
		local nrCw = buf(7,1):uint()
		local cwLen = tmLen / nrCw  --maybe wrong, need check
		local idx = 8
		while idx < 8 + tmlen do
			t:add(f_ac_tm_cw, buf(idx, cwLen))
			idx = idx + cwLen
		end
	end
	ac_table:add(0x9032, AC_VAL_TRACEMARK_INDICATOR)
	ac_protos[0x9032] = ac_table:get_dissector(0x9032)
	
-- 9033
local AC_SET_EXTENSION = Proto("AC_SET_EXTENSION", "AC Set Extension")

-- 9034
local AC_VAL_CPS_EXPORT = Proto("AC_VAL_CPS_EXPORT", "cps export")
	f_ac_cps_len = ProtoField.uint16("AC_VAL_CPS_EXPORT.tmlen", "cps length", base.DEC)
	f_ac_cps_extended_drm_data = ProtoField.uint8("AC_VAL_CPS_EXPORT.extended_drm_data", "extended drm data")
	AC_VAL_CPS_EXPORT.fields = {f_ac_cps_len,f_ac_cps_extended_drm_data}
	function AC_VAL_CPS_EXPORT.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_CPS_EXPORT, buf(0, buf:len()))
		local cpsLen = buf(4,2):uint()
		t:add(f_ac_cps_len, buf(4,2))
		t:add(f_ac_cps_extended_drm_data, buf(6,cpsLen))
	end
	ac_table:add(0x9034, AC_VAL_CPS_EXPORT)
	ac_protos[0x9034] = ac_table:get_dissector(0x9034)
	
--9035
local AC_VAL_CIPLUS_COPY_CONTROL_13 = Proto("AC_VAL_CIPLUS_COPY_CONTROL_13", "CI+ copy control 13")
	f_ac_cpplus13_ict = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL_13.ict", "ict copy control")
	f_ac_cpplus13_rct = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL_13.rct", "rct copy control info")
	f_ac_cpplus13_rl = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL_13.rl", "rl copy control info")
	f_ac_cpplus13_ci_digital_only_token = ProtoField.uint8("AC_VAL_CIPLUS_COPY_CONTROL_13.ci_digital_only_token", "ci digital only token")
	AC_VAL_CIPLUS_COPY_CONTROL_13.fields = {f_ac_cpplus13_ict, f_ac_cpplus13_rct, f_ac_cpplus13_rl, f_ac_cpplus13_ci_digital_only_token}
	function AC_VAL_CIPLUS_COPY_CONTROL_13.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_CIPLUS_COPY_CONTROL_13, buf(0, buf:len()))
		t:add(f_ac_cpplus13_ict, buf(4,1))
		t:add(f_ac_cpplus13_rct, buf(5,1))
		t:add(f_ac_cpplus13_rl, buf(6,1))
		t:add(f_ac_cpplus13_ci_digital_only_token, buf(7,1))
	end
	ac_table:add(0x9035, AC_VAL_CIPLUS_COPY_CONTROL_13)
	ac_protos[0x9035] = ac_table:get_dissector(0x9035)
	
-- 9036
local AC_VAL_PVR_ACCESS_LEVEL = Proto("AC_VAL_PVR_ACCESS_LEVEL", "pvr access level")
	f_ac_pvr_access_level = ProtoField.uint8("AC_VAL_PVR_ACCESS_LEVEL.level", "level", base.DEC)
	AC_VAL_PVR_ACCESS_LEVEL.fields = {f_ac_pvr_access_level}
	function AC_VAL_PVR_ACCESS_LEVEL.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_PVR_ACCESS_LEVEL, buf(0, buf:len()))
		t:add(f_ac_pvr_access_level, buf(4,1))
	end
	ac_table:add(0x9036, AC_VAL_PVR_ACCESS_LEVEL)
	ac_protos[0x9036] = ac_table:get_dissector(0x9036)

-- 9037
local AC_VAL_NONE_SHAREABLE_FLAG = Proto("AC_VAL_NONE_SHAREABLE_FLAG", "none shareable flag")
	f_ac_none_shareable_flag = ProtoField.uint8("AC_VAL_NONE_SHAREABLE_FLAG.nonshareable", "nonshareable", base.DEC)
	AC_VAL_NONE_SHAREABLE_FLAG.fields = {f_ac_none_shareable_flag}
	function AC_VAL_NONE_SHAREABLE_FLAG.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_NONE_SHAREABLE_FLAG, buf(0, buf:len()))
		t:add(f_ac_none_shareable_flag, buf(4,1))
	end
	ac_table:add(0x9037, AC_VAL_NONE_SHAREABLE_FLAG)
	ac_protos[0x9037] = ac_table:get_dissector(0x9037)

-- 9040
local AC_VAL_HD_PLUS_TRICK_MODE = Proto("AC_VAL_HD_PLUS_TRICK_MODE", "HD+ Trick Mode")
	f_hd_plus_trick_mode = ProtoField.uint8("AC_VAL_HD_PLUS_TRICK_MODE.trickmode", "trickmode", base.HEX, nil, 0xE0)
	AC_VAL_HD_PLUS_TRICK_MODE.fields = {f_hd_plus_trick_mode}
	function AC_VAL_HD_PLUS_TRICK_MODE.dissector(buf, pkt, root)
		local t = root:add(AC_VAL_HD_PLUS_TRICK_MODE, buf(0, buf:len()))
		t:add(f_hd_plus_trick_mode, buf(4,1))
	end
	ac_table:add(0x9040, AC_VAL_HD_PLUS_TRICK_MODE)
	ac_protos[0x9040] = ac_table:get_dissector(0x9040)
	
-- unknow
local Unknow_AC = Proto("Unknow_AC", "Unknow AC")

AC_VALUE_DICT = {
				[0x9011] = {compound = false, proto = AC_VAL_VERSION, length = 1},
				[0x9001] = {compound = false, proto = AC_VAL_SERVICE_INDENTIFIER, length = 4},
				[0x9002] = {compound = false, proto = AC_VAL_SERVICE_TAG, length = nil},
				[0x9012] = {compound = false, proto = AC_VAL_SERVICE_ID, length = 2},
				[0x9013] = {compound = false, proto = AC_VAL_TRANSPORT_STREAM_ID, length = 2},
				[0x9014] = {compound = false, proto = AC_VAL_NETWORK_ID, length = 2},
				[0x9015] = {compound = false, proto = AC_VAL_COMPONENT_ID, length = 2},
				[0x9016] = {compound = true, proto = AC_SET, length = nil},
				[0x9017] = {compound = false, proto = AC_VAL_SECTOR, length = 1},
				[0x9018] = {compound = false, proto = AC_VAL_PRODUCT_ID, length = 2},
				[0x9019] = {compound = false, proto = AC_VAL_SPOTBEAM_ID, length = 2},
				[0x901A] = {compound = false, proto = AC_VAL_BLOCKOUT_ID, length = 2},
				[0x901B] = {compound = false, proto = AC_VAL_PVR_FLAG, length = 1},
				[0x901C] = {compound = false, proto = AC_VAL_MARRIAGE_FLAG, length = 1},
				[0x901D] = {compound = false, proto = AC_VAL_IPPV, length = nil},				
				[0x901E] = {compound = false, proto = AC_VAL_COPY_CONTROL, length = 2},
				[0x901F] = {compound = false, proto = AC_VAL_MACROVISION, length = 1},
				[0x9020] = {compound = true, proto = AC_VAL_CONTENT_RIGHT, length = nil},
				[0x9021] = {compound = false, proto = AC_VAL_EXTENDED_EVENT_ID, length = 32},
				[0x9022] = {compound = false, proto = AC_VAL_PLAYBACK_WINDOW, length = 25},
				[0x9023] = {compound = false, proto = AC_VAL_NR_OF_PLAYBACKS, length = 1},
				[0x9024] = {compound = false, proto = AC_VAL_MUST_EXPIRE_FLAG, length = 1},
				[0x9025] = {compound = false, proto = AC_VAL_PRODUCT_RECORD_FLAG, length = 1},
				[0x9026] = {compound = true, proto = AC_VAL_CA_EXPRESSION, length = nil},
				[0x9027] = {compound = true, proto = AC_VAL_PRODUCT_FILTER, length = nil},
				[0x9028] = {compound = false, proto = AC_VAL_FILTER_TYPE, length = 1},
				[0x9029] = {compound = false, proto = AC_VAL_OR_OPERATOR, length = 0},
				[0x902A] = {compound = false, proto = EXTENDED_AC_SET, length = nil},
				[0x902B] = {compound = false, proto = AC_VAL_PRODUCT_TAG, length = nil},
				[0x902C] = {compound = false, proto = AC_VAL_SPOTBEAM_TAG, length = nil},
				[0x902D] = {compound = false, proto = AC_VAL_BLOCKOUT_TAG, length = nil},
				[0x902E] = {compound = false, proto = AC_VAL_MATURITY_RATING, length = 4},
				[0x902F] = {compound = false, proto = AC_VAL_COMPRESSED_COMPOUND, length = nil},
				[0x9030] = {compound = false, proto = AC_VAL_CIPLUS_COPY_CONTROL, length = 3},
				[0x9031] = {compound = false, proto = AC_VAL_REQUIRED_CILAYER_LEVEL, length = 1},
				[0x9032] = {compound = false, proto = AC_VAL_TRACEMARK_INDICATOR, length = 2},
				[0x9033] = {compound = true, proto = AC_SET_EXTENSION, length = nil},
				[0x9034] = {compound = false, proto = AC_VAL_CPS_EXPORT, length = nil},
				[0x9035] = {compound = false, proto = AC_VAL_CIPLUS_COPY_CONTROL_13, length = 4},
				[0x9036] = {compound = false, proto = AC_VAL_PVR_ACCESS_LEVEL, length = 1},
				[0x9037] = {compound = false, proto = AC_VAL_NONE_SHAREABLE_FLAG, length = 1},
				[0x9038] = {compound = false, proto = AC_VAL_ENHANCED_COPY_PROTECTION, length = nil},
				[0x9039] = {compound = false, proto = AC_VAL_CI_PLUS_COPY_CONTROL_14, length = 5},
				[0x9040] = {compound = false, proto = AC_VAL_HD_PLUS_TRICK_MODE, length = 1}
	}


	--[[
	access criteria by reference to DVB triplet
	--]]
	AC_BYREF = Proto("AC_BYREF", "access criteria by reference")
	f_rtype = ProtoField.uint16("AC_BYREF.type", "AC by Reference", base.HEX)
	f_rlength = ProtoField.uint16("AC_BYREF.Length", "Length", base.DEC)
	f_roriginal_network_id = ProtoField.uint16("AC_BYREF.orinetworkid", "Original Network Id", base.DEC)
	f_rtransport_id = ProtoField.uint16("AC_BYREF.transportId", "Transport Id", base.DEC)
	f_rservice_id = ProtoField.uint16("AC_BYREF.serviceId", "Service Id", base.DEC)
	AC_BYREF.fields = {f_rtype, f_rlength, f_roriginal_network_id, f_rtransport_id, f_rservice_id}
	function AC_BYREF.dissector(buf, pkt,root)
		local ptype = buf(0, 2):uint()
		if ptype ~= 0x9001 then
			return false
		end
		
		local t = root:add(AC_BYREF, buf(0, buf:len()))
		t:add(f_rtype, buf(0, 2))
		t:add(f_rlength, buf(2, 2))
		t:add(f_roriginal_network_id, buf(4, 2))
		t:add(f_rtransport_id, buf(6, 2))
		t:add(f_rservice_id, buf(8, 2))
	end
	
	ac_table:add(0x9001, AC_BYREF)
	
	ac_protos[0x9001] = ac_table:get_dissector(0x9001)
	
	--[[
	access criteria by reference to service tag
	--]]
	AC_BYREF2TAG = Proto("AC_BYREF2TAG", "access criteria by reference to service tag")
	f_ttype = ProtoField.uint16("AC_BYREF2TAG.type", "AC by Reference to Service Tag", base.HEX)
	f_tlength = ProtoField.uint16("AC_BYREF2TAG.Length", "Length", base.DEC)
	f_tservice_tag = ProtoField.string("AC_BYREF2TAG.serviceTag", "Service Tag")
	AC_BYREF2TAG.fields = {f_ttype, f_tlength, f_tservice_id}
	function AC_BYREF2TAG.dissector(buf, pkt,root)
		local ptype = buf(0, 2):uint()
		if ptype ~= 0x9002 then
			return false
		end
		
		local len = buf(2, 2):uint()
		
		local t = root:add(AC_BYREF2TAG, buf(0,  buf:len()))
		t:add(f_ttype, buf(0, 2))
		t:add(f_tlength, buf(2, 2))
		t:add(f_tservice_tag, buf(4, len))
	end
	
	ac_table:add(0x9002, AC_BYREF2TAG)

	ac_protos[0x9002] = ac_table:get_dissector(0x9002)
	
	--[[
	access criteria by value
	--]]
	AC_BYVAL = Proto("AC_BYVAL", "access criteria by value")
	f_vtype = ProtoField.uint16("AC_BYVAL.type", "AC by Value", base.HEX)
	f_vlength = ProtoField.uint16("AC_BYVAL.Length", "Length", base.DEC)
	f_vplayload = ProtoField.bytes("AC_BYVAL.playload", "Values")
	AC_BYVAL.fields = {f_vtype, f_vlength, f_vplayload}
	function AC_BYVAL.dissector(buf, pkt,root)
		local ptype = buf(0, 2):uint()
		if ptype ~= 0x9010 then
			return false
		end
		
		local len = buf(2, 2):uint()
		
		local t = root:add(AC_BYVAL, buf(0,  buf:len()))
		t:add(f_vtype, buf(0, 2))
		t:add(f_vlength, buf(2, 2))
		
		if false == parse_ac(buf(4, len):tvb(),pkt,t) then 
			t:add(f_vplayload, buf(4, len))
		end
	end
	
	ac_table:add(0x9010, AC_BYVAL)
	
	ac_protos[0x9010] = ac_table:get_dissector(0x9010)
	
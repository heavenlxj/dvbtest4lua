--[[

SI Descriptors Library

--]]

desc_table = DissectorTable.new("DESCRIPTOR_TABLE", "SI Descriptors", FT_STRING)

--[[
DESCRIPTOR MAP (PARITIAL)
                    {
                    0x40: NetworkNameDescriptor,    				Y
                    0x5B: MultilingualNetworkNameDescriptor,
                    0x41: ServiceListDescriptor,   					 Y
                    0x90: NetworkListDescriptor,
                    0x62: FrequencyListDescriptor,
                    0x79: S2SatelliteDeliverySystemDescriptor,
                    0x43: SatelliteDeliverySystemDescriptor,
                    0x5a: TerrestrialDeliverySystemDescriptor,
                    0x47: BouquetNameDescriptor,					Y
                    0x91: BouquetListDescriptor,					Y
                    0x4f: TimeShiftedEventDescriptor,
                    0x54: ContentDescriptor,
                    0x4D: ShortEventDescriptor,
                    0x4b: NvodReferenceDescriptor,
                    0x64: DataBroadcastDescriptor,
                    0x48: ServiceDescriptor,							Y
                    0x5d: MultilingualServiceNameDescriptor,
                    0x49: CountryAvailabilityDescriptor,                    
                    0x4c: TimeShiftedServiceDescriptor,
                    0x4E: ExtendedEventDescriptor,
                    0x55: ParentalRatingDescriptor,
                    0x95: MuxTransportListDescriptor,
                    0x96: MuxSignatureDescriptor,
                    0x4a: IrdetoLinkageTypeDescriptor,					Y
                    0x5C: MultilingualBouquetNameDescriptor,
                    0x93: ChannelListMappingDescriptor,
                    0xf0: IrdetoIPPVDescriptor,
                    0x44: CableDeliverySystemDescriptor,
                    0xb0: EntitlementIndicationDescriptor,
                    0x94: EventTrackingDescriptor,
		    0x5f: PrivateDataSpecifierDescriptor				Y
                    }
--]]

--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------      SI  DESCRIPTORS LIST      -------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

local NETWORK_NAME_DESCRIPTOR = Proto("NETWORK_NAME_DESCRIPTOR", "Network Name Descriptor")
local nnd_network_name = ProtoField.string("NETWORK_NAME_DESCRIPTOR.network_name", "Network Name")

NETWORK_NAME_DESCRIPTOR.fields = {nnd_network_name}

function NETWORK_NAME_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(nnd_network_name, buf(0, buf_len))
end

desc_table:add(0x40, NETWORK_NAME_DESCRIPTOR)

-------------------------------------------------

local BOUQUET_NAME_DESCRIPTOR = Proto("BOUQUET_NAME_DESCRIPTOR", "Bouquet Name Descriptor")
local bnd_bouquet_name = ProtoField.string("BOUQUET_NAME_DESCRIPTOR.bouquet_name", "bouquet Name")

BOUQUET_NAME_DESCRIPTOR.fields = {bnd_bouquet_name}

function BOUQUET_NAME_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(bnd_bouquet_name, buf(0, buf_len))
end

desc_table:add(0x47, BOUQUET_NAME_DESCRIPTOR)

-------------------------------------------------

local SERVICE_LIST_DESCRIPTOR = Proto("SERVICE_LIST_DESCRIPTOR", "Service List Descriptor")
local sld_service_id = ProtoField.uint16("SERVICE_LIST_DESCRIPTOR.service_id", "Service Id", base.HEX)
local sld_service_type = ProtoField.bytes("SERVICE_LIST_DESCRIPTOR.service_type", "Service Type", base.HEX)

SERVICE_LIST_DESCRIPTOR.fields = {sld_service_id, sld_service_type}

function SERVICE_LIST_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
    local index = 0
    while index < buf_len do
		root:add(sld_service_id, buf(index, 2))
		root:add(sld_service_type, buf(index+2, 1))
		index = index + 3
	end	
end

desc_table:add(0x41, SERVICE_LIST_DESCRIPTOR)

-------------------------------------------------

local OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR = Proto("OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR", "Old Style Private Data Specifier Descriptor")
local ospdsd_old_style_private_data_specifier = ProtoField.uint32("OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR", "Old Style Private Data Specifier", base.HEX)

OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR.fields = {ospdsd_old_style_private_data_specifier}

function OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(ospdsd_old_style_private_data_specifier, buf(0, buf_len))
end

desc_table:add(0x80, OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR)

-------------------------------------------------

local BOUQUET_LIST_DESCRIPTOR = Proto("BOUQUET_LIST_DESCRIPTOR", "Bouquet List Descriptor")
local bld_bouquet_id = ProtoField.uint16("BOUQUET_LIST_DESCRIPTOR.bouquet_id", "Bouquet Id", base.HEX)

BOUQUET_LIST_DESCRIPTOR.fields = {bld_bouquet_id}

function BOUQUET_LIST_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
    local index = 0
    while index < buf_len do
		root:add(bld_bouquet_id, buf(index, 2))
		index = index + 2
	end	

end

desc_table:add(0x91, BOUQUET_LIST_DESCRIPTOR)

-------------------------------------------------

local CHANNEL_LIST_MAPPING_DESCRIPTOR = Proto("CHANNEL_LIST_MAPPING_DESCRIPTOR", "Channel List Mapping Descriptor")
local clmd_service_id = ProtoField.uint16("CHANNEL_LIST_MAPPING_DESCRIPTOR.service_id", "Service Id", base.HEX)
local clmd_channel_number = ProtoField.uint16("CHANNEL_LIST_MAPPING_DESCRIPTOR.channel_number", "Channel Number", base.HEX)

CHANNEL_LIST_MAPPING_DESCRIPTOR.fields = {clmd_service_id, clmd_channel_number}

function CHANNEL_LIST_MAPPING_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
        local index = 0
        while index < buf_len do
		root:add(clmd_service_id, buf(index, 2))		
                root:add(clmd_channel_number, buf(index+2, 2))
		index = index + 4
	end	

end

desc_table:add(0x93, CHANNEL_LIST_MAPPING_DESCRIPTOR)

-------------------------------------------------

local EVENT_TRACKING_DESCRIPTOR = Proto("EVENT_TRACKING_DESCRIPTOR", "Event Tracking Descriptor")
local etd_unique_event_id = ProtoField.uint32("EVENT_TRACKING_DESCRIPTOR.unique_event_id", "Unique Id", base.HEX)
local etd_main_content_id = ProtoField.uint32("EVENT_TRACKING_DESCRIPTOR.main_content_id", "Main Content Id", base.HEX)
local etd_sub_content_id = ProtoField.uint16("EVENT_TRACKING_DESCRIPTOR.sub_content_id", "Sub Content Id", base.HEX)
local etd_main_group_id = ProtoField.uint32("EVENT_TRACKING_DESCRIPTOR.main_group_id", "Main Group Id", base.HEX)
local etd_sub_group_id = ProtoField.uint16("EVENT_TRACKING_DESCRIPTOR.sub_group_id", "Sub Group Id", base.HEX)

EVENT_TRACKING_DESCRIPTOR.fields = {etd_unique_event_id, etd_main_content_id, etd_sub_content_id,  etd_main_group_id,  etd_sub_group_id}

function EVENT_TRACKING_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
        local index = 0
	root:add(etd_unique_event_id, buf(index, 4))		
        root:add(etd_main_content_id, buf(index+4, 4))
	root:add(etd_sub_content_id, buf(index+8, 2))
	root:add(etd_main_group_id, buf(index+10, 4))
	root:add(etd_sub_group_id, buf(index+14, 2))
end

desc_table:add(0x94, EVENT_TRACKING_DESCRIPTOR)

-------------------------------------------------

local NETWORK_LIST_DESCRIPTOR = Proto("NETWORK_LIST_DESCRIPTOR", "Network List Descriptor")
local nld_network_id = ProtoField.uint16("NETWORK_LIST_DESCRIPTOR.network_id", "Network Id", base.DEC)

NETWORK_LIST_DESCRIPTOR.fields = {nld_network_id}

function NETWORK_LIST_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
        local index = 0
        while index < buf_len do
		root:add(nld_network_id, buf(index, 2))		
		index = index + 2
	end	

end

desc_table:add(0x90, NETWORK_LIST_DESCRIPTOR)

-------------------------------------------------

local ENTITLEMENT_INDICATION_DESCRIPTOR = Proto("ENTITLEMENT_INDICATION_DESCRIPTOR", "Entitlement Indication Descriptor")
local SECTOR_BLOCK = Proto("SECTOR_BLOCK", "Sector Block")
local eid_sector_number = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.sector_number", "Sector Number", base.DEC)
local eid_num_scrambling_products = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.num_scrambling_products", "Number Of Scrambling Products", base.DEC)
local eid_scrambling_product = ProtoField.uint16("ENTITLEMENT_INDICATION_DESCRIPTOR.scrambling_product", "Scrambling Product", base.DEC)
local eid_product_type = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.product_type", "Product Type", base.DEC)
local eid_num_spot_beams = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.num_spot_beams", "Number Of Spot Beams", base.DEC)
local eid_spot_beams_product = ProtoField.uint16("ENTITLEMENT_INDICATION_DESCRIPTOR.spot_beams_product", "Spot Beams Product", base.DEC)
local eid_num_blockouts = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.num_blockouts", "Number Of Blocks", base.DEC)
local eid_blockout_product = ProtoField.uint16("ENTITLEMENT_INDICATION_DESCRIPTOR.blockout_product", "Blocks Product", base.DEC)
local eid_analog_copy_protection_cci = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTORS.analog_copy_protection_cci", "Analog Copy Protection CCI", base.HEX, nil, 0xc0)
local eid_digital_copy_protection_cci = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTORS.digital_copy_protection_cci", "Digital Copy Protection CCI", base.HEX, nil, 0x30)
local eid_reserved = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTOR.reserved", "Reserved", base.HEX, nil, 0x0f)
local eid_macrovision = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTORS.macrovision", "macrovision", base.HEX, nil, 0xfc)
local eid_reserved2 = ProtoField.uint8("ENTITLEMENT_INDICATION_DESCRIPTORS.reserved2", "Reserved2", base.HEX, nil, 0x03)
ENTITLEMENT_INDICATION_DESCRIPTOR.fields = {eid_sector_number, eid_num_scrambling_products, eid_scrambling_product, eid_product_type, eid_num_spot_beams, eid_spot_beams_product, eid_num_blockouts, eid_blockout_product, eid_analog_copy_protection_cci, eid_digital_copy_protection_cci, eid_reserved, eid_macrovision, eid_reserved2}

function ENTITLEMENT_INDICATION_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
        local index = 0

        while index < buf_len do
		local scrambling_products_index = 0
		local spot_beam_products_index = 0
		local blockout_products_index = 0

		sbk = root:add(SECTOR_BLOCK, buf(index, 1))
		sbk:add(eid_sector_number, buf(index, 1))

		sps = sbk:add(eid_num_scrambling_products, buf(index+1, 1))
		local num_scrambling_products = buf(index+1, 1):uint()
		while scrambling_products_index < num_scrambling_products do
			sps:add(eid_scrambling_product, buf(index+2+3*scrambling_products_index, 2)) 
			sps:add(eid_product_type, buf(index+4+3*scrambling_products_index, 1))
			scrambling_products_index = scrambling_products_index + 1
		end

		sbs = sbk:add(eid_num_spot_beams, buf(index+2+3*num_scrambling_products, 1))
		local num_spot_beams = buf(index+2+3*num_scrambling_products, 1):uint()
		while spot_beam_products_index < num_spot_beams do
			sbs:add(eid_scrambling_product, buf(index+2+3*num_scrambling_products+1+2*spot_beam_products_index, 2)) 
			spot_beam_products_index = spot_beam_products_index + 1
		end

		bs = sbk:add(eid_num_blockouts, buf(index+2+3*num_scrambling_products+1+2*num_spot_beams, 1))
		local num_blockouts = buf(index+2+3*num_scrambling_products+1+2*num_spot_beams, 1):uint()
		while blockout_products_index < num_blockouts do
			bs:add(eid_blockout_product, buf(index+2+3*num_scrambling_products+1+2*num_spot_beams+1+2*blockout_products_index, 2)) 
			blockout_products_index = blockout_products_index + 1
		end

		local temp_index = index+2+3*num_scrambling_products+1+2*num_spot_beams+1+2*num_blockouts
		sbk:add(eid_analog_copy_protection_cci, buf(temp_index, 1))
		sbk:add(eid_digital_copy_protection_cci, buf(temp_index, 1))
		sbk:add(eid_reserved, buf(temp_index, 1))
		sbk:add(eid_macrovision, buf(temp_index+1, 1))		
		sbk:add(eid_reserved2, buf(temp_index+1, 1))

		index = temp_index+2
	end	
end

desc_table:add(0xb0, ENTITLEMENT_INDICATION_DESCRIPTOR)

-------------------------------------------------

local IRDETO_IPPV_DESCRIPTOR = Proto("IRDETO_IPPV_DESCRIPTOR", "Irdeto IPPV Descriptor")
local IPPV_EVENT_BLOCK = Proto("IPPV_EVENT_BLOCK", "IPPV Event Block")
local IPPV_CURRENCY_DETAIL_BLOCK = Proto("IPPV_CURRENCY_DETAIL_BLOCK", "IPPV Currency Detail Block")
local iippvd_ippv_ca_event_id = ProtoField.uint64("IRDETO_IPPV_DESCRIPTOR.ippv_ca_event_id", "IPPV CA Event Id", base.DEC)
local iippvd_country_code = ProtoField.uint24("IRDETO_IPPV_DESCRIPTOR.country_code", "Country Code", base.HEX)
local iippvd_reserved_future_use = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.reserved_future_use", "Reserved Future Use", base.HEX, nil, 0xfc)
local iippvd_currency_detail_flag = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.currency_detail_flag", "Currency Detail Flag", base.DEC, nil, 0x02)
local iippvd_cost_detail_flag = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.cost_detail_flag", "Cost Detail Flag", base.DEC, nil, 0x01)
local iippvd_event_cost = ProtoField.uint32("IRDETO_IPPV_DESCRIPTOR.event_cost", "Event Cost", base.HEX)
local iippvd_language_loop_length = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.language_loop_length", "Language Loop Length", base.DEC)
local iippvd_iso_639_language_code = ProtoField.uint24("IRDETO_IPPV_DESCRIPTOR.iso_639_language_code", "ISO 639 Language Code", base.HEX)
local iippvd_reserved_future_use2 = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.reserved_future_use2", "Reserved Future Use2", base.HEX, nil, 0xfe)
local iippvd_currency_prefix_flag = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.currency_prefix_flag", "Currency Prefix Flag", base.HEX, nil, 0x01)
local iippvd_text_length = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.text_length", "Text Length", base.DEC)
local iippvd_text_char = ProtoField.uint8("IRDETO_IPPV_DESCRIPTOR.text_char", "Text Char", base.HEX)

IRDETO_IPPV_DESCRIPTOR.fields = {iippvd_ippv_ca_event_id, iippvd_country_code, iippvd_currency_detail_flag, iippvd_reserved_future_use, iippvd_cost_detail_flag, iippvd_event_cost, iippvd_language_loop_length, iippvd_iso_639_language_code, iippvd_reserved_future_use2, iippvd_currency_prefix_flag, iippvd_text_length, iippvd_text_char}

function IRDETO_IPPV_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local index = 0
	root:add(iippvd_ippv_ca_event_id, buf(index, 8))
	local cycle_index = index+8    
        while cycle_index < buf_len do
		local t = root:add(IPPV_EVENT_BLOCK, buf(cycle_index, 1))  
		t:add(iippvd_country_code, buf(cycle_index, 3))
		t:add(iippvd_reserved_future_use, buf(cycle_index+3, 1))
		t:add(iippvd_currency_detail_flag, buf(cycle_index+3, 1))
		local IPPV_currency_detail_flag = bit:_and(buf(cycle_index+3, 1):uint(), 0x02)
		t:add(iippvd_cost_detail_flag, buf(cycle_index+3, 1))
		local IPPV_cost_detail_flag = bit:_and(buf(cycle_index+3, 1):uint(), 0x01)

		if IPPV_cost_detail_flag == 1 then
			t:add(iippvd_event_cost, buf(cycle_index+4, 4))
			t:add(iippvd_language_loop_length, buf(cycle_index+8, 1))
			local language_loop_length = buf(cycle_index+8, 1):uint()
			if IPPV_currency_detail_flag == 2 then
				local r = t:add(IPPV_CURRENCY_DETAIL_BLOCK, buf(cycle_index+9, 1))
				local language_loop_index = 0
				while language_loop_index < language_loop_length do
					r:add(iippvd_iso_639_language_code, buf(cycle_index+9, 3))
					r:add(iippvd_reserved_future_use2, buf(cycle_index+12, 1))
					r:add(iippvd_currency_prefix_flag, buf(cycle_index+12, 1))
					local s = r:add(iippvd_text_length, buf(cycle_index+13, 1))
					local IPPV_text_length = buf(cycle_index+13, 1):uint()
					local text_index = 0
					while text_index < IPPV_text_length do
						s:add(iippvd_text_char, buf(cycle_index+14+text_index, 1))
						text_index = text_index+1
					end
					language_loop_index = language_loop_index+5+IPPV_text_length
				end
			end
			cycle_index = cycle_index+5+language_loop_length
		end
		cycle_index  = cycle_index+4
	end	
end

desc_table:add(0xf0, IRDETO_IPPV_DESCRIPTOR)

-------------------------------------------------

local SERVICE_DESCRIPTOR = Proto("SERVICE_DESCRIPTOR", "Service Descriptor")
local sd_service_type = ProtoField.uint8("SERVICE_DESCRIPTOR.service_type", "Service Type", base.HEX)
local sd_provider_name_len = ProtoField.uint8("SERVICE_DESCRIPTOR.p_name_len", "Provider Name Length", base.DEC)
local sd_provider_name = ProtoField.string("SERVICE_DESCRIPTOR.p_name", "Provider Name")
local sd_service_name_len = ProtoField.uint8("SERVICE_DESCRIPTOR.s_name_len", "Service Name Length", base.DEC)
local sd_service_name = ProtoField.string("SERVICE_DESCRIPTOR.service_name", "Service Name")

SERVICE_DESCRIPTOR.fields = {sd_service_type, sd_provider_name_len, sd_provider_name, sd_service_name_len, sd_service_name}

function SERVICE_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(sd_service_type, buf(0,1))
	root:add(sd_provider_name_len, buf(1,1))
	local provider_name_len = buf(1,1):uint()
	root:add(sd_provider_name, buf(2, provider_name_len))
	root:add(sd_service_name_len, buf(2+provider_name_len, 1))
	local service_len = buf(2+provider_name_len, 1):uint()
	root:add(sd_service_name, buf(3+provider_name_len, service_len))
end

desc_table:add(0x48, SERVICE_DESCRIPTOR)

-------------------------------------------------

local IRDETO_LINKAGE_TYPE_DESCRIPTOR = Proto("IRDETO_LINKAGE_TYPE_DESCRIPTOR", "Irdeto Linkage Type Descriptor")
local IRDETO_LINKAGE_CODE_DOWNLOAD = Proto("IRDETO_LINKAGE_CODE_DOWNLOAD", "Code Download Linkage Type")
local IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD = Proto("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD", "Enhanced Code Download Linkage Type")
local IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE = Proto("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE", "Software System Update Linkage Type")
local IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD = Proto("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD", "Dtvia Code Download Linkage Type")

local linkage_ts_id = ProtoField.uint16("IRDETO_LINKAGE_TYPE_DESCRIPTOR.ts_id", "Transport Stream Id", base.HEX)
local linkage_ori_nwid = ProtoField.uint16("IRDETO_LINKAGE_TYPE_DESCRIPTOR.ori_nwid", "Original Network Id", base.HEX)
local linkage_service_id = ProtoField.uint16("IRDETO_LINKAGE_TYPE_DESCRIPTOR.service_id", "Service Id", base.HEX)
local linkage_type = ProtoField.uint8("IRDETO_LINKAGE_TYPE_DESCRIPTOR.linkage_type", "Linkage Type", base.HEX)
local linkage_payload = ProtoField.bytes("IRDETO_LINKAGE_TYPE_DESCRIPTOR.payload", "Payload", base.HEX)

--CODE DOWNLOAD
local cd_manuf_code = ProtoField.uint8("IRDETO_LINKAGE_CODE_DOWNLOAD.manuf_code", "Manufacturer Code", base.HEX)
local cd_control_byte = ProtoField.uint8("IRDETO_LINKAGE_CODE_DOWNLOAD.control_byte", "Control Byte", base.HEX)

--ENHANCED CODE DOWNLOAD
local ecd_rfu = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.rfu", "RFU", base.HEX)
local ecd_manuf_code = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.manuf_code", "Enhanced Manufacturer Code", base.HEX)
local ecd_hardware_code = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.hardware_code", "Hardware Code", base.HEX)
local ecd_operator_variant_high = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.op_variant_h", "Operator Variant High", base.HEX)
local ecd_operator_variant_low = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.op_variant_l", "Operator Variant Low", base.HEX)
local ecd_load_sequence_nr = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.load_sequence_nr", "Load Sequence Number", base.HEX)
local ecd_control_byte = ProtoField.uint8("IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.control_byte", "Enhanced Control Byte", base.HEX)

--SOFTWARE SYSTEM UPDATE
local ssu_oui_data_len = ProtoField.uint8("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.oui_len", "OUI Data Length", base.DEC)
local ssu_oui = ProtoField.bytes("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.oui", "OUI", base.HEX)
local ssu_selector_len = ProtoField.uint8("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.selector_len", "Selector Length", base.DEC)
local ssu_maunf_id = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.manuf_id", "Manufacturer Id", base.HEX)
local ssu_hardware_version = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.hardware_version", "Hardware Version", base.HEX)
local ssu_rfu = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.rfu", "RFU", base.HEX)
local ssu_software_model = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.software_model", "Software Model", base.HEX)
local ssu_sub_software_model = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.sub_software_model", "Sub Software Model", base.HEX)
local ssu_software_version = ProtoField.uint16("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.software_version", "Software Version", base.HEX)
local ssu_trigger_control_byte = ProtoField.uint8("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.trigger_control_byte", "Trigger Control Byte", base.HEX)
local ssu_download_mode = ProtoField.uint8("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.download_mode", "Download Mode", base.HEX)
local ssu_private_data = ProtoField.bytes("IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.private_data", "Private Data", base.HEX)

--DTVIA CODE DOWNLOAD
local dcd_manuf_code = ProtoField.uint8("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.manuf_code", "Manufacturer Code", base.HEX)
local dcd_hardware_version = ProtoField.bytes("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.hardware_version", "Hardware Version", base.HEX)
local dcd_software_version = ProtoField.bytes("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.software_version", "Software Version", base.HEX)
local dcd_serial_nr_start = ProtoField.bytes("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.sn_start", "Serial Number Start", base.HEX)
local dcd_serial_nr_end = ProtoField.bytes("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.sn_end", "Serial Number End", base.HEX)
local dcd_control_code = ProtoField.uint8("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.control_code", "Control Code", base.HEX)
local dcd_rfu = ProtoField.uint16("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.rfu", "RFU", base.HEX)
local dcd_user_data_len = ProtoField.uint8("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.user_data_len", "User Data Length", base.DEC)
local dcd_user_data = ProtoField.bytes("IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.user_data", "User Data", base.HEX)

--Linkage Type Table
local linkage_type_table = DissectorTable.new("LINKAGE_TYPE", "Linkage Type Table", FT_STRING)

IRDETO_LINKAGE_TYPE_DESCRIPTOR.fields = {linkage_ts_id, linkage_ori_nwid, linkage_service_id, linkage_type, linkage_payload}
IRDETO_LINKAGE_CODE_DOWNLOAD.fields = {cd_manuf_code, cd_control_byte}
IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.fields = {ecd_rfu, ecd_manuf_code, ecd_hardware_code, ecd_operator_variant_high, ecd_operator_variant_low, ecd_load_sequence_nr, ecd_control_byte}
IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.fields = {ssu_oui_data_len, ssu_oui, ssu_selector_len, ssu_maunf_id, ssu_hardware_version, ssu_rfu, ssu_software_model, ssu_sub_software_model,
											ssu_software_version, ssu_trigger_control_byte, ssu_download_mode, ssu_private_data}
IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.fields = {dcd_manuf_code, dcd_hardware_version, dcd_software_version, dcd_serial_nr_start, dcd_serial_nr_end, dcd_control_code, dcd_rfu, dcd_user_data_len, dcd_user_data}

function IRDETO_LINKAGE_CODE_DOWNLOAD.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(IRDETO_LINKAGE_CODE_DOWNLOAD, buf(0, buf_len))
	local index = 0
	while index < buf_len do
		t:add(cd_manuf_code, buf(index, 1))
		t:add(cd_control_byte, buf(index+1, 1))
		index = index + 2
	end
end

 function IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD, buf(0, buf_len))
	local index = 0
	while index < buf_len do
		t:add(ecd_rfu, buf(index, 1))
		t:add(ecd_manuf_code, buf(index+1, 1))
		t:add(ecd_rfu, buf(index+2, 1))
		t:add(ecd_hardware_code, buf(index+3, 1))
		t:add(ecd_rfu, buf(index+4, 1))
		t:add(ecd_operator_variant_high, buf(index+5, 1))
		t:add(ecd_rfu, buf(index+6, 1))
		t:add(ecd_operator_variant_low, buf(index+7, 1))
		t:add(ecd_rfu, buf(index+8, 1))
		t:add(ecd_load_sequence_nr, buf(index+9, 1))
		t:add(ecd_rfu, buf(index+10, 1))
		t:add(ecd_control_byte, buf(index+11, 1))
		index = index + 12
	end
end

function IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE, buf(0, buf_len))
	t:add(ssu_oui_data_len, buf(0, 1))
	t:add(ssu_oui, buf(1, 3))
	t:add(ssu_selector_len, buf(4, 1))
	t:add(ssu_maunf_id, buf(5, 2))
	t:add(ssu_hardware_version, buf(7, 2))
	t:add(ssu_rfu, buf(9, 2))
	t:add(ssu_software_model, buf(11, 2))
	t:add(ssu_sub_software_model, buf(13, 2))
	t:add(ssu_software_version, buf(15, 2))
	t:add(ssu_trigger_control_byte, buf(17, 1))
	t:add(ssu_download_mode, buf(18, 1))
	t:add(ssu_private_data, buf(19, buf_len - 19))
end


function IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD, buf(0, buf_len))	
	t:add(dcd_manuf_code, buf(0,1))
	t:add(dcd_hardware_version, buf(1,4))
	t:add(dcd_software_version, buf(5,4))
	t:add(dcd_serial_nr_start, buf(9,4))
	t:add(dcd_serial_nr_end, buf(13,4))
	t:add(dcd_control_code, buf(17,1))
	t:add(dcd_rfu, buf(18,2))
	t:add(dcd_user_data_len, buf(20,1))
	local user_data_len = buf(20,1):uint()
	t:add(dcd_user_data, buf(21, user_data_len))	
end

linkage_type_table:add(0x09, IRDETO_LINKAGE_SOFTWARE_SYSTEM_UPDATE)
linkage_type_table:add(0x80, IRDETO_LINKAGE_CODE_DOWNLOAD)
linkage_type_table:add(0x82, IRDETO_LINKAGE_ENHANCED_CODE_DOWNLOAD)
linkage_type_table:add(0xa0, IRDETO_LINKAGE_DTVIA_CODE_DOWNLOAD)


function IRDETO_LINKAGE_TYPE_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(linkage_ts_id, buf(0, 2))
	root:add(linkage_ori_nwid, buf(2, 2))
	root:add(linkage_service_id, buf(4, 2))
	root:add(linkage_type, buf(6, 1))
	local linkage_type = buf(6,1):uint()
	local payload = buf(7, buf_len - 7)
	local dissect = linkage_type_table:get_dissector(linkage_type)
	if dissect ~= nil then
		dissect:call(payload:tvb(), pkt, root)
	else
		root:add(linkage_payload, payload)
	end
end

desc_table:add(0x4a, IRDETO_LINKAGE_TYPE_DESCRIPTOR)

-------------------------------------------------

local PRIVATE_DATA_SPECIFIER_DESCRIPTOR = Proto("PRIVATE_DATA_SPECIFIER_DESCRIPTOR", "Private Data Specifier Descriptor")
local pdsd_specifier = ProtoField.bytes("PRIVATE_DATA_SPECIFIER_DESCRIPTOR.spec", "Private Data Specifier", base.HEX)

PRIVATE_DATA_SPECIFIER_DESCRIPTOR.fields = {pdsd_specifier}

function PRIVATE_DATA_SPECIFIER_DESCRIPTOR.dissector(buf, pkt, root)
	local buf_len = buf:len()
	root:add(pdsd_specifier, buf(0, 4))
end

desc_table:add(0x5f, PRIVATE_DATA_SPECIFIER_DESCRIPTOR)


----------------------------------------------------------------------------------
----------------------------------------------------------------------------------
--------------------------   DESCRIPTOR MAP   ------------------------------------
----------------------------------------------------------------------------------
----------------------------------------------------------------------------------
DESCRIPTOR_MAP = {
					[0x40] = NETWORK_NAME_DESCRIPTOR,
					[0x41] = SERVICE_LIST_DESCRIPTOR,
					[0x47] = BOUQUET_NAME_DESCRIPTOR,
					[0x48] = SERVICE_DESCRIPTOR,
					[0x4a] = IRDETO_LINKAGE_TYPE_DESCRIPTOR,
					[0x5f] = PRIVATE_DATA_SPECIFIER_DESCRIPTOR,
					[0x80] = OLD_STYLE_PRIVATE_DATA_SPECIFIER_DESCRIPTOR,
					[0x90] = NETWORK_LIST_DESCRIPTOR,
					[0x91] = BOUQUET_LIST_DESCRIPTOR,
                    [0x93] = CHANNEL_LIST_MAPPING_DESCRIPTOR,
                    [0x94] = EVENT_TRACKING_DESCRIPTOR,
                    [0xb0] = ENTITLEMENT_INDICATION_DESCRIPTOR,
                    [0xf0] = IRDETO_IPPV_DESCRIPTOR
}

----------------------------------------------------------------------------------
----------------------------------------------------------------------------------
--------------------------   BASE DESCRIPTOR   -----------------------------------
----------------------------------------------------------------------------------
----------------------------------------------------------------------------------


local DESCRIPTORS = Proto("DESCRIPTORS", "Descriptors")
local BASE_DESCRIPTOR = Proto("BASE_DESCRIPTOR", "Base Descriptor")
local desc_tag = ProtoField.uint8("DESCRIPTORS.desc_tag", "Tag", base.HEX)
local desc_len = ProtoField.uint8("DESCRIPTORS.desc_len", "Length", base.DEC)
local desc_payload = ProtoField.bytes("DESCRIPTORS.payload", "Payload", base.DEC)

DESCRIPTORS.fields = {desc_tag, desc_len, desc_payload}

function DESCRIPTORS.dissector(buf, pkt, root)
	local buf_len = buf:len()
	if buf_len < 2 or buf_len > 256 then
		return false
	end
	
	local t = root:add(DESCRIPTORS, buf(0, buf_len))
	local index = 0
	while index < buf_len do
		local tag = buf(index, 1):uint()
		local length = buf(index+1, 1):uint()
		local payload = buf(index + 2, length)
		local dissect = desc_table:get_dissector(tag)
		if dissect ~= nil then
			local p = DESCRIPTOR_MAP[tag]
			if p ~= nil then
				local st = t:add(p, buf(index, 2+length))
				st:add(desc_tag, buf(index, 1))
				st:add(desc_len, buf(index+1, 1))
				dissect:call(payload:tvb(), pkt, st)
			else
				t:add('PROTOCOL : '..tostring(p))
				return false
			end
		else
			s = t:add(BASE_DESCRIPTOR, buf(index, length + 2))
			s:add(desc_tag, buf(index, 1))
			s:add(desc_len, buf(index+1, 1))
			s:add(desc_payload, payload)
		end

		index = index + 2 + length
	
	end
end

desc_table:add(0x00, DESCRIPTORS)

--TS STREAM BLOCKS

local TS_STREAM_BLOCKS = Proto("TS_STREAM_BLOCKS", "TS Stream Blocks")
local TS_STREAM_BLOCK = Proto("TS_STREAM_BLOCK", "TS Stream Block")
local ts_desc_ts_id = ProtoField.uint16("TS_STREAM_BLOCKS.ts_id", "Transport Stream Id", base.HEX)
local ts_desc_original_ni = ProtoField.uint16("TS_STREAM_BLOCKS.ori_ni", "Original Network Id", base.HEX)
local ts_desc_rfu = ProtoField.uint8("TS_STREAM_BLOCKS.rfu", "RFU", base.HEX, nil, 0xf0)
local ts_desc_len = ProtoField.uint16("TS_STREAM_BLOCKS.desc_len", "Transport Descriptors Length", base.DEC, nil, 0x0fff)
local ts_desc_payload = ProtoField.bytes("TS_STREAM_BLOCKS.desc_payload", "Descriptor Payload", base.HEX)

TS_STREAM_BLOCKS.fields = {ts_desc_ts_id, ts_desc_original_ni, ts_desc_rfu, ts_desc_len, ts_desc_payload}

function TS_STREAM_BLOCKS.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local index = 0
	local external_cycle_index = 0
	local t = root:add(TS_STREAM_BLOCKS, buf(index, buf_len))
	while external_cycle_index+2 < buf_len do
		local b = t:add(TS_STREAM_BLOCK, buf(external_cycle_index+2, 6))
		b:add(ts_desc_ts_id, buf(external_cycle_index+2, 2))
		b:add(ts_desc_original_ni, buf(external_cycle_index+4, 2))
		b:add(ts_desc_rfu, bit:_and(buf(external_cycle_index+6, 1):uint(), 0xf0))
		b:add(ts_desc_len, bit:_and(buf(external_cycle_index+6, 2):uint(), 0x0fff))
        local descriptor_index = external_cycle_index+8
		local descriptors_len = bit:_and(buf(external_cycle_index+6, 2):uint(), 0x0fff)
		while descriptor_index < descriptors_len do
			local tag = buf(descriptor_index, 1):uint()
			local length = buf(descriptor_index+1, 1):uint()
			local payload = buf(descriptor_index + 2, length)
			local dissect = desc_table:get_dissector(tag)
			if dissect ~= nil then
				local p = DESCRIPTOR_MAP[tag]
				if p ~= nil then
					local st = b:add(p, buf(descriptor_index, 2+length))
					st:add(desc_tag, buf(descriptor_index, 1))
					st:add(desc_len, buf(descriptor_index+1, 1))
					dissect:call(payload:tvb(), pkt, st)
				else
					b:add('PROTOCOL : '..tostring(p))
					return false
				end
			else
				s = b:add(BASE_DESCRIPTOR, buf(descriptor_index, length + 2))
				s:add(desc_tag, buf(descriptor_index, 1))
				s:add(desc_len, buf(descriptor_index+1, 1))
				s:add(desc_payload, payload)
			end
		
			descriptor_index = descriptor_index + 2 + length
	
		end
		external_cycle_index = external_cycle_index+6+descriptors_len
	end
end

desc_table:add(0x01, TS_STREAM_BLOCKS)

--SERVICE DESCRIPTOR BLOCK

local SERVICE_DESCRIPTORS = Proto("SERVICE_DESCRIPTORS", "Service Descriptors")
local SERVICE_DESCRIPTOR_BLOCK = Proto("SERVICE_DESCRIPTOR_BLOCK", "Service Descriptor Block")
local service_desc_id = ProtoField.uint16("SERVICE_DESCRIPTORS.service_id", "Service Id", base.HEX)
local service_desc_rfu = ProtoField.uint8("SERVICE_DESCRIPTORS.rfu", "RFU", base.HEX, nil, 0xfc)
local service_desc_eit_sf = ProtoField.uint8("SERVICE_DESCRIPTORS.eit_sf", "EIT Schedule Flag", base.HEX, nil, 0x02)
local service_desc_eit_pff = ProtoField.uint8("SERVICE_DESCRIPTORS.eit_pff", "EIT Present Following Flag", base.HEX, nil, 0x01)
local service_desc_rs = ProtoField.uint16("SERVICE_DESCRIPTORS.rs", "Running Status", base.HEX, {[0]= 'Undefined', [1] = 'Not Running', [2] = 'Starts in a few seconds', [3] = 'Pausing', [4] = 'Running', [5] = 'Service Off-Air', [6] = 'RFU', [7] = 'RFU'}, 0xe000)
local service_desc_fcm = ProtoField.uint16("SERVICE_DESCRIPTORS.fcm", "Free CA Mode", base.HEX, nil, 0x1000)
local service_desc_len = ProtoField.uint16("SERVICE_DESCRIPTORS.desc_len", "Descriptor Length", base.DEC, nil, 0x0fff)
local service_desc_payload = ProtoField.bytes("SERVICE_DESCRIPTORS.desc_payload", "Descriptor Payload", base.HEX)
local service_crc_32 = ProtoField.uint32("SERVICE_DESCRIPTORS.crc_32", "CRC_32", base.HEX)

SERVICE_DESCRIPTORS.fields = {service_desc_id, service_desc_rfu, service_desc_eit_sf, service_desc_eit_pff, service_desc_rs, service_desc_fcm, service_desc_len, service_desc_payload, service_crc_32}

function SERVICE_DESCRIPTORS.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(SERVICE_DESCRIPTORS, buf(0, buf_len))
	local index = 0
	while index < buf_len do
		if index + 5 <= buf_len then
			local desc_len = bit:_and(buf(index+3, 2):uint(), 0x0fff)
			local block_len = 5 + desc_len
			local p = t:add(SERVICE_DESCRIPTOR_BLOCK, buf(index, block_len))
			p:add(service_desc_id, buf(index, 2))
			p:add(service_desc_rfu, buf(index+2, 1))
			p:add(service_desc_eit_sf, buf(index + 2, 1))
			p:add(service_desc_eit_pff, buf(index + 2, 1))
			p:add(service_desc_rs, buf(index+3, 2))
			p:add(service_desc_fcm, buf(index+3, 2))
			p:add(service_desc_len, buf(index+3, 2))
			if desc_len > 0 then
				desc_table:get_dissector(0x00):call(buf(index+5, desc_len):tvb(), pkt, p)
			end
			index = index + 5 + desc_len
		else
			t:add(service_crc_32, buf(index, buf_len - index))
			break
		end
	end

end

desc_table:add(0x02, SERVICE_DESCRIPTORS)

--EIT DESCRIPTOR BLOCK

local EIT_DESCRIPTORS = Proto("EIT_DESCRIPTORS", "EIT Descriptors")
local EIT_DESCRIPTOR_BLOCK = Proto("EIT_DESCRIPTOR_BLOCK", "EIT Descriptor Block")
local eit_desc_evt_id = ProtoField.uint16("EIT_DESCRIPTORS.evt_id", "Event Id", base.HEX)
local eit_desc_start_time = ProtoField.bytes("EIT_DESCRIPTORS.start_time", "Start Time", base.HEX)
local eit_desc_eit_duration = ProtoField.bytes("EIT_DESCRIPTORS.eit_duration", "Duration", base.HEX)
local eit_desc_rs = ProtoField.uint16("EIT_DESCRIPTORS.rs", "Running Status", base.HEX, {[0]= 'Undefined', [1] = 'Not Running', [2] = 'Starts in a few seconds', [3] = 'Pausing', [4] = 'Running', [5] = 'Service Off-Air', [6] = 'RFU', [7] = 'RFU'}, 0xe000)
local eit_desc_fcm = ProtoField.uint16("EIT_DESCRIPTORS.fcm", "Free CA Mode", base.HEX, nil, 0x1000)
local eit_desc_len = ProtoField.uint16("EIT_DESCRIPTORS.desc_len", "Descriptor Length", base.DEC, nil, 0x0fff)
local eit_desc_payload = ProtoField.bytes("EIT_DESCRIPTORS.desc_payload", "Descriptor Payload", base.HEX)

EIT_DESCRIPTORS.fields = {eit_desc_evt_id, eit_desc_start_time, eit_desc_eit_duration, eit_desc_rs, eit_desc_fcm, eit_desc_len, eit_desc_payload}

function EIT_DESCRIPTORS.dissector(buf, pkt, root)
	local buf_len = buf:len()
	local t = root:add(EIT_DESCRIPTORS, buf(0, buf_len))
	local index = 0
	while index < buf_len do
		if index + 12 <= buf_len then
			local desc_len = bit:_and(buf(index+10, 2):uint(), 0x0fff)
			local block_len = index + 12 + desc_len
			local p = t:add(EIT_DESCRIPTOR_BLOCK, buf(index, block_len))
			p:add(eit_desc_evt_id, buf(index, 2))
			p:add(eit_desc_start_time, buf(index+2, 5))
			p:add(eit_desc_eit_duration, buf(index + 7, 3))
			p:add(eit_desc_rs, buf(index+10, 2))
			p:add(eit_desc_fcm, buf(index+10, 2))
			p:add(eit_desc_len, buf(index+10, 2))
			if desc_len > 0 then
				desc_table:get_dissector(0x00):call(buf(index+12, desc_len):tvb(), pkt, p)
			end
			index = index + 12 + desc_len
		else
			local p = t:add(EIT_DESCRIPTOR_BLOCK, buf(index, buf_len - index))
			p:add(ts_desc_payload, buf(index, buf_len - index))
			break
		end
	end

end

desc_table:add(0x03, EIT_DESCRIPTORS)

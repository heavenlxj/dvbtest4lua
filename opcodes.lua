--[[
opcodes.lua

This file contains the dissetors funtion for different opcodes of EMMs or ECMs, just for IUC.
If you need to add other opcodes, please update the list as below, thanks for your contribution.


EMM Opcode List For IUC:

0x80    ----------						Secotr Overwrite Opcode
0x81    ----------						Region Control Opcode
0x82    ----------						Paring Opcode
0x83	----------						Attribute Download Opcode
0x84	----------						Entitlement Property Opcode
0x85	----------						Timestamp	Opcode
0x86    ----------						Product Key Opcode
0x87	----------						PVRMSK Product Opcode
0x88	----------						Product Overwrite Opcode
0x89	----------						Clear Product Opcode
0x97	----------						Nationality Opcode
0x8f	----------						Stuffing Opcode
0x8c	----------						Application Data Opcode
0x90	----------						VOD Product Overwrite Opcoce
0x96	----------						VOD Asset ID Opocde
0x9a    ----------                      Advertisement EMM Opcode
0x9b    ----------                      Block Download EMM Opcode
0x9d    ----------                      Secure PVRMSK download Opcode
0xa3    ----------                      Shared PVRMSK Opcode 
0x9f    ----------						Product Key update Opcode
0xc1	----------						Time Stamp Filter Opcode
0xc5	----------						Life Time Opcode
0xa2	----------						ARP Config Opcode
0xae	----------						IFCP Image Advertisement
0xaf	----------						IFCP Image Download

EMM Opcode List For Smart Card:

0x1a	----------						Time Sync Opcode
0xfb	----------						Time Stamp Opcode
0x1d	----------						Time Refreshness Opcode
0x62	----------						Nationality Download Opcode
0x56	----------						Regional Control Opcode
0x11	----------						Product ID Download Opcode
0x05	----------						Surf	Lock Config Opcode
0x3b	----------						HGPC V5 Card Opcode
0x1e	----------						Macrovision Configuration Opcode
0xa0	----------						ARP Config Opcode
0x6b	----------						HGPC V6 Card Opcode
0x50	----------						Product Key Overwrite Opcode
0x68	----------						Sector Control Overwrite Opcode
0x0f	----------						Chipset Pairing Opcode
0x12	----------						Chipset Unpairing Opcode
0x14	----------						Extended Pairing Opcode	
0x98	----------						Scs Control Opcode
0xbb	----------						PVRMSK Download Opcode
0x13	----------						Tweak Key Opcode
0x43	----------						Patch Level Update Opcode
0x42	----------						Package Download Opcode
0xc4	----------						Package Level Filter Opcode
0x41	----------						Package Initiation Opocde
0x02	----------						Patch Data Download Opcode
0x01	----------						Patch Initiate Opcode
0x15	----------						OVK Download Opcode
0x18    ----------						Update TKc Opcode
0x58	----------						Ippv Debit Limit OpCode
0x59    ----------						IPPV Feedback Phone Number Download Opcode
0x5a	----------						Ippv Feedback Key Download OpCode
0x5b	----------						Ippv Initiate Callback OpCode
0xcb	----------						Group Vector Filter Opcode
0x25	----------						Product Vector Opcode
0x38    ----------						HGPC Primary Secure Client Activation Opcode
0x39	----------						HGPC Secondary Secure Client Activation Opcode
0x3a	----------						HGPC - Force Renew Opcode

--]]

--CCP PROTOCOL TABLE
ccp_table = DissectorTable.new("CCP_TABLE", "CCP OPCODES", FT_STRING)

--CCP OPCODE TABLE
ccp_opcodes_protos = {}

function is_stuffing_opcode(opcode)
	local stuffing_opcode = {
								[0x03] = 1, -- STUFFING CA2,
								[0xff] = 1, -- STUFFING CA3,
								[0x91] = 1, -- STUFFING CCA,
								[0x8f] = 1, -- STUFFING DVBSC
							}

	if (stuffing_opcode[opcode] and stuffing_opcode[opcode] == 1) then
		return true
	else
		return false
	end
end

function is_opcode_version2(opcode)
	local version2_opcode = { 	[0x81] = 1, 
								[0x97] = 1, 
								[0x80] = 1, 
								[0x82] = 1, 
								[0x83] = 1, 
								[0x84] = 1, 
								[0x85] = 1, 
								[0x87] = 1, 
								[0x88] = 1, 
								[0x8C] = 1,
								[0x8F] = 1, 
								[0x90] = 1,
								[0x96] = 1,
								[0x89] = 1,
								[0xC1] = 1,
								[0x9A] = 1,
								[0x9B] = 1,
								[0xA2] = 1,
								[0xAE] = 1,
								[0xAF] = 1
							}
	if ( version2_opcode[opcode] and version2_opcode[opcode] == 1 ) then
		return true
	else
		return false
	end
end

function is_dulipicate_opcode(opcode)
	local emm_ecm_opcode_list = {	[0xc4] = 1,
									[0xc0] = 1,
									[0xc5] = 1,
									[0xA2] = 1,
									[0xA3] = 1
								}
	if ( emm_ecm_opcode_list[opcode] and emm_ecm_opcode_list[opcode] == 1 ) then
		return true
	else
		return false
	end	
end

function is_dulipicate_emm_opcode(opcode)
	local ca2_ca3_opcode_list = {	[0x3b] = 1
								}
	if ( ca2_ca3_opcode_list[opcode] and ca2_ca3_opcode_list[opcode] == 1 ) then
		return true
	else
		return false
	end	
end

	--[[

	CCP Message

	--]]

	local CCP_PAR_UNKNOWN = Proto("CCP_PAR_UNKNOWN", "UnKnown opcode")
	f_opcode = ProtoField.uint8("CCP_PAR_UNKNOWN.OpCode", "OpCode", base.HEX)
	f_length = ProtoField.uint16("CCP_PAR_UNKNOWN.Length", "Length", base.DEC)
	f_data = ProtoField.bytes("CCP_PAR_UNKNOWN.Data", "Data")
	f_authentication = ProtoField.bytes("CCP_PAR_UNKNOWN.Authentication", "Authentication", base.HEX)
	CCP_PAR_UNKNOWN.fields = {f_opcode, f_length, f_data, f_authentication}
	function CCP_PAR_UNKNOWN.dissector(buf, pkt,root)
		local opcode = buf(0, 1) : uint()
		local length_size = 1

		if is_opcode_version2(opcode) then
			length_size = 2
		elseif is_stuffing_opcode(opcode) then
			length_size = 0
		end
		
		if   is_dulipicate_opcode(opcode) and cca_ecm_opcode_flag == true then
			opcode = 256 + opcode
		elseif is_dulipicate_opcode(opcode) and ca3_ecm_opcode_flag == true then
			opcode = 512 + opcode
		elseif is_dulipicate_opcode(opcode) and ca2_ecm_opcode_flag == true then
			opcode = 512 + opcode
		end
		
		if   is_dulipicate_emm_opcode(opcode) and ca3_emm_opcode_flag == true then
			opcode = 4096 + opcode
		end		

		local buf_len = buf:len()
		if buf_len < 1 + length_size then
			return false
		end
		
		local payload_length = nil 
		if length_size ~= 0 then	
			payload_length = buf(1, length_size) : uint()
		else
			payload_length = buf_len - 1
		end
		 
        if ccp_opcodes_protos[opcode] then
			local dis = ccp_opcodes_protos[opcode]["dis"]
			return dis:call(buf, pkt, root)
		elseif payload_length ~= 6 and buf_len == 8 then
			-- opcode is not recognized, the 'length field' is not correct, and the this is the last 8 bytes of the buffer.
			-- we can parse it as authentication.
			-- this field will not appear in MSP request. But some times we need to parse the MSP response. (ECM replacement)
			root:add(f_authentication, buf(0, 8))
			return true
		else
			local t = root:add(CCP_PAR_UNKNOWN, buf(0, payload_length+1+length_size))
			t:add( f_opcode, buf(0, 1))
			if length_size ~= 0 then
				t:add( f_length, buf(1, length_size))
			end
			t:add( f_data, buf( 1 + length_size, payload_length))
		end

		if buf_len < payload_length + 1 + length_size then
			return false
		end

		if ( buf_len - 1 - length_size - payload_length > 0) then
			local next_buf = buf( 1 + length_size + payload_length, buf_len - 1 - length_size - payload_length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	ccp_table:add(0xFFFF, CCP_PAR_UNKNOWN)


---------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------EMM OPCODES FOR  IUC----------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------	

--[[

	IUC :  Sector Overwrite Opcode Parser

--]]
	local CCP_PAR_SECTOR_OVERWRITE = Proto("CCP_PAR_SECTOR_OVERWRITE", "Sector Overwrite")
	f_sector_overwrite_opcode = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Opcode", "Opcode", base.HEX)
	f_sector_overwrite_length = ProtoField.uint16("CCP_PAR_SECTOR_OVERWRITE.Length", "Length", base.DEC)
	f_sector_overwrite_reserved1 = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Reserved1", "Reserved1", base.HEX, nil, 0xf0)
	f_sector_overwrite_sector_number = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Sector_Number", "Sector Number", base.HEX, nil, 0xf)
	f_sector_overwrite_reserved2 = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Reserved2", "Reserved2", base.HEX, nil, 0xfe)
	f_sector_overwrite_group_key_index = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Group_Key_Index", "Group Key Index", base.DEC, nil, 0x1)
	f_sector_overwrite_compound_generation = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Compound_Generation", "Compound Generation", base.HEX, nil, 0xf0)
	f_sector_overwrite_variant = ProtoField.uint8("CCP_PAR_SECTOR_OVERWRITE.Variant", "Variant", base.HEX, nil, 0x0f)
	f_sector_overwrite_group_key = ProtoField.bytes("CCP_PAR_SECTOR_OVERWRITE.Group_Key", "Group Key", base.HEX)
	f_sector_overwrite_super_group_position = ProtoField.bytes("CCP_PAR_SECTOR_OVERWRITE.Super_Group_Position", "Super Group Position", base.HEX)
	f_sector_overwrite_group_unique_address = ProtoField.bytes("CCP_PAR_SECTOR_OVERWRITE.Group_Unique_Address", "Group Unique Address", base.HEX)

	CCP_PAR_SECTOR_OVERWRITE.fields = {f_sector_overwrite_opcode, f_sector_overwrite_length, f_sector_overwrite_reserved1, f_sector_overwrite_reserved2,
									f_sector_overwrite_group_key_index, f_sector_overwrite_compound_generation, f_sector_overwrite_variant,
									f_sector_overwrite_group_key, f_sector_overwrite_super_group_position, f_sector_overwrite_group_unique_address,
									f_sector_overwrite_sector_number}

	function CCP_PAR_SECTOR_OVERWRITE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x80 then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_SECTOR_OVERWRITE, buf(0,  3 + length))
		t:add(f_sector_overwrite_opcode, buf(0, 1))
		t:add(f_sector_overwrite_length, buf(1, 2))
		t:add(f_sector_overwrite_reserved1, buf(3,1))
		t:add(f_sector_overwrite_sector_number, buf(3,1))
		t:add(f_sector_overwrite_reserved2, buf(4,1))
		t:add(f_sector_overwrite_group_key_index, buf(4,1))
		t:add(f_sector_overwrite_compound_generation, buf(5,1))
		t:add(f_sector_overwrite_variant, buf(5,1))
		t:add(f_sector_overwrite_group_key, buf(6,16))
		t:add(f_sector_overwrite_super_group_position, buf(22,2))
		t:add(f_sector_overwrite_group_unique_address, buf(24,3))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true

	end

	ccp_table:add(0x0080, CCP_PAR_SECTOR_OVERWRITE)

	-- register ccp opcodes table
	ccp_opcodes_protos = {
		[0x0080] = {
						["dis"] = ccp_table:get_dissector(0x0080),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}
	}

--[[

	IUC  :  Region Control Opcode Parser

--]]
	local CCP_PAR_REGION_CONTROL = Proto("CCP_PAR_REGION_CONTROL", "Region Control")
	f_region_control_opcode = ProtoField.uint8("CCP_PAR_REGION_CONTROL.OpCode", "OpCode", base.HEX)
	f_region_control_length = ProtoField.uint16("CCP_PAR_REGION_CONTROL.Length", "Length", base.DEC)
	f_region_control_region = ProtoField.uint8("CCP_PAR_REGION_CONTROL.Region", "Region", base.HEX)
	f_region_control_sub_region = ProtoField.uint8("CCP_PAR_REGION_CONTROL.SubRegion", "SubRegion", base.HEX)

	CCP_PAR_REGION_CONTROL.fields = {f_region_control_opcode, f_region_control_length, f_region_control_region, f_region_control_sub_region}
	function CCP_PAR_REGION_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x81 then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_REGION_CONTROL, buf(0,  3 + length))
		t:add( f_region_control_opcode, buf(0, 1))
		t:add( f_region_control_length, buf(1, 2))
		t:add( f_region_control_region, buf(3, 1))
		t:add( f_region_control_sub_region, buf(4,1))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0081, CCP_PAR_REGION_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0081]  = {
						["dis"] = ccp_table:get_dissector(0x0081),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[
	
IUC  :   Pairing opcode

--]]
	local CCP_PAR_PAIRING = Proto("CCP_PAR_PAIRING", "Pairing")
	f_pairing_opcode = ProtoField.uint8("CCP_PAR_PAIRING.Opcode", "Opcode", base.HEX)
	f_pairing_length = ProtoField.uint16("CCP_PAR_PAIRING.Length", "Length", base.DEC)
	f_pairing_reserved1 = ProtoField.uint8("CCP_PAR_PAIRING.Reserved1", "Reserved1", base.HEX, nil, 0xc0)
	f_pairing_key_ladder_support = ProtoField.uint8("CCP_PAR_PAIRING.Key_Ladder_Support", "Key Ladder Support", base.HEX, 
													{[0]='CW',[1]='CW+PVR',[2]='CW+PVR(OTT)',[3]='CW+PVR(PVR+OTT)'},
													0x30)
	f_pairing_sector_number = ProtoField.uint8("CCP_PAR_PAIRING.Sector_Number", "Sector Number", base.HEX)
	f_pairing_compound_generation = ProtoField.uint8("CCP_PAR_PAIRING.Compound_Generation", "Compound Generation", base.HEX, nil, 0xf0)
	f_pairing_variant = ProtoField.uint8("CCP_PAR_PAIRING.Variant", "Variant", base.HEX, nil, 0x0f)
	f_pairing_cssn = ProtoField.uint32("CCP_PAR_PAIRING.CSSN", "CSSN", base.DEC)
	f_pairing_cssk_xsmk = ProtoField.bytes("CCP_PAR_PAIRING.CSSK_XSMK", "CSSK Encrypted by XSMK", base.HEX)
	f_pairing_cssk_csuk = ProtoField.bytes("CCP_PAR_PAIRING.CSSK_CSUK", "CSSK Encrypted by CSUK", base.HEX)
	f_pairing_reserved2 = ProtoField.uint8("CCP_PAR_PAIRING.Reserved2", "Reserved2", base.HEX, nil, 0x80)
	f_pairing_ifcp_msr_indicator = ProtoField.uint8("CCP_PAR_PAIRING.IFCP_MSR_Indicator", "IFCP MSR Indicator", base.DEC, {[0]='MSR', [1]='IFCP'}, 0x80)
	f_pairing_key_cipher_mode = ProtoField.uint8("CCP_PAR_PAIRING.Key_Cipher_Mode", "Key Cipher Mode", base.HEX, nil, 0x70)
	f_pairing_reserved3 = ProtoField.uint8("CCP_PAR_PAIRING.Reserved3", "Reserved3", base.HEX, nil, 0x0c)
	f_pairing_secure_cw_mode = ProtoField.uint8("CCP_PAR_PAIRING.Secure_CW_Mode", "Secure CW Mode", base.HEX,
												{[0]='No key ladder}', [1]='2-TDES', [2]='Active node locked', [3]='AES'},
												0x03)
	f_pairing_cpsk_xsmk = ProtoField.bytes("CCP_PAR_PAIRING.CPSK_XSMK", "CPSK Encrypted by Pvr AES XSMK", base.HEX)
	f_pairing_cpsk_csuk = ProtoField.bytes("CCP_PAR_PAIRING.CPSK_CSUK", "CPSK Encrypted by Pvr AES CSUK", base.HEX)
	f_pairing_reserved4 = ProtoField.uint8("CCP_PAR_PAIRING.Reserved4", "Reserved4", base.HEX, nil, 0xf8)
	f_pairing_pvr_key_cipher_mode = ProtoField.uint8("CCP_PAR_PAIRING.Pvr_Key_Cipher_Mode", "Pvr Key Cipher Mode", base.HEX, nil, 0x07)
	f_pairing_ottsk_xsmk = ProtoField.bytes("CCP_PAR_PAIRING.CSSK_XSMK", "OTTSK Encrypted by Ott XSMK", base.HEX)
	f_pairing_ottsk_csuk = ProtoField.bytes("CCP_PAR_PAIRING.CSSK_CSUK", "OTTSK Encrypted by Ott CSUK", base.HEX)
	f_pairing_ott_key_cipher_mode = ProtoField.string("CCP_PAR_PAIRING.Ott_Key_Cipher_Mode", "Ott Key Cipher Mode", base.HEX, nil, 0x07)
	f_pairing_reserved5 = ProtoField.uint8("CCP_PAR_PAIRING.Reserved5", "Reserved5", base.HEX, nil, 0xf0)
	f_pairing_secure_pvr_mode = ProtoField.uint8("CCP_PAR_PAIRING.Secure_Pvr_Mode", "Secure Pvr Mode", base.HEX, {[1]='2-TDES',[2]='AES'}, 0x0c)
	f_pairing_secure_hls_mode = ProtoField.uint8("CCP_PAR_PAIRING.Secure_Hls_Mode", "Secure Hls Mode", base.HEX, nil, 0x03)
	
	CCP_PAR_PAIRING.fields = {f_pairing_opcode, f_pairing_length, f_pairing_reserved1,f_pairing_reserved2, f_pairing_reserved3,
							f_pairing_reserved4, f_pairing_reserved5, f_pairing_key_ladder_support, f_pairing_sector_number, f_pairing_compound_generation,
							f_pairing_variant, f_pairing_cssn, f_pairing_cssk_xsmk, f_pairing_cssk_csuk, f_pairing_key_cipher_mode, f_pairing_ifcp_msr_indicator, f_pairing_secure_cw_mode, 
							f_pairing_cpsk_xsmk, f_pairing_cpsk_csuk, f_pairing_pvr_key_cipher_mode, f_pairing_ottsk_xsmk, f_pairing_ottsk_csuk, f_pairing_ott_key_cipher_mode,
							f_pairing_secure_pvr_mode, f_pairing_secure_hls_mode}

	function CCP_PAR_PAIRING.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x82 then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_PAIRING, buf(0,  3 + length))
		t:add(f_pairing_opcode, buf(0, 1))
		t:add(f_pairing_length, buf(1, 2))
		t:add(f_pairing_reserved1, buf(3,1))
		t:add(f_pairing_key_ladder_support, buf(3,1))
		t:add(f_pairing_sector_number, buf(3,1))
		t:add(f_pairing_compound_generation, buf(4, 1))
		t:add(f_pairing_variant, buf(4, 1))
		t:add(f_pairing_cssn, buf(5,4))
		t:add(f_pairing_cssk_xsmk, buf(9,16))
		t:add(f_pairing_cssk_csuk, buf(25,16))
		t:add(f_pairing_reserved2, buf(41,1))
		t:add(f_pairing_ifcp_msr_indicator, buf(41,1))
		t:add(f_pairing_key_cipher_mode, buf(41,1))
		t:add(f_pairing_reserved3, buf(41,1))
		t:add(f_pairing_secure_cw_mode, buf(41,1))
		
		local key_ladder_support = bit:_and(bit:_rshift(buf(3,1):uint(), 4), 0x03)
		if (key_ladder_support == 0x1) then
		    t:add(f_pairing_cpsk_xsmk, buf(42,16))
		    t:add(f_pairing_cpsk_csuk, buf(58,16))
		    t:add(f_pairing_reserved4, buf(74,1))
			t:add(f_pairing_pvr_key_cipher_mode, buf(74,1))
			t:add(f_pairing_reserved5, buf(75,1))
		    t:add(f_pairing_secure_pvr_mode, buf(75,1))
		    t:add(f_pairing_secure_hls_mode, buf(75,1))
		end
		
		if (key_ladder_support == 0x2) then
		    t:add(f_pairing_ottsk_xsmk, buf(42,16))
		    t:add(f_pairing_ottsk_csuk, buf(58,16))
		    t:add(f_pairing_reserved4, buf(74,1))
		    t:add(f_pairing_ott_key_cipher_mode, buf(74,1))
			t:add(f_pairing_reserved5, buf(75,1))
		    t:add(f_pairing_secure_pvr_mode, buf(75,1))
		    t:add(f_pairing_secure_hls_mode, buf(75,1))
		end
		
		if (key_ladder_support == 0x3) then
		    t:add(f_pairing_cpsk_xsmk, buf(42,16))
		    t:add(f_pairing_cpsk_csuk, buf(58,16))
		    t:add(f_pairing_reserved4, buf(74,1))
		    t:add(f_pairing_pvr_key_cipher_mode, buf(74,1))
		    t:add(f_pairing_ottsk_xsmk, buf(75,16))
		    t:add(f_pairing_ottsk_csuk, buf(91,16))
		    t:add(f_pairing_reserved4, buf(107,1))
		    t:add(f_pairing_ott_key_cipher_mode, buf(107,1))
			t:add(f_pairing_reserved5, buf(108,1))
		    t:add(f_pairing_secure_pvr_mode, buf(108,1))
		    t:add(f_pairing_secure_hls_mode, buf(108,1))
		end
		
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true

	end

	ccp_table:add(0x0082, CCP_PAR_PAIRING)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0082]  = {
						["dis"] = ccp_table:get_dissector(0x0082),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :   Attribute Download Opcode Parser

--]]
	local CCP_PAR_ATTRIBUTE_DOWNLOAD = Proto("CCP_PAR_ATTRIBUTE_DOWNLOAD", "Attribute Download")
	f_attribute_download_opcode = ProtoField.uint8("CCP_PAR_ATTRIBUTE_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_attribute_download_length = ProtoField.uint16("CCP_PAR_ATTRIBUTE_DOWNLOAD.Length", "Length", base.DEC)
	f_attribute_download_attribute_index = ProtoField.uint8("CCP_PAR_ATTRIBUTE_DOWNLOAD.attribute_index", "Attribute_Index", base.HEX)
	f_attribute_download_offest = ProtoField.uint8("CCP_PAR_ATTRIBUTE_DOWNLOAD.offset", "Offset", base.HEX)
	f_attribute_download_attribute_value = ProtoField.bytes("CCP_PAR_ATTRIBUTE_DOWNLOAD.attribute_value", "Attribute Value", base.HEX)

	CCP_PAR_ATTRIBUTE_DOWNLOAD.fields = {f_attribute_download_opcode, f_attribute_download_length, f_attribute_download_attribute_index,
										f_attribute_download_offest, f_attribute_download_attribute_value}

	function CCP_PAR_ATTRIBUTE_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x83 then
			return false
		end

		local length = buf(1, 2) : uint()
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_ATTRIBUTE_DOWNLOAD, buf(0,  3 + length))
		t:add(f_attribute_download_attribute_index, buf(3,1))
		t:add(f_attribute_download_offest, buf(4,1))
		t:add(f_attribute_download_attribute_value, buf(5, buf_len -5))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true

	end

	ccp_table:add(0x0083, CCP_PAR_ATTRIBUTE_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0083]  = {
						["dis"] = ccp_table:get_dissector(0x0083),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

	
--[[

	IUC  :   Entitlement property opcode

--]]

	local CCP_PAR_ENTITLEMENT_PROPERTY = Proto("CCP_PAR_ENTITLEMENT_PROPERTY", "Entitlement Property")
	f_entitlement_property_opcode = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Opcode", "Opcode", base.HEX)
	f_entitlement_property_length = ProtoField.uint16("CCP_PAR_ENTITLEMENT_PROPERTY.Length", "Length", base.DEC)
	f_entitlement_property_rfu1 = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Rfu1", "Rfu1", base.DEC, nil, 0xc0)
	f_entitlement_property_flag_field_length = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.FL", "Flag Field Length", base.DEC, nil, 0x30)
	f_entitlement_property_starting_date_field_length = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.SDL", "Starting Date Field Length", base.DEC, nil, 0x0c)
	f_entitlement_property_duration_field_length = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.DL", "Duration Field Length", base.DEC, nil, 0x03)
	f_entitlement_property_flags = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags", "Flags", base.HEX)
	fepf_rfu = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags.RFU", "RFU", base.DEC, nil, 0xf0)
	fepf_PTO = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags.PTO", "Purchase to Own", base.DEC, nil, 0x08)
	fepf_SVOD = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags.SVOD", "Subscription VOD Product", base.DEC, nil, 0x04)
	fepf_PPVVOD = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags.PPVVOD", "PPV VOD Product", base.DEC, nil, 0x02)
	fepf_FSU = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Flags.FSU", "FSU product", base.DEC, nil, 0x01)
	f_entitlement_property_starting_date = ProtoField.string("CCP_PAR_ENTITLEMENT_PROPERTY.StartingDate", "StartingDate")
	f_entitlement_property_rfu2 = ProtoField.string("CCP_PAR_ENTITLEMENT_PROPERTY.Rfu2", "Rfu2")
	f_entitlement_property_extension_to_starting_date = ProtoField.bytes("CCP_PAR_ENTITLEMENT_PROPERTY.ESD", "Extension to Starting Date", base.DEC)
    f_entitlement_property_duration = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.Duration", "Duration", base.DEC)
	f_entitlement_property_extension_to_duration = ProtoField.bytes("CCP_PAR_ENTITLEMENT_PROPERTY.ExtensionToDuration", "Extension to Duration", base.HEX)
	fepetd_rfu = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.ExtensionToDuration.RFU", "RFU", base.DEC, nil, 0xfe)
	fepetd_hours = ProtoField.uint8("CCP_PAR_ENTITLEMENT_PROPERTY.ExtensionToDuration.Hours", "Hours", base.DEC, nil, 0x01)
	fepetd_extdur = ProtoField.bytes("CCP_PAR_ENTITLEMENT_PROPERTY.ExtensionToDuration.ExtDuration", "Extension to duration", base.DEC)

	CCP_PAR_ENTITLEMENT_PROPERTY.fields = {f_entitlement_property_opcode, f_entitlement_property_length, f_entitlement_property_rfu1, f_entitlement_property_flag_field_length,
							f_entitlement_property_starting_date_field_length, f_entitlement_property_duration_field_length, f_entitlement_property_flags, f_entitlement_property_starting_date,
							f_entitlement_property_rfu2, f_entitlement_property_extension_to_starting_date, f_entitlement_property_duration, f_entitlement_property_extension_to_duration,
							fepf_rfu, fepf_PTO, fepf_SVOD, fepf_PPVVOD, fepf_FSU, fepetd_rfu, fepetd_hours, fepetd_extdur}

	function CCP_PAR_ENTITLEMENT_PROPERTY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x84 then
			return false
		end

		local length = buf(1, 2) : uint()
             local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_ENTITLEMENT_PROPERTY, buf(0,  3 + length))
		t:add(f_entitlement_property_opcode, buf(0, 1))
		t:add(f_entitlement_property_length, buf(1, 2))
		t:add(f_entitlement_property_rfu1, buf(3,1))--, bit:_rshift((bit:_and(buf(3, 1):uint(), 0xC0)),6))
		t:add(f_entitlement_property_flag_field_length, buf(3,1))--, bit:_rshift((bit:_and(buf(3,1):uint(), 0x30)),4))
		t:add(f_entitlement_property_starting_date_field_length, buf(3,1))--, bit:_rshift((bit:_and(buf(3,1):uint(), 0x0C)),2))
		t:add(f_entitlement_property_duration_field_length, buf(3,1))--, bit:_and(buf(3,1):uint(), 0x03))
		local fl = bit:_rshift((bit:_and(buf(3,1):uint(), 0x30)),4)
		local sdl = bit:_rshift((bit:_and(buf(3,1):uint(), 0x0C)),2)
		local dl = bit:_and(buf(3,1):uint(), 0x03)
		local t_flags = t:add(f_entitlement_property_flags, buf(4, fl))
		t_flags:add(fepf_rfu, buf(4, fl))--, bit:_rshift(bit:_and(buf(4,1):uint(), 0xf0), 4))
		t_flags:add(fepf_PTO, buf(4, fl))--, bit:_rshift(bit:_and(buf(4,1):uint(), 0x08), 3))
		t_flags:add(fepf_SVOD, buf(4, fl))--, bit:_rshift(bit:_and(buf(4,1):uint(), 0x04), 2))
		t_flags:add(fepf_PPVVOD, buf(4, fl))--, bit:_rshift(bit:_and(buf(4,1):uint(), 0x02), 1))
		t_flags:add(fepf_FSU, buf(4, fl))--, bit:_and(buf(4,1):uint(), 0x01))
		
		t:add(f_entitlement_property_starting_date, buf(4+fl, 2), bit:_rshift(buf(4+fl, 2):uint(),1))
		t:add(f_entitlement_property_rfu2, buf(4+fl,2), bit:_and(buf(4+fl,2):uint(), 0x0001))
		local extension_offset = 0
		if sdl ~= 0 then
		    t:add(f_entitlement_property_extension_to_starting_date, buf(6+fl, sdl+2))
			extension_offset = 6+fl+sdl+2
		else
			t:add(f_entitlement_property_duration, buf(6+fl, 1))
			extension_offset = 6+fl+1
		end
		local offset = 6+fl+sdl+2
		if dl ~=0 then
			local t_extdur = t:add(f_entitlement_property_extension_to_duration, buf(extension_offset, dl))
			t_extdur:add(fepetd_rfu, buf(extension_offset, 1))--, bit:_rshift(bit:_and(buf(extension_offset, 1):uint(), 0xfe), 1))
			t_extdur:add(fepetd_hours, buf(extension_offset, 1))--, bit:_and(buf(extension_offset, 1):uint(), 0x01))
			t_extdur:add(fepetd_extdur, buf(extension_offset+1, dl-1))
		end

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true

	end

	ccp_table:add(0x0084, CCP_PAR_ENTITLEMENT_PROPERTY)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0084]  = {
						["dis"] = ccp_table:get_dissector(0x0084),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  Timestamp Opcode Parser

--]]
	local CCP_PAR_TIMESTAMP = Proto("CCP_PAR_TIMESTAMP", "Timestamp")
	f_timestamp_opcode = ProtoField.uint8("CCP_PAR_TIMESTAMP.Opcode", "Opcode", base.HEX)
	f_timestamp_length = ProtoField.uint16("CCP_PAR_TIMESTAMP.Length", "Length", base.DEC)
	f_timestamp_rfu= ProtoField.uint8("CCP_PAR_TIMESTAMP.Rfu", "Rfu", base.DEC)
	f_timestamp = ProtoField.bytes("CCP_PAR_TIMESTAMP.Timestamp", "Timestamp", base.HEX)

	CCP_PAR_TIMESTAMP.fields = {f_timestamp_opcode, f_timestamp_length, f_timestamp_rfu, f_timestamp}
	function CCP_PAR_TIMESTAMP.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x85 then
			return false
		end

		local length = buf(1, 2) : uint()
             local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_TIMESTAMP, buf(0,  3 + length))
		t:add( f_timestamp_opcode, buf(0, 1))
		t:add( f_timestamp_length, buf(1, 2))
		t:add( f_timestamp_rfu, buf(3, 1))
		t:add( f_timestamp, buf(4, 4))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0085, CCP_PAR_TIMESTAMP)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0085]  = {
						["dis"] = ccp_table:get_dissector(0x0085),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  Product Key Opcode Parser

--]]

	local CCP_PAR_PRODUCT_KEY = Proto("CCP_PAR_PRODUCT_KEY", "Product key")
	f_product_key_opcode = ProtoField.uint8("CCP_PAR_PRODUCT_KEY.Opcode", "Opcode", base.HEX)
	f_product_key_length = ProtoField.uint16("CCP_PAR_PRODUCT_KEY.Length", "Length", base.DEC)
	f_product_key_index = ProtoField.uint8("CCP_PAR_PRODUCT_KEY.KeyIndex", "KeyIndex", base.DEC)
	f_product_key_cg = ProtoField.string("CCP_PAR_PRODUCT_KEY.CG", "CompoundGeneration")
	f_product_key_var = ProtoField.string("CCP_PAR_PRODUCT_KEY.VAR", "Variant")
	f_product_key_pkey = ProtoField.bytes("CCP_PAR_PRODUCT_KEY.PKey", "ProductKey")

	CCP_PAR_PRODUCT_KEY.fields = {f_product_key_opcode, f_product_key_length, f_product_key_index, f_product_key_cg, f_product_key_var, f_product_key_pkey, f_product_key_product_group_transformation}
	function CCP_PAR_PRODUCT_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x86 then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_PRODUCT_KEY, buf(0,  3 + length))
		t:add( f_product_key_opcode, buf(0, 1))
		t:add( f_product_key_length, buf(1, 2))
		t:add( f_product_key_index, bit:_rshift(buf(3, 1):uint(), 3))
		t:add( f_product_key_cg, bit:_rshift(buf(4,1):uint(), 4))
		t:add( f_product_key_var, bit:_and(buf(4,1):uint(), 0x0F))
		t:add( f_product_key_pkey, buf(5, 16))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0086, CCP_PAR_PRODUCT_KEY)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0086]  = {
						["dis"] = ccp_table:get_dissector(0x0086),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  PVRMSK download Opcode Parser

--]]

	local CCP_PAR_PVRMSK_DOWNLOAD = Proto("CCP_PAR_PVRMSK_DOWNLOAD", "PvrmskDownload")
	f_pvrmsk_download_opcode = ProtoField.uint8("CCP_PAR_PVRMSK_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_pvrmsk_download_length = ProtoField.uint16("CCP_PAR_PVRMSK_DOWNLOAD.Length", "Length", base.DEC)
	f_pvrmsk_download_compound_generation= ProtoField.string("CCP_PAR_PVRMSK_DOWNLOAD.CG", "CG")
	f_pvrmsk_download_variant= ProtoField.string("CCP_PAR_PVRMSK_DOWNLOAD.Variant", "Variant")
	f_pvrmsk_download_pvrmsk = ProtoField.bytes("CCP_PAR_PVRMSK_DOWNLOAD.Pvrmsk", "Pvrmsk", base.HEX)

	CCP_PAR_PVRMSK_DOWNLOAD.fields = {f_pvrmsk_download_opcode, f_pvrmsk_download_length, f_pvrmsk_download_compound_generation, f_pvrmsk_download_variant, f_pvrmsk_download_pvrmsk}
	function CCP_PAR_PVRMSK_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x87 then
			return false
		end

		local length = buf(1, 2) : uint()
             local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_PVRMSK_DOWNLOAD, buf(0,  3 + length))
		t:add( f_pvrmsk_download_opcode, buf(0, 1))
		t:add( f_pvrmsk_download_length, buf(1, 2))
		t:add( f_pvrmsk_download_compound_generation, bit:_rshift((bit:_and(buf(3, 1):uint(),0xF0)), 4))
		t:add( f_pvrmsk_download_variant, bit:_and(buf(3, 1):uint(), 0x0F))
		t:add( f_pvrmsk_download_pvrmsk, buf(4, 16))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0087, CCP_PAR_PVRMSK_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0087]  = {
						["dis"] = ccp_table:get_dissector(0x0087),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  Product Overwrite opcode

--]]

	local CCP_PAR_PRODUCT_OVERWRITE = Proto("CCP_PAR_PRODUCT_OVERWRITE", "Product Key Overwrite")
	f_po_key_opcode = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.OpCode", "OpCode", base.HEX)
	f_po_key_length = ProtoField.uint16("CCP_PAR_PRODUCT_OVERWRITE.Length", "Length", base.DEC)
	--3,1 0 4
	f_po_compound_generation = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.CompoundGeneration", "Compound Generation", base.HEX, nil, 0xf0)
	--3,1 4,4
	f_po_variant = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.Variant", "Variant", base.HEX, nil, 0x0f)
	--4,2
	f_po_product = ProtoField.uint16("CCP_PAR_PRODUCT_OVERWRITE.Product", "Product", base.HEX)
	--6,1
	f_po_cwdk_version = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.CWDKVersion", "CWDK Version", base.HEX)
	--7,16
	f_po_cwdk = ProtoField.bytes("CCP_PAR_PRODUCT_OVERWRITE.CWDK", "CWDK")
	--23,512
	f_po_entitlement_vector = ProtoField.bytes("CCP_PAR_PRODUCT_OVERWRITE.EntitlementVector", "Entitlement Vector", base.HEX)
	--535,1 0,5
	f_po_pk_index = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.PKIndex", "PKey Index", base.DEC, nil, 0xf8)
	--535,1, 2,3
	f_po_reserved = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.reserved", "Reserved", base.HEX, nil, 0x06)
	--535,1 7,1
	f_po_pk_hash = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.PKHash", "PK Hash", base.DEC, nil, 0x01)
	--536,16
	f_po_product_key = ProtoField.bytes("CCP_PAR_PRODUCT_OVERWRITE.ProductKey","PKey Prime", base.HEX)
	--552 + which,1 4,4
	f_po_sream_reserved = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.s_reserved", "Reserved", base.HEX, nil, 0xc0)
	f_po_evkd_expand_mode = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.s_evkdmode", "EVKD Expand mode", base.HEX, {[0]='3DES SOC/Silcion ID', [1]='AES SOC'}, 0x30)
	f_po_stream_generation = ProtoField.uint8("CCP_PAR_PRODUCT_OVERWRITE.StreamGeneration", "Stream Generation", base.HEX, nil, 0x0f)

	CCP_PAR_PRODUCT_OVERWRITE.fields = {f_po_key_opcode, f_po_key_length, f_po_compound_generation, f_po_variant, f_po_reserved, f_po_sream_reserved,f_po_evkd_expand_mode, f_po_product, f_po_cwdk_version, f_po_cwdk, f_po_entitlement_vector, f_po_pk_index, f_po_pk_hash, f_po_product_key, f_po_stream_generation}
	function CCP_PAR_PRODUCT_OVERWRITE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x88 then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_PRODUCT_OVERWRITE, buf(0,  3 + length))
		t:add( f_po_key_opcode, buf(0, 1))
		t:add( f_po_key_length, buf(1, 2))
		t:add( f_po_compound_generation, buf(3, 1))
		t:add( f_po_variant, buf(3,1))
		t:add( f_po_product, buf(4, 2))
		t:add( f_po_cwdk_version, buf(6, 1))
		t:add( f_po_cwdk, buf(7, 16))
		t:add( f_po_entitlement_vector, buf(23, 512))
		t:add( f_po_pk_index, buf(535, 1))
		t:add( f_po_reserved, buf(535, 1))
		t:add( f_po_pk_hash, buf(535, 1))
		t:add( f_po_product_key, buf(536, 16))
		t:add( f_po_sream_reserved, buf(552, 1))
		t:add( f_po_evkd_expand_mode, buf(552, 1))
		t:add( f_po_stream_generation, buf(552, 1))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0088, CCP_PAR_PRODUCT_OVERWRITE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0088] = {
						["dis"] = ccp_table:get_dissector(0x0088),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}

--[[

	IUC  :  Clear product Opcode Parser

--]]

	local CCP_PAR_CLEAR_PRODUCT = Proto("CCP_PAR_CLEAR_PRODUCT", "ClearProduct")
	f_clear_product_opcode = ProtoField.uint8("CCP_PAR_CLEAR_PRODUCT.Opcode", "Opcode", base.HEX)
	f_clear_product_length = ProtoField.uint16("CCP_PAR_CLEAR_PRODUCT.Length", "Length", base.DEC)
	f_clear_product_product_id = ProtoField.bytes("CCP_PAR_CLEAR_PRODUCT.ProductId", "ProductId")

	CCP_PAR_CLEAR_PRODUCT.fields = {f_clear_product_opcode, f_clear_product_length, f_clear_product_product_id}

	function CCP_PAR_CLEAR_PRODUCT.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x89 then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		local data_type = buf(3,1):uint()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_CLEAR_PRODUCT, buf(0,  3 + length))
		t:add(f_clear_product_opcode, buf(0, 1))
		t:add(f_clear_product_length, buf(1, 2))
		local index = 3
		while index + 2 <= buf_len do
			t:add(f_clear_product_product_id, buf(index, 2))
			index = index + 2
		end

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end

	ccp_table:add(0x0089, CCP_PAR_CLEAR_PRODUCT)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0089] = {
						["dis"] = ccp_table:get_dissector(0x0089),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  Nationality Opcode Parser

--]]

	local CCP_PAR_NATIONALITY = Proto("CCP_PAR_NATIONALITY", "Nationality")
	f_nationality_opcode = ProtoField.uint8("CCP_PAR_NATIONALITY.Opcode", "Opcode", base.HEX)
	f_nationality_length = ProtoField.uint16("CCP_PAR_NATIONALITY.Length", "Length", base.DEC)
	f_nationality = ProtoField.bytes("CCP_PAR_NATIONALITY.Nationality", "Nationality", base.HEX)

	CCP_PAR_NATIONALITY.fields = {f_nationality_opcode, f_nationality_length, f_nationality}

	function CCP_PAR_NATIONALITY.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x97 then
			return false
		end

		local length = buf(1,2) : uint()
		local nationality = buf(3,3)
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_NATIONALITY, buf(0,  3 + length))
		t:add(f_nationality_opcode, opcode)
		t:add(f_nationality_length, length)
		t:add(f_nationality, nationality)

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end

	ccp_table:add(0x0097, CCP_PAR_NATIONALITY)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0097] = {
						["dis"] = ccp_table:get_dissector(0x0097),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

	IUC  :  Application Data Opcode Parser

--]]
	local CCP_PAR_APPLICATION_DATA = Proto("CCP_PAR_APPLICATION_DATA", "Application Data")
	f_application_data_opcode = ProtoField.uint8("CCP_PAR_APPLICATION_DATA.Opcode", "Opcode", base.HEX)
	f_application_data_length = ProtoField.uint16("CCP_PAR_APPLICATION_DATA.Length", "Length", base.DEC)
	f_application_data_type = ProtoField.string("CCP_PAR_APPLICATION_DATA.Type", "Type")
	f_application_data = ProtoField.bytes("CCP_PAR_APPLICATION_DATA.Data", "Application Data", base.HEX)

	CCP_PAR_APPLICATION_DATA.fields = {f_application_data_opcode, f_application_data_length, f_application_data_type, f_application_data}

	function CCP_PAR_APPLICATION_DATA.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x8c then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		local data_type = buf(3,1):uint()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_APPLICATION_DATA, buf(0,  3 + length))
		t:add(f_application_data_opcode, opcode)
		t:add(f_application_data_length, length)
		t:add(f_application_data_type, data_type)
		if data_type == 0x00 then --IRD EMM Data
			local parser = msp_table:get_dissector(0xFFFF)
			parser:call(buf(4, buf_len-4):tvb(), pkt, t)
		else
			t:add(f_application_data, buf(4, buf_len - 4))
		end

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end

	ccp_table:add(0x008c, CCP_PAR_APPLICATION_DATA)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x008c] = {
						["dis"] = ccp_table:get_dissector(0x008c),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}


--[[

	IUC  :	VOD Product Overwrite Opcode Parser  

--]]
	
	local CCP_PAR_VOD_PRODUCT_OVERWRITE = Proto("CCP_PAR_VOD_PRODUCT_OVERWRITE", "VOD Product Overwrite")
	f_vod_prod_overwrite_opcode = ProtoField.uint8("CCP_PAR_VOD_PRODUCT_OVERWRITE.Opcode", "Opcode", base.HEX)
	f_vod_prod_overwrite_length = ProtoField.uint16("CCP_PAR_VOD_PRODUCT_OVERWRITE.Length", "Length", base.DEC)
	f_vod_prod_overwrite_cg = ProtoField.string("CCP_PAR_VOD_PRODUCT_OVERWRITE.cg", "Compound Generation")
	f_vod_prod_overwrite_variant = ProtoField.string("CCP_PAR_VOD_PRODUCT_OVERWRITE.variant", "Variant")
	f_vod_prod_overwrite_prod_id = ProtoField.uint16("CCP_PAR_VOD_PRODUCT_OVERWRITE.prod_id", "Product Id", base.DEC)
	f_vod_prod_overwrite_cwdk_version = ProtoField.uint8("CCP_PAR_VOD_PRODUCT_OVERWRITE.cwdk_version", "CWDK Version", base.DEC)
	f_vod_prod_overwrite_cwdk = ProtoField.bytes("CCP_PAR_VOD_PRODUCT_OVERWRITE.cwdk", "CWDK", base.HEX)
	f_vod_prod_overwrite_vod_nonce_length = ProtoField.uint8("CCP_PAR_VOD_PRODUCT_OVERWRITE.vod_nonce_length" , "VOD Nonce Length",base.DEC) --must be 0x10
	f_vod_prod_overwrite_vod_nonce = ProtoField.bytes("CCP_PAR_VOD_PRODUCT_OVERWRITE.vod_nonce", "VOD Nonce", base.HEX)
	f_vod_prod_overwrite_pk_index = ProtoField.string("CCP_PAR_VOD_PRODUCT_OVERWRITE.pk_index", "Product Key Index", base.DEC)
	f_vod_prod_overwrite_reserved = ProtoField.string("CCP_PAR_VOD_PRODUCT_OVERWRITE.reserved", "Reserved")
	f_vod_prod_overwrite_u_prime = ProtoField.bytes("CCP_PAR_VOD_PRODUCT_OVERWRITE.u_prime", "U Prime", base.HEX)
	f_vod_prod_overwrite_sg = ProtoField.string("CCP_PAR_VOD_PRODUCT_OVERWRITE.sg", "Stream Generation", base.DEC)


	CCP_PAR_VOD_PRODUCT_OVERWRITE.fields = {f_vod_prod_overwrite_opcode, f_vod_prod_overwrite_length, f_vod_prod_overwrite_cg, f_vod_prod_overwrite_variant,
											f_vod_prod_overwrite_prod_id, f_vod_prod_overwrite_cwdk_version, f_vod_prod_overwrite_cwdk, f_vod_prod_overwrite_vod_nonce_length,
											f_vod_prod_overwrite_vod_nonce, f_vod_prod_overwrite_pk_index, f_vod_prod_overwrite_reserved, f_vod_prod_overwrite_u_prime,
											f_vod_prod_overwrite_sg}

	function CCP_PAR_VOD_PRODUCT_OVERWRITE.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x90 then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_VOD_PRODUCT_OVERWRITE, buf(0,  3 + length))
		t:add(f_vod_prod_overwrite_opcode, opcode)
		t:add(f_vod_prod_overwrite_length, length)
		t:add(f_vod_prod_overwrite_cg, bit:_rshift(buf(3,1) :uint(), 4))
		t:add(f_vod_prod_overwrite_variant, bit:_and(buf(3,1):uint(), 0x0f))
		t:add(f_vod_prod_overwrite_prod_id, buf(4,2))
		t:add(f_vod_prod_overwrite_cwdk_version, buf(6,1))
		t:add(f_vod_prod_overwrite_cwdk, buf(7,16))
		t:add(f_vod_prod_overwrite_vod_nonce_length, buf(23,1))
		t:add(f_vod_prod_overwrite_vod_nonce, buf(24,16))
		t:add(f_vod_prod_overwrite_pk_index, bit:_rshift(buf(40,1):uint(),3))
		t:add(f_vod_prod_overwrite_reserved, bit:_and(buf(40,1):uint(), 0x07))
		t:add(f_vod_prod_overwrite_u_prime, buf(41, 16))
		t:add(f_vod_prod_overwrite_sg, bit:_rshift(buf(57,1):uint(),4))
		t:add(f_vod_prod_overwrite_reserved, bit:_and(buf(57,1):uint(), 0x0f))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

	end

	ccp_table:add(0x0090, CCP_PAR_VOD_PRODUCT_OVERWRITE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0090] = {
						["dis"] = ccp_table:get_dissector(0x0090),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}


--[[
	
	IUC  :  VOD Asset ID Opcode Parser
	
--]]
	
	local CCP_PAR_VOD_ASSET_ID = Proto("CCP_PAR_VOD_ASSET_ID", "VOD Asset Id")
	f_vod_asset_id_opcode = ProtoField.uint8("CCP_PAR_VOD_ASSET_ID.opcode", "Opcode", base.HEX)
	f_vod_asset_id_length = ProtoField.uint16("CCP_PAR_VOD_ASSET_ID.length", "Length", base.DEC)
	f_vod_asset_id_asset_id = ProtoField.bytes("CCP_PAR_VOD_ASSET_ID.asset_id", "Asset ID", base.HEX)

	CCP_PAR_VOD_ASSET_ID.fields = {f_vod_asset_id_opcode, f_vod_asset_id_length, f_vod_asset_id_asset_id}

	function CCP_PAR_VOD_ASSET_ID.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x96 then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_VOD_ASSET_ID, buf(0,  3 + length))
		t:add(f_vod_asset_id_opcode, opcode)
		t:add(f_vod_asset_id_length, length)
		t:add(f_vod_asset_id_asset_id, buf(3,4))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

	end

	ccp_table:add(0x0096, CCP_PAR_VOD_ASSET_ID)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0096] = {
						["dis"] = ccp_table:get_dissector(0x0096),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[

	IUC  :  Advertisement EMM Opcode

--]]

	local CCP_PAR_ADVERTISEMENT_EMM = Proto("CCP_PAR_ADVERTISEMENT_EMM", "Advertisement EMM")
	f_ad_opcode = ProtoField.uint8("CCP_PAR_ADVERTISEMENT_EMM.OpCode", "OpCode", base.HEX)
	f_ad_length = ProtoField.uint16("CCP_PAR_ADVERTISEMENT_EMM.Length", "Length", base.DEC)
	--3,4
	f_ad_change_version = ProtoField.bytes("CCP_PAR_ADVERTISEMENT_EMM.ChangeVersion", "ChangeVersion")
	--7,1 0,5
	f_ad_rfu = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.Rfu", "Rfu")
	--7,1 6,1
	f_ad_cleanup_operation = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.CleanupOperation", "CleanupOperation")
	--7,1 7,1
	f_ad_action_on_failure = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.ActionOnFailure", "ActionOnFailure")
	--8,1
	f_ad_tms_expression_length = ProtoField.uint8("CCP_PAR_ADVERTISEMENT_EMM.TmsExpressionLength", "TmsExpressionLength", base.DEC)
	--9,M
	f_ad_tms_expression = ProtoField.bytes("CCP_PAR_ADVERTISEMENT_EMM.TmsExpression", "TmsExpression")
	--9+M,1 0,4
	f_ad_major = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.Major", "Major")
	--9+M,1 5,7
	f_ad_minor = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.Minor", "Minor")
	--10+M,1
	f_ad_build = ProtoField.uint8("CCP_PAR_ADVERTISEMENT_EMM.Build", "Build", base.HEX)
	--11+M,1 0,4
	f_ad_cg = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.Cg", "Cg")
	--11+M,1 5,7
	f_ad_sg = ProtoField.string("CCP_PAR_ADVERTISEMENT_EMM.Sg", "Sg")
	--12+M,1
	f_ad_sectors = ProtoField.uint8("CCP_PAR_ADVERTISEMENT_EMM.Sectors", "Sectors", base.DEC)
	--13+M,v
	f_ad_descriptors = ProtoField.bytes("CCP_PAR_ADVERTISEMENT_EMM.Descriptors", "Descriptors")

	CCP_PAR_ADVERTISEMENT_EMM.fields = {f_ad_opcode, f_ad_length, f_ad_change_version, f_ad_rfu,
	f_ad_cleanup_operation, f_ad_action_on_failure, f_ad_tms_expression_length, f_ad_tms_expression, f_ad_major, f_ad_minor, f_ad_build, f_ad_cg, f_ad_sg, f_ad_sectors, f_ad_descriptors}
	function CCP_PAR_ADVERTISEMENT_EMM.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x9a then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_ADVERTISEMENT_EMM, buf(0,  3 + length))
		t:add( f_ad_opcode, buf(0, 1))
		t:add( f_ad_length, buf(1, 2))
		t:add( f_ad_change_version, buf(3, 4))
		t:add( f_ad_rfu, bit:_and(bit:_rshift(buf(7, 1):uint(),2),0x3F))
		t:add( f_ad_cleanup_operation, bit:_and(bit:_rshift(buf(7, 1):uint(),1),0x01))
		t:add( f_ad_action_on_failure, bit:_and(buf(7, 1):uint(),0x01))
		t:add( f_ad_tms_expression_length, buf(8, 1))
		local M = buf (8,1):uint()
		t:add( f_ad_tms_expression, buf(9, M))
		t:add( f_ad_major, bit:_rshift(buf(9+M, 1):uint(), 4))
		t:add( f_ad_minor, bit:_and(buf(9+M, 1):uint(), 0x0F))
		t:add( f_ad_build, buf(10+M, 1))
		t:add( f_ad_cg, bit:_rshift(buf(11+M, 1):uint(), 4))
		t:add( f_ad_sg, bit:_and(buf(11+M, 1):uint(), 0x0F))
		t:add( f_ad_sectors, buf(12+M, 1))
		t:add( f_ad_descriptors, buf(13+M, length-10-M))
		
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end
		
		return true
    end
	ccp_table:add(0x009a, CCP_PAR_ADVERTISEMENT_EMM)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x009a] = {
						["dis"] = ccp_table:get_dissector(0x009a),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}	
	
	--[[

	IUC  :  Block Download EMM Opcode

--]]

	local CCP_PAR_BLOCK_DOWNLOAD_EMM = Proto("CCP_PAR_BLOCK_DOWNLOAD_EMM", "Block Download EMM")
	f_block_download_opcode = ProtoField.uint8("CCP_PAR_BLOCK_DOWNLOAD_EMM.Opcode", "OpCode", base.HEX)
	f_block_download_length = ProtoField.uint16("CCP_PAR_BLOCK_DOWNLOAD_EMM.Length", "Length", base.DEC)
	--3,4
	f_block_download_ptid = ProtoField.bytes("CCP_PAR_BLOCK_DOWNLOAD_EMM.Ptid", "Ptid")
	--7,1 0,5
	f_block_download_block_number = ProtoField.uint16("CCP_PAR_BLOCK_DOWNLOAD_EMM.BlockNumber", "BlockNumber", base.DEC)
	--7,1 6,1
	f_block_download_data = ProtoField.bytes("CCP_PAR_BLOCK_DOWNLOAD_EMM.Data", "Data")
	
	CCP_PAR_BLOCK_DOWNLOAD_EMM.fields = {f_block_download_opcode, f_block_download_length, f_block_download_ptid, f_block_download_block_number, f_block_download_data}
	function CCP_PAR_BLOCK_DOWNLOAD_EMM.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x9b then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_BLOCK_DOWNLOAD_EMM, buf(0,  3 + length))
		t:add( f_block_download_opcode, buf(0, 1))
		t:add( f_block_download_length, buf(1, 2))
		t:add( f_block_download_ptid, buf(3, 2))
		t:add( f_block_download_block_number, buf(5, 2))
		t:add( f_block_download_data, buf(7, length - 4))
				
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end
		
		return true
    end
	ccp_table:add(0x009b, CCP_PAR_BLOCK_DOWNLOAD_EMM)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x009b] = {
						["dis"] = ccp_table:get_dissector(0x009b),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}	
		
	--[[

	IUC  :  IFCP Image Advertisement EMM Opcode

--]]

	local CCP_PAR_IFCP_ADVERTISEMENT_EMM = Proto("CCP_PAR_IFCP_ADVERTISEMENT_EMM", "IFCP Advertisement EMM")
	f_ifcp_ad_opcode = ProtoField.uint8("CCP_PAR_IFCP_ADVERTISEMENT_EMM.OpCode", "OpCode", base.HEX)
	f_ifcp_ad_length = ProtoField.uint16("CCP_PAR_IFCP_ADVERTISEMENT_EMM.Length", "Length", base.DEC)
	--3, 8
	f_ifcp_ad_stream_descriptor = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptor", "Emm Stream Descriptor")
	f_ifcp_ad_stream_descriptor_tag = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptorTag", "Descriptor Tag")
	f_ifcp_ad_stream_descriptor_length = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptorLength", "Descriptor Length")
	f_ifcp_ad_stream_descriptor_emm_filter = ProtoField.uint8("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptorEmmFilter", "Descriptor EMM Filter", base.HEX, nil, 0xF8)
	f_ifcp_ad_stream_descriptor_emm_address_length = ProtoField.uint8("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptorEmmAddressLength", "Descriptor EMM Address Length", base.HEX, nil, 0x07)
	f_ifcp_ad_stream_descriptor_emm_address = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.EmmStreamDescriptorEmmAddree", "Descriptor EMM Address")
	--11, n * 11
	f_ifcp_package_descriptor = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptor", "Package Stream Descriptor")
	f_ifcp_package_descriptor_tag = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorTag", "Descriptor Tag")
	f_ifcp_package_descriptor_length = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorLength", "Descriptor Length")
	f_ifcp_package_descriptor_ptid = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorPtid", "PTID")
	f_ifcp_package_descriptor_nr_of_blocks = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorNrOfBlock", "Nr Of Block")
	f_ifcp_package_descriptor_rfu = ProtoField.uint8("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorRfu", "RFU", base.HEX, nil, 0xF0)
	f_ifcp_package_descriptor_block_size = ProtoField.uint8("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorBlockSize", "Block Size", base.HEX, nil, 0x0F)
	f_ifcp_package_descriptor_check_sum = ProtoField.bytes("CCP_PAR_IFCP_ADVERTISEMENT_EMM.PackageStreamDescriptorCheckSum", "Check Sum")
	

	CCP_PAR_IFCP_ADVERTISEMENT_EMM.fields = {f_ifcp_ad_opcode, f_ifcp_ad_length, f_ifcp_ad_stream_descriptor, f_ifcp_ad_stream_descriptor_tag, f_ifcp_ad_stream_descriptor_length,
											f_ifcp_ad_stream_descriptor_emm_filter, f_ifcp_ad_stream_descriptor_emm_address_length, f_ifcp_ad_stream_descriptor_emm_address, f_ifcp_package_descriptor,
											f_ifcp_package_descriptor_tag, f_ifcp_package_descriptor_length, f_ifcp_package_descriptor_ptid, f_ifcp_package_descriptor_nr_of_blocks, f_ifcp_package_descriptor_rfu,
											f_ifcp_package_descriptor_block_size, f_ifcp_package_descriptor_check_sum}
	
	function CCP_PAR_IFCP_ADVERTISEMENT_EMM.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xae then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_IFCP_ADVERTISEMENT_EMM, buf(0,  3 + length))
		t:add( f_ifcp_ad_opcode, buf(0, 1))
		t:add( f_ifcp_ad_length, buf(1, 2))
		
		-- EMM stream descriptor
		st = t:add( f_ifcp_ad_stream_descriptor, buf(3, 8))
		st:add( f_ifcp_ad_stream_descriptor_tag, buf(3, 1))
		st:add( f_ifcp_ad_stream_descriptor_length, buf(4, 1))
		st:add( f_ifcp_ad_stream_descriptor_emm_filter, buf(5, 1))
		st:add( f_ifcp_ad_stream_descriptor_emm_address_length, buf(5, 1))
		st:add( f_ifcp_ad_stream_descriptor_emm_address, buf(6, 5))
		
		for i = 0, ((length - 8) / 11  - 1) do
			st = t:add( f_ifcp_package_descriptor, buf(11, length-8))
			st:add( f_ifcp_package_descriptor_tag, buf(11, 1))
			st:add( f_ifcp_package_descriptor_length, buf(12, 1))
			st:add( f_ifcp_package_descriptor_ptid, buf(13, 2))
			st:add( f_ifcp_package_descriptor_nr_of_blocks, buf(15, 2))
			st:add( f_ifcp_package_descriptor_rfu, buf(16, 1))
			st:add( f_ifcp_package_descriptor_block_size, buf(16, 1))
			st:add( f_ifcp_package_descriptor_check_sum, buf(17, 4))
		end
				
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end
		
		return true
    end
	ccp_table:add(0x00ae, CCP_PAR_IFCP_ADVERTISEMENT_EMM)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00ae] = {
						["dis"] = ccp_table:get_dissector(0x00ae),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}	
		
	--[[

	IUC  :  IFCP Image Download EMM Opcode

--]]

	local CCP_PAR_IFCP_DOWNLOAD_EMM = Proto("CCP_PAR_IFCP_DOWNLOAD_EMM", "IFCP Download EMM")
	f_ifcp_download_opcode = ProtoField.uint8("CCP_PAR_IFCP_DOWNLOAD_EMM.OpCode", "OpCode", base.HEX)
	f_ifcp_download_length = ProtoField.uint16("CCP_PAR_IFCP_DOWNLOAD_EMM.Length", "Length", base.DEC)
	--3, 2
	f_ifcp_download_version = ProtoField.bytes("CCP_PAR_IFCP_DOWNLOAD_EMM.Version", "Version")
	--5, 2
	f_ifcp_download_ptid = ProtoField.bytes("CCP_PAR_IFCP_DOWNLOAD_EMM.Ptid", "PTID")
	--7, 48
	f_ifcp_download_am = ProtoField.bytes("CCP_PAR_IFCP_DOWNLOAD_EMM.ActivionMessage", "Activion Message")

	CCP_PAR_IFCP_DOWNLOAD_EMM.fields = {f_ifcp_download_opcode, f_ifcp_download_length, f_ifcp_download_version, f_ifcp_download_ptid, f_ifcp_download_am}
	
	function CCP_PAR_IFCP_DOWNLOAD_EMM.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xaf then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_IFCP_DOWNLOAD_EMM, buf(0,  3 + length))
		t:add( f_ifcp_download_opcode, buf(0, 1))
		t:add( f_ifcp_download_length, buf(1, 2))
		t:add( f_ifcp_download_version, buf(3, 2))
		t:add( f_ifcp_download_ptid, buf(5, 2))
		t:add( f_ifcp_download_am, buf(7, 48))
		
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end
		
		return true
    end
	ccp_table:add(0x00af, CCP_PAR_IFCP_DOWNLOAD_EMM)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00af] = {
						["dis"] = ccp_table:get_dissector(0x00af),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
		}	
		
	--[[
	
	IUC  :  Secure PVRMSK download Opcode Parser
	
--]]
	
	local CCP_PAR_SECURE_PVRMSK_DOWNLOAD = Proto("CCP_PAR_SECURE_PVRMSK_DOWNLOAD", "Secure PVRMSK download")
	f_secure_pvrmsk_download_opcode = ProtoField.uint8("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_secure_pvrmsk_download_length = ProtoField.uint16("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.length", "Length", base.DEC)
	f_secure_pvrmsk_download_key_cipher_mode = ProtoField.string("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.key_cipher_mode", "Key cipher mode")
    f_secure_pvrmsk_download_reserved1 = ProtoField.string("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.reserved1", "Reserved1")
	f_secure_pvrmsk_download_reserved2 = ProtoField.bytes("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.reserved2", "Reserved2", base.HEX)
	f_secure_pvrmsk_download_pvrmsk = ProtoField.bytes("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.pvrmsk", "Pvrmsk encrypted by cpsk", base.HEX)
	f_secure_pvrmsk_download_cpsk = ProtoField.bytes("CCP_PAR_SECURE_PVRMSK_DOWNLOAD.cpsk", "Cpsk encrypted by pvr aes xsmk", base.HEX)
	
	CCP_PAR_SECURE_PVRMSK_DOWNLOAD.fields = {f_secure_pvrmsk_download_opcode, f_secure_pvrmsk_download_length, f_secure_pvrmsk_download_key_cipher_mode, f_secure_pvrmsk_download_reserved1, f_secure_pvrmsk_download_reserved2, f_secure_pvrmsk_download_pvrmsk, f_secure_pvrmsk_download_cpsk}

	function CCP_PAR_SECURE_PVRMSK_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0x9d then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_SECURE_PVRMSK_DOWNLOAD, buf(0,  3 + length))
		t:add(f_secure_pvrmsk_download_opcode, opcode)
		t:add(f_secure_pvrmsk_download_length, length)
		t:add(f_secure_pvrmsk_download_key_cipher_mode, bit:_rshift(buf(3,1) :uint(), 7))
		t:add(f_secure_pvrmsk_download_reserved1, bit:_and(buf(3,1):uint(), 0x7f))
		t:add(f_secure_pvrmsk_download_reserved2, buf(4,2))
		t:add(f_secure_pvrmsk_download_pvrmsk, buf(6,16))
		t:add(f_secure_pvrmsk_download_cpsk, buf(22,16))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

	end

	ccp_table:add(0x009d, CCP_PAR_SECURE_PVRMSK_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x009d] = {
						["dis"] = ccp_table:get_dissector(0x009d),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

	IUC  :  Shared PVRMSK Opcode Parser
	
--]]
	
	local CCP_PAR_SHARED_PVRMSK = Proto("CCP_PAR_SHARED_PVRMSK", "Shared PVRMSK")
	local CCP_PAR_SHARED_PVRMSK_FOR_EACH_CLIENT = Proto("CCP_PAR_SHARED_PVRMSK_FOR_EACH_CLIENT", "Shared PVRMSK for each client")
	f_shared_pvrmsk_opcode = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.opcode", "Opcode", base.HEX)
	f_shared_pvrmsk_length = ProtoField.uint16("CCP_PAR_SHARED_PVRMSK.length", "Length", base.DEC)
	f_shared_pvrmsk_client_type = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.client_type", "Client type", base.HEX, {[0]='SoC',[1]='Silicon ID',[2]='IAC'}, 0xc0)
    f_shared_pvrmsk_rfu = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.rfu", "RFU", base.HEX, nil, 0x3f)
	f_shared_pvrmsk_device_domain_id = ProtoField.uint32("CCP_PAR_SHARED_PVRMSK.device_domain_id", "Device domain id", base.HEX)
	f_shared_pvrmsk_unique_session_key_identifier = ProtoField.uint16("CCP_PAR_SHARED_PVRMSK.session_key_identifier", "Session key identifier", base.HEX)
	f_shared_pvrmsk_cpsk = ProtoField.bytes("CCP_PAR_SHARED_PVRMSK.cpsk", "CPSK", base.HEX)
	f_shared_pvrmsk_number_of_pvrmsk = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.number_of_pvrmsk", "Nubmer of PVRMSK", base.DEC)
	f_shared_pvrmsk_id_type = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.pvrmsk_id_type", "PVRMSK Id Type", base.HEX, nil, 0xc0)
	f_shared_pvrmsk_rfu2 = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.pvrmsk_rfu", "PVRMSK RFU", base.HEX, nil, 0x3f)
	f_shared_pvrmsk_device_identifier = ProtoField.uint32("CCP_PAR_SHARED_PVRMSK.pvrmsk_device_identifier", "PVRMSK Device identifier", base.DEC)
	f_shared_pvrmsk_key_cipher_mode = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.pvrmsk_key_cipher_mode", "PVRMSK Key_cipher_mode", base.HEX, nil, 0x80)
	f_shared_pvrmsk_reserved = ProtoField.uint8("CCP_PAR_SHARED_PVRMSK.pvrmsk_reserved", "PVRMSK Reserved", base.HEX, nil, 0x7f)
	f_shared_pvrmsk_pvrmsk = ProtoField.bytes("CCP_PAR_SHARED_PVRMSK.pvrmsk_pvrmsk", "PVRMSK PVRMSK", base.HEX)
	
	CCP_PAR_SHARED_PVRMSK.fields = {f_shared_pvrmsk_opcode, f_shared_pvrmsk_length, f_shared_pvrmsk_client_type, f_shared_pvrmsk_rfu, f_shared_pvrmsk_device_domain_id, f_shared_pvrmsk_unique_session_key_identifier, f_shared_pvrmsk_cpsk, f_shared_pvrmsk_number_of_pvrmsk, f_shared_pvrmsk_id_type, f_shared_pvrmsk_rfu2, f_shared_pvrmsk_device_identifier, f_shared_pvrmsk_reserved, f_shared_pvrmsk_key_cipher_mode, f_shared_pvrmsk_pvrmsk}

	function CCP_PAR_SHARED_PVRMSK.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if opcode ~=0xa3 then
			return false
		end

		local length = buf(1,2) : uint()
		local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t= root:add(CCP_PAR_SHARED_PVRMSK, buf(0,  3 + length))
		t:add(f_shared_pvrmsk_opcode, opcode)
		t:add(f_shared_pvrmsk_length, length)
		t:add(f_shared_pvrmsk_client_type, buf(3,1))
		t:add(f_shared_pvrmsk_rfu, buf(3,1))
		t:add(f_shared_pvrmsk_device_domain_id, buf(4,4))
		t:add(f_shared_pvrmsk_unique_session_key_identifier, buf(8,2))
		t:add(f_shared_pvrmsk_cpsk, buf(10,16))
		t:add(f_shared_pvrmsk_number_of_pvrmsk, buf(26,1))

		local pvrmsk_nr = (length - 24) / 22
		for i=0, pvrmsk_nr-1 do
			local pt= t:add(CCP_PAR_SHARED_PVRMSK_FOR_EACH_CLIENT, buf(27 + i * 22,  22))
			pt:add(f_shared_pvrmsk_id_type, buf(27 + i * 22 ,1))
			pt:add(f_shared_pvrmsk_rfu2, buf(27 + i * 22 ,1))
			pt:add(f_shared_pvrmsk_device_identifier, buf(28 + i * 22, 4))
			pt:add(f_shared_pvrmsk_key_cipher_mode, buf(32 + i * 22 ,1))
			pt:add(f_shared_pvrmsk_reserved, buf(32 + i * 22, 1))
			pt:add(f_shared_pvrmsk_pvrmsk, buf(33 + i * 22,16))
		end
		
		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

	end

	ccp_table:add(0x00a3, CCP_PAR_SHARED_PVRMSK)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00a3] = {
						["dis"] = ccp_table:get_dissector(0x00a3),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[
	IUC  :  Product Key Update Opcode Parser

--]]

	local CCP_PAR_PRODUCT_KEY_UPDATE = Proto("CCP_PAR_PRODUCT_KEY_UPDATE", "Product key update")
	f_product_key_update_opcode = ProtoField.uint8("CCP_PAR_PRODUCT_KEY_UPDATE.Opcode", "Opcode", base.HEX)
	f_product_key_update_length = ProtoField.uint16("CCP_PAR_PRODUCT_KEY_UPDATE.Length", "Length", base.DEC)
	f_product_key_update_index = ProtoField.uint8("CCP_PAR_PRODUCT_KEY_UPDATE.KeyIndex", "KeyIndex", base.DEC)
	f_product_key_update_cg = ProtoField.string("CCP_PAR_PRODUCT_KEY_UPDATE.CG", "CompoundGeneration")
	f_product_key_update_var = ProtoField.string("CCP_PAR_PRODUCT_KEY_UPDATE.VAR", "Variant")
	f_product_key_update_pkey = ProtoField.bytes("CCP_PAR_PRODUCT_KEY_UPDATE.PKey", "ProductKey")

	CCP_PAR_PRODUCT_KEY_UPDATE.fields = {f_product_key_update_opcode, f_product_key_update_length, f_product_key_update_index, f_product_key_update_cg, f_product_key_update_var, f_product_key_update_pkey, f_product_key_update_product_group_transformation}
	function CCP_PAR_PRODUCT_KEY_UPDATE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x9f then
			return false
		end

		local length = buf(1, 2) : uint()
        local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_PRODUCT_KEY_UPDATE, buf(0,  3 + length))
		t:add( f_product_key_update_opcode, buf(0, 1))
		t:add( f_product_key_update_length, buf(1, 2))
		t:add( f_product_key_update_index, bit:_rshift(buf(3, 1):uint(), 3))
		t:add( f_product_key_update_cg, bit:_rshift(buf(4,1):uint(), 4))
		t:add( f_product_key_update_var, bit:_and(buf(4,1):uint(), 0x0F))
		t:add( f_product_key_update_pkey, buf(5, 16))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x009f, CCP_PAR_PRODUCT_KEY_UPDATE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x009f]  = {
						["dis"] = ccp_table:get_dissector(0x009f),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	IUC  :  Timestamp filter Opcode
	
	--]]

	local CCP_PAR_TIMESTAMP_FILTER = Proto("CCP_PAR_TIMESTAMP_FILTER", "Timestamp Filter")
	--0,1
	f_timestamp_filter_opcode = ProtoField.uint8("CCP_PAR_TIMESTAMP_FILTER.Opcode", "Opcode", base.HEX)
	--1,2
	f_timestamp_filter_length = ProtoField.uint16("CCP_PAR_TIMESTAMP_FILTER.Length", "Length", base.DEC)
	--3,1
	f_timestamp_filter_rfu = ProtoField.uint8("CCP_PAR_TIMESTAMP_FILTER.Rfu", "Rfu", base.DEC)
	--4,4
	f_timestamp_filter_timestamp = ProtoField.bytes("CCP_PAR_TIMESTAMP_FILTER.Timestamp", "Timestamp")

	CCP_PAR_TIMESTAMP_FILTER.fields = {f_timestamp_filter_opcode, f_timestamp_filter_length, f_timestamp_filter_rfu, f_timestamp_filter_timestamp}
	function CCP_PAR_TIMESTAMP_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc1 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_TIMESTAMP_FILTER, buf(0,  3 + length))
		t:add( f_timestamp_filter_opcode, buf(0, 1))
		t:add( f_timestamp_filter_length, buf(1, 2))
		t:add( f_timestamp_filter_rfu, buf(3, 1))
		t:add( f_timestamp_filter_timestamp, buf(4, 4))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c1, CCP_PAR_TIMESTAMP_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c1] = {
						["dis"] = ccp_table:get_dissector(0x00c1),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	
	IUC  :  Life Time Opcode
	
	--]]
	local CCP_PAR_LIFE_TIME = Proto("CCP_PAR_LIFE_TIME", "Life Time")
	f_life_time_opcode = ProtoField.uint8("CCP_PAR_LIFE_TIME.Opcode", "Opcode", base.HEX)
	f_life_time_length = ProtoField.uint16("CCP_PAR_LIFE_TIME.Length", "Length", base.DEC)
	f_life_time_rfu = ProtoField.uint8("CCP_PAR_LIFE_TIME.Rfu", "Rfu", base.DEC)
	f_life_time_starttime = ProtoField.bytes("CCP_PAR_LIFE_TIME.Starttime", "Starttime")
	f_life_time_lifetime = ProtoField.bytes("CCP_PAR_LIFE_TIME.Lifetime", "Lifetime")

	CCP_PAR_LIFE_TIME.fields = {f_life_time_opcode, f_life_time_length, f_life_time_rfu, f_life_time_starttime, f_life_time_lifetime}
	
	function CCP_PAR_LIFE_TIME.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc5 then
			return false
		end

		local length = buf(1, 2) : uint()
             local buf_len = buf:len()
		if buf_len < length + 3 then
			return false
		end

		local t = root:add(CCP_PAR_LIFE_TIME, buf(0,  3 + length))
		t:add( f_life_time_opcode, buf(0, 1))
		t:add( f_life_time_length, buf(1, 2))
		t:add( f_life_time_rfu, buf(3, 1))
		t:add( f_life_time_starttime, buf(4, 4))
		t:add( f_life_time_lifetime, buf(8, 4))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c5, CCP_PAR_LIFE_TIME)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c5] = {
						["dis"] = ccp_table:get_dissector(0x00c5),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[
				
IUC  :  ARP Config Opcode

--]]
	local CCP_PAR_CCA_ARP_CONFIG = Proto("CCP_PAR_CCA_ARP_CONFIG", "CCA ARP Config")
	f_cca_arp_config_opcode = ProtoField.uint8("CCP_PAR_CCA_ARP_CONFIG.opcode", "Opcode", base.HEX)
	f_cca_arp_config_length = ProtoField.uint16("CCP_PAR_CCA_ARP_CONFIG.length", "Length", base.DEC)
	f_cca_arp_config_ciml_ext = ProtoField.uint16("CCP_PAR_CCA_ARP_CONFIG.ciml_ext", "Channel Id Match Limit", base.DEC)
	f_cca_arp_config_reset_arp = ProtoField.uint8("CCP_PAR_CCA_ARP_CONFIG.reset_arp", "Reset ARP", base.DEC, nil, 0x80)
	f_cca_arp_config_rfu = ProtoField.uint8("CCP_PAR_CCA_ARP_CONFIG.rfu", "RFU", base.HEX, nil, 0x70)
	f_cca_arp_config_inactive_time = ProtoField.uint8("CCP_PAR_CCA_ARP_CONFIG.inactive_time", "Inactive Time", base.DEC, nil, 0x0f)
	
	CCP_PAR_CCA_ARP_CONFIG.fields = {f_cca_arp_config_opcode, f_cca_arp_config_length, f_cca_arp_config_ciml_ext, f_cca_arp_config_reset_arp, f_cca_arp_config_rfu, f_cca_arp_config_inactive_time}
	
	function CCP_PAR_CCA_ARP_CONFIG.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xa2 then
			return false
		end

		local length = buf(1, 2):uint()
        local buf_len = buf:len()
		if buf_len < length + 2 then
			return false
		end			
	
		local t= root:add(CCP_PAR_CCA_ARP_CONFIG, buf(0,  3 + length))
		t:add(f_cca_arp_config_opcode, buf(0,1))
		t:add(f_cca_arp_config_length, buf(1,2))
		t:add(f_cca_arp_config_ciml_ext, buf(3,2))
		t:add(f_cca_arp_config_reset_arp, buf(5,1))
		t:add(f_cca_arp_config_rfu, buf(5,1))
		t:add(f_cca_arp_config_inactive_time, buf(5,1))

		if ( buf_len - 3 - length > 0) then
			local next_buf = buf( 3 + length, buf_len - 3 - length)
			return ccp_table:get_dissector(0x00FF):call( next_buf:tvb(), pkt, root)
		end

		return true			
		
	end
	
	ccp_table:add(0x00a2, CCP_PAR_CCA_ARP_CONFIG)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00a2] = {
						["dis"] = ccp_table:get_dissector(0x00a2),
						["version"] = 2 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
---------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------EMM OPCODES FOR  SMART CARD----------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------	
	
--[[

0x1a	----------						Time Sync Opcode
0xfb	----------						Time Stamp Opcode
0x1d	----------						Time Freshness Opcode
0x62	----------						Nationality Opcode
0x56	----------						Regional Control Opcode
0x11	----------						Product ID Download Opcode
0x05	----------						Surf Lock Config Opcode
0x3b	----------						PVR MSK Opcode
0x1e	----------						CI Layer Configuration Opcode
0xa0	----------						ARP Config Opcode
0x6b	----------						HGPC V6 Card Opcode
0x50	----------						Product Key Overwrite Opcode
0x0f	----------						Chipset Pairing Opcode
0x12	----------						Chipset Unpairing Opcode
0x14	----------						Extended Pairing Opcode	
0x98	----------						Scs Control Opcode
0xbb	----------						PVRMSK Download Opcode
0x13	----------						TWEAK Key Opcode
0x43	----------						Patch Level Update Opcode
0x42	----------						Package Download Opcode
0x41	----------						Package Initiation Opocde
0x15	----------						OVK Download Opcode
0x18    ----------						Update TKc Opcode
0x58	----------						Ippv Debit Limit OpCode
0x59    ----------						IPPV Feedback Phone Number Download Opcode
0x5a	----------						Ippv Feedback Key Download OpCode
0x5b	----------						Ippv Initiate Callback OpCode
0xcb	----------						Group Vector Filter Opcode
0x38    ----------						HGPC Primary Secure Client Activation Opcode
0x39	----------						HGPC Secondary Secure Client Activation Opcode
0x3a	----------						HGPC - Force Renew Opcode

---]]	

--[[

Smart Card : Time Sync Opocde

--]]

	local CCP_PAR_SC_TIME_SYNC = Proto("CCP_PAR_SC_TIME_SYNC", "Time Sync")
	f_time_sync_emm_opcode = ProtoField.uint8("CCP_PAR_SC_TIME_SYNC.opcode", "Opcode", base.HEX)
	f_time_sync_emm_length = ProtoField.uint16("CCP_PAR_SC_TIME_SYNC.length", "Length", base.DEC)
	f_time_sync_emm_time_stamp = ProtoField.bytes("CCP_PAR_SC_TIME_SYNC.time_stamp", "Time Stamp", base.HEX)
	
	CCP_PAR_SC_TIME_SYNC.fields = {f_time_sync_emm_opcode, f_time_sync_emm_length, f_time_sync_emm_time_stamp}
	
	function CCP_PAR_SC_TIME_SYNC.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x1a then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t= root:add(CCP_PAR_SC_TIME_SYNC, buf(0,  2 + length))
		t:add(f_time_sync_emm_opcode, opcode)
		t:add(f_time_sync_emm_length, length)
		t:add(f_time_sync_emm_time_stamp, buf(2,4))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x001a, CCP_PAR_SC_TIME_SYNC)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x001a] = {
						["dis"] = ccp_table:get_dissector(0x001a),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

Smart Card :  Time Filter Opcode

--]]

	local CCP_PAR_SC_TIME_FILTER = Proto("CCP_PAR_SC_TIME_FILTER", "Time Filter")
	f_time_filter_opcode = ProtoField.uint8("CCP_PAR_SC_TIME_FILTER.opcode", "Opcode", base.HEX)
	f_time_filter_length = ProtoField.uint16("CCP_PAR_SC_TIME_FILTER.length", "Length", base.DEC)
	f_time_filter_time_stamp = ProtoField.bytes("CCP_PAR_SC_TIME_FILTER.time_stamp", "Time Stamp", base.HEX)
	f_time_filter_duration = ProtoField.uint8("CCP_PAR_SC_TIME_FILTER.duration", "Duration", base.DEC)
	
	CCP_PAR_SC_TIME_FILTER.fields = {f_time_filter_opcode, f_time_filter_length, f_time_filter_time_stamp, f_time_filter_duration}
	
	function CCP_PAR_SC_TIME_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xfb then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	
	
		local t= root:add(CCP_PAR_SC_TIME_FILTER, buf(0,  2 + length))
		t:add(f_time_filter_opcode, opcode)
		t:add(f_time_filter_length, length)
		t:add(f_time_filter_time_stamp, buf(2,4))
		t:add(f_time_filter_duration, buf(6,1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	
	end
	
	ccp_table:add(0x00fb, CCP_PAR_SC_TIME_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00fb] = {
						["dis"] = ccp_table:get_dissector(0x00fb),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	

	
--[[

Smart Card : Time Freshness Opcode

--]]	

	local CCP_PAR_SC_TIME_FRESHNESS = Proto("CCP_PAR_SC_TIME_FRESHNESS", "Time Freshness")
	f_time_freshness_opcode = ProtoField.uint8("CCP_PAR_SC_TIME_FRESHNESS.opcode", "Opcode", base.HEX)
	f_time_freshness_length = ProtoField.uint16("CCP_PAR_SC_TIME_FRESHNESS.length", "Length", base.DEC)
	f_time_freshness_ts_freshness_window = ProtoField.bytes("CCP_PAR_SC_TIME_FRESHNESS.ts_freshness_window", "Time Stamp Freshness Window", base.HEX)
	
	CCP_PAR_SC_TIME_FRESHNESS.fields = {f_time_freshness_opcode, f_time_freshness_length, f_time_freshness_ts_freshness_window}
	
	function CCP_PAR_SC_TIME_FRESHNESS.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x1d then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
	
		local t= root:add(CCP_PAR_SC_TIME_FRESHNESS, buf(0,  2 + length))
		t:add(f_time_freshness_opcode, opcode)
		t:add(f_time_freshness_length, length)
		t:add(f_time_freshness_ts_freshness_window, buf(2,2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true		
	end
	
	ccp_table:add(0x001d, CCP_PAR_SC_TIME_FRESHNESS)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x001d] = {
						["dis"] = ccp_table:get_dissector(0x001d),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		
	
--[[

Smart Card :  Nationality Download Opocde

--]]	

	local CCP_PAR_SC_NATIONALITY_DOWNLOAD = Proto("CCP_PAR_SC_NATIONALITY_DOWNLOAD", "Nationality Download")
	f_nationality_sc_opcode = ProtoField.uint8("CCP_PAR_SC_NATIONALITY_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_nationality_sc_length = ProtoField.uint16("CCP_PAR_SC_NATIONALITY_DOWNLOAD.length", "Length", base.DEC)
	f_nationality_sc_nationality = ProtoField.bytes("CCP_PAR_SC_NATIONALITY_DOWNLOAD.nationality", "Nationality", base.HEX)
	
	CCP_PAR_SC_NATIONALITY_DOWNLOAD.fields = {f_nationality_sc_opcode, f_nationality_sc_length, f_nationality_sc_nationality}
	
	function CCP_PAR_SC_NATIONALITY_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x62 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_NATIONALITY_DOWNLOAD, buf(0,  2 + length))
		t:add(f_nationality_sc_opcode, opcode)
		t:add(f_nationality_sc_length, length)
		t:add(f_nationality_sc_nationality, buf(2,3))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0062, CCP_PAR_SC_NATIONALITY_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0062] = {
						["dis"] = ccp_table:get_dissector(0x0062),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card :  Regional Control Opocde

--]]	

	local CCP_PAR_SC_REGIONAL_CONTROL = Proto("CCP_PAR_SC_REGIONAL_CONTROL", "Regional Control")
	f_region_control_sc_opcode = ProtoField.uint8("CCP_PAR_SC_REGIONAL_CONTROL.opcode", "Opcode", base.HEX)
	f_region_control_sc_length = ProtoField.uint16("CCP_PAR_SC_REGIONAL_CONTROL.length", "Length", base.DEC)
	f_region_control_sc_region = ProtoField.uint8("CCP_PAR_SC_REGIONAL_CONTROL.region", "Region", base.HEX)
	f_region_control_sc_sub_region = ProtoField.uint8("CCP_PAR_SC_REGIONAL_CONTROL.sub_region", "Sub Region", base.HEX)
	
	CCP_PAR_SC_REGIONAL_CONTROL.fields = {f_region_control_sc_opcode, f_region_control_sc_length, f_region_control_sc_region, f_region_control_sc_sub_region}
	
	function CCP_PAR_SC_REGIONAL_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x56 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_REGIONAL_CONTROL, buf(0,  2 + length))
		t:add(f_region_control_sc_opcode, opcode)
		t:add(f_region_control_sc_length, length)
		t:add(f_region_control_sc_region, buf(2,1))
		t:add(f_region_control_sc_sub_region, buf(3,1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0056, CCP_PAR_SC_REGIONAL_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0056] = {
						["dis"] = ccp_table:get_dissector(0x0056),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		
	
--[[

Smart Card :  Product Id Download Opocde

--]]	

	local CCP_PAR_SC_PRODUCT_ID_DOWNLOAD = Proto("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD", "Product Id Download")
	local PRODUCT_INFO = Proto("PRODUCT_INFO", "Product Info")
	f_product_id_download_sc_opcode = ProtoField.uint8("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_product_id_download_sc_length = ProtoField.uint16("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.length", "Length", base.DEC)
	f_product_id_download_sc_product_id = ProtoField.uint16("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.product_id", "Product Id", base.DEC)
	f_product_id_download_sc_start_date = ProtoField.uint16("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.start_date", "Start Date", base.DEC)
	f_product_id_download_sc_duration = ProtoField.uint8("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.duration", "Duration", base.DEC)
	f_product_id_download_sc_status = ProtoField.uint8("CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.status", "Status", base.DEC)
	
	CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.fields = {f_product_id_download_sc_opcode, f_product_id_download_sc_length, f_product_id_download_sc_product_id, f_product_id_download_sc_start_date,
																					f_product_id_download_sc_duration, f_product_id_download_sc_status}
	
	function CCP_PAR_SC_PRODUCT_ID_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x11 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_PRODUCT_ID_DOWNLOAD, buf(0,  2 + length))
		t:add(f_product_id_download_sc_opcode, opcode)
		t:add(f_product_id_download_sc_length, length)
		index = 0
		while index < length do
			local st = t:add(PRODUCT_INFO, buf(2+index, 6))
			st:add(f_product_id_download_sc_product_id, buf(2+index, 2))
			st:add(f_product_id_download_sc_start_date, buf(4+index, 2))
			st:add(f_product_id_download_sc_duration, buf(6+index, 1))
			st:add(f_product_id_download_sc_status, buf(7+index, 1))
			index = index + 6
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0011, CCP_PAR_SC_PRODUCT_ID_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0011] = {
						["dis"] = ccp_table:get_dissector(0x0011),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	

--[[

Smart Card :  Surf Locking Config Opocde

--]]	

	local CCP_PAR_SC_SURF_LOCK_CONFIG = Proto("CCP_PAR_SC_SURF_LOCK_CONFIG", "Surf Locking Config")
	f_surf_locking_config_sc_opcode = ProtoField.uint8("CCP_PAR_SC_SURF_LOCK_CONFIG.opcode", "Opcode", base.HEX)
	f_surf_locking_config_sc_length = ProtoField.uint16("CCP_PAR_SC_SURF_LOCK_CONFIG.length", "Length", base.DEC)
	f_surf_locking_config_sc_cp_min = ProtoField.uint8("CCP_PAR_SC_SURF_LOCK_CONFIG.cp_min", "CP Minimum", base.DEC)
	f_surf_locking_config_sc_rfu = ProtoField.string("CCP_PAR_SC_SURF_LOCK_CONFIG.rfu", "RFU")
	f_surf_locking_config_sc_init_switches = ProtoField.string("CCP_PAR_SC_SURF_LOCK_CONFIG.init_switches", "Initial Switches Number")
	f_surf_locking_config_sc_fsc_inc = ProtoField.uint8("CCP_PAR_SC_SURF_LOCK_CONFIG.fsc_inc", "FSC Increment Counter", base.DEC)
	f_surf_locking_config_sc_fsc_dec = ProtoField.uint8("CCP_PAR_SC_SURF_LOCK_CONFIG.fsc_dec", "FSC Decrement Counter", base.DEC)
	f_surf_locking_config_sc_fsc_max = ProtoField.uint16("CCP_PAR_SC_SURF_LOCK_CONFIG.fsc_max", "Allowed Max FSC", base.DEC)
	f_surf_locking_config_sc_rlp = ProtoField.string("CCP_PAR_SC_SURF_LOCK_CONFIG.rlp", "Reset Locking Period")
	f_surf_locking_config_sc_slp = ProtoField.string("CCP_PAR_SC_SURF_LOCK_CONFIG.slp", "Surf Locking Period")
	
	CCP_PAR_SC_SURF_LOCK_CONFIG.fields = {f_surf_locking_config_sc_opcode, f_surf_locking_config_sc_length, f_surf_locking_config_sc_cp_min, f_surf_locking_config_sc_rfu, f_surf_locking_config_sc_init_switches,
																			f_surf_locking_config_sc_fsc_inc, f_surf_locking_config_sc_fsc_dec, f_surf_locking_config_sc_fsc_max, f_surf_locking_config_sc_rlp, f_surf_locking_config_sc_slp}
	
	function CCP_PAR_SC_SURF_LOCK_CONFIG.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x05 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_SURF_LOCK_CONFIG, buf(0,  2 + length))
		t:add(f_nationality_sc_opcode, opcode)
		t:add(f_nationality_sc_length, length)
		t:add(f_surf_locking_config_sc_cp_min, buf(2,1))
		t:add(f_surf_locking_config_sc_rfu, bit:_and(bit:_rshift(buf(3,1):uint(), 5),0x7))
		t:add(f_surf_locking_config_sc_init_switches, bit:_and(buf(3,1):uint(), 0x1f))
		t:add(f_surf_locking_config_sc_fsc_inc, buf(4,1))
		t:add(f_surf_locking_config_sc_fsc_dec, buf(5,1))
		t:add(f_surf_locking_config_sc_fsc_max, buf(6,2))
		t:add(f_surf_locking_config_sc_rlp, bit:_and(bit:_rshift(buf(8,1):uint(),4), 0xf))
		t:add(f_surf_locking_config_sc_slp, bit:_and(buf(8,1):uint(), 0xf))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0005, CCP_PAR_SC_SURF_LOCK_CONFIG)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0005] = {
						["dis"] = ccp_table:get_dissector(0x0005),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  :  CI Layer Configuration Opcode

--]]	

	local CCP_PAR_SC_CI_LAYER_CONFIG = Proto("CCP_PAR_SC_CI_LAYER_CONFIG", "CI Layer Configuration")
	f_ci_layer_config_opcode = ProtoField.uint8("CCP_PAR_SC_CI_LAYER_CONFIG.opcode", "Opcode", base.HEX)
	f_ci_layer_config_length = ProtoField.uint16("CCP_PAR_SC_CI_LAYER_CONFIG.length", "Length", base.DEC)
	f_ci_layer_config_rfu = ProtoField.string("CCP_PAR_SC_CI_LAYER_CONFIG.rfu", "RFU")
	f_ci_layer_config_enforceipr = ProtoField.string("CCP_PAR_SC_CI_LAYER_CONFIG.enforceipr", "Enforce IPR")
	f_ci_layer_config_security_level = ProtoField.string("CCP_PAR_SC_CI_LAYER_CONFIG.security_level", "Security Level")
	f_ci_layer_config_relax = ProtoField.string("CCP_PAR_SC_CI_LAYER_CONFIG.relax", "Relax Service Enforcement")
	
	CCP_PAR_SC_CI_LAYER_CONFIG.fields = {f_ci_layer_config_opcode, f_ci_layer_config_length, f_ci_layer_config_rfu, f_ci_layer_config_enforceipr, f_ci_layer_config_security_level, f_ci_layer_config_relax}
	
	function CCP_PAR_SC_CI_LAYER_CONFIG.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x1e then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CCP_PAR_SC_CI_LAYER_CONFIG, buf(0,  2 + length))
		t:add(f_ci_layer_config_opcode, opcode)
		t:add(f_ci_layer_config_length, length)
		t:add(f_ci_layer_config_rfu, bit:_and(buf(2,1):uint(), 0x0e))
		t:add(f_ci_layer_config_enforceipr, bit:_rshift(bit:_and(buf(2,1):uint(), 0x80), 7))
		t:add(f_ci_layer_config_security_level, bit:_rshift(bit:_and(buf(2,1):uint(), 0x70), 4))
		t:add(f_ci_layer_config_relax, bit:_and(buf(2,1):uint(), 0x01))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	
	end
	
	ccp_table:add(0x001e, CCP_PAR_SC_CI_LAYER_CONFIG)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x001e] = {
						["dis"] = ccp_table:get_dissector(0x001e),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[
				
Smart Card  :  ARP Config Opcode

--]]
	local CCP_PAR_SC_ARP_CONFIG = Proto("CCP_PAR_SC_ARP_CONFIG", "ARP Config")
	f_arp_config_opcode = ProtoField.uint8("CCP_PAR_SC_ARP_CONFIG.opcode", "Opcode", base.HEX)
	f_arp_config_length = ProtoField.uint16("CCP_PAR_SC_ARP_CONFIG.length", "Length", base.DEC)
	f_arp_config_ciml_ext = ProtoField.uint16("CCP_PAR_SC_ARP_CONFIG.ciml_ext", "Channel Id Match Limit", base.DEC)
	f_arp_config_reset_arp = ProtoField.uint8("CCP_PAR_SC_ARP_CONFIG.reset_arp", "Reset ARP", base.DEC, nil, 0x80)
	f_arp_config_rfu = ProtoField.uint8("CCP_PAR_SC_ARP_CONFIG.rfu", "RFU", base.HEX, nil, 0x70)
	f_arp_config_inactive_time = ProtoField.uint8("CCP_PAR_SC_ARP_CONFIG.inactive_time", "Inactive Time", base.DEC, nil, 0x0f)
	
	CCP_PAR_SC_ARP_CONFIG.fields = {f_arp_config_opcode, f_arp_config_length, f_arp_config_ciml_ext, f_arp_config_reset_arp, f_arp_config_rfu, f_arp_config_inactive_time}
	
	function CCP_PAR_SC_ARP_CONFIG.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xa0 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			
	
		local t= root:add(CCP_PAR_SC_ARP_CONFIG, buf(0,  2 + length))
		t:add(f_arp_config_opcode, buf(0,1))
		t:add(f_arp_config_length, buf(1,1))
		t:add(f_arp_config_ciml_ext, buf(2,2))
		t:add(f_arp_config_reset_arp, buf(4,1))
		t:add(f_arp_config_rfu, buf(4,1))
		t:add(f_arp_config_inactive_time, buf(4,1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true			
		
	end
	
	ccp_table:add(0x00a0, CCP_PAR_SC_ARP_CONFIG)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00a0] = {
						["dis"] = ccp_table:get_dissector(0x00a0),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  :  0x6b	HGPC V6 Card Opcode

--]]	

	local CCP_PAR_SC_HGPC_V6_CARD = Proto("CCP_PAR_SC_HGPC_V6_CARD", "HGPC V6 Card")
	f_hgpc_v6_card_opcode = ProtoField.uint8("CCP_PAR_SC_HGPC_V6_CARD.opcode", "Opcode", base.HEX)
	f_hgpc_v6_card_length = ProtoField.uint16("CCP_PAR_SC_HGPC_V6_CARD.length", "Length", base.DEC)
	f_hgpc_v6_card_hna_timeout = ProtoField.uint16("CCP_PAR_SC_HGPC_V6_CARD.hna_timeout", "HNA Timeout", base.DEC)
	f_hgpc_v6_card_hna_heartbeat = ProtoField.uint16("CCP_PAR_SC_HGPC_V6_CARD.hna_heartbeat", "HNA Heartbeat", base.DEC)
	f_hgpc_v6_card_hnr_timeout_value = ProtoField.bytes("CCP_PAR_SC_HGPC_V6_CARD.hnr_timeout_value", "HNR Timeout Value", base.HEX)
	f_hgpc_v6_card_hna_generation = ProtoField.uint16("CCP_PAR_SC_HGPC_V6_CARD.hna_generation", "HNA Generation", base.DEC)
	
	CCP_PAR_SC_HGPC_V6_CARD.fields = {f_hgpc_v6_card_opcode, f_hgpc_v6_card_length, f_hgpc_v6_card_hna_timeout, f_hgpc_v6_card_hna_heartbeat, f_hgpc_v6_card_hnr_timeout_value, f_hgpc_v6_card_hna_generation}
	
	function CCP_PAR_SC_HGPC_V6_CARD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x6b then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t= root:add(CCP_PAR_SC_HGPC_V6_CARD, buf(0,  2 + length))
		t:add(f_hgpc_v6_card_opcode, buf(0,1))
		t:add(f_hgpc_v6_card_length, buf(1,1))
		t:add(f_hgpc_v6_card_hna_generation, buf(2,2))
		t:add(f_hgpc_v6_card_hna_heartbeat, buf(4,2))
		t:add(f_hgpc_v6_card_hna_timeout, buf(6,2))
		t:add(f_hgpc_v6_card_hnr_timeout_value, buf(8, length - 6))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x006b, CCP_PAR_SC_HGPC_V6_CARD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x006b] = {
						["dis"] = ccp_table:get_dissector(0x006b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  :  0x3b	HGPC V5 Card Opcode

--]]	

	local CCP_PAR_SC_HGPC_V5_CARD = Proto("CCP_PAR_SC_HGPC_V5_CARD", "HGPC V5 Card")
	f_hgpc_v5_card_opcode = ProtoField.uint8("CCP_PAR_SC_HGPC_V5_CARD.opcode", "Opcode", base.HEX)
	f_hgpc_v5_card_length = ProtoField.uint16("CCP_PAR_SC_HGPC_V5_CARD.length", "Length", base.DEC)
	f_hgpc_v5_card_hna_timeout = ProtoField.uint16("CCP_PAR_SC_HGPC_V5_CARD.hna_timeout", "HNA Timeout", base.DEC)
	f_hgpc_v5_card_hna_heartbeat = ProtoField.uint16("CCP_PAR_SC_HGPC_V5_CARD.hna_heartbeat", "HNA Heartbeat", base.DEC)
	f_hgpc_v5_card_hnr_timeout_value = ProtoField.bytes("CCP_PAR_SC_HGPC_V5_CARD.hnr_timeout_value", "HNR Timeout Value", base.HEX)
	f_hgpc_v5_card_hna_generation = ProtoField.uint16("CCP_PAR_SC_HGPC_V5_CARD.hna_generation", "HNA Generation", base.DEC)
	
	CCP_PAR_SC_HGPC_V5_CARD.fields = {f_hgpc_v5_card_opcode, f_hgpc_v5_card_length, f_hgpc_v5_card_hna_timeout, f_hgpc_v5_card_hna_heartbeat, f_hgpc_v5_card_hnr_timeout_value, f_hgpc_v5_card_hna_generation}
	
	function CCP_PAR_SC_HGPC_V5_CARD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3b then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t= root:add(CCP_PAR_SC_HGPC_V5_CARD, buf(0,  2 + length))
		t:add(f_hgpc_v5_card_opcode, buf(0,1))
		t:add(f_hgpc_v5_card_length, buf(1,1))
		t:add(f_hgpc_v5_card_hna_generation, buf(2,2))
		t:add(f_hgpc_v5_card_hna_heartbeat, buf(4,2))
		t:add(f_hgpc_v5_card_hna_timeout, buf(6,2))
		t:add(f_hgpc_v5_card_hnr_timeout_value, buf(8, length - 6))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x003b, CCP_PAR_SC_HGPC_V5_CARD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003b] = {
						["dis"] = ccp_table:get_dissector(0x003b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	

--[[

Smart Card  :  0x3b	PVRMSK OPCODE

--]]	

	local CCP_PAR_CA3_PVRMSK_DOWNLOAD = Proto("CCP_PAR_CA3_PVRMSK_DOWNLOAD", "CA3 PVRMSK")
	f_pvrmsk_ca3_opcode = ProtoField.uint8("CCP_PAR_CA3_PVRMSK_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_pvrmsk_ca3_length = ProtoField.uint16("CCP_PAR_CA3_PVRMSK_DOWNLOAD.length", "Length", base.DEC)
	f_pvrmsk_ca3_rfu1 = ProtoField.uint8("CCP_PAR_CA3_PVRMSK_DOWNLOAD.rfu1", "RFU1", base.HEX, nil, 0xc0)
	f_pvrmsk_ca3_pvrmsk_version = ProtoField.uint8("CCP_PAR_CA3_PVRMSK_DOWNLOAD.pvrmsk_version", "PVRMSK Version", base.HEX, nil, 0x30)
	f_pvrmsk_ca3_rfu2 = ProtoField.uint8("CCP_PAR_CA3_PVRMSK_DOWNLOAD.rfu2", "RFU2", base.HEX, nil, 0x0f)
	f_pvrmsk_ca3_pvrmsk = ProtoField.bytes("CCP_PAR_CA3_PVRMSK_DOWNLOAD.pvrmsk", "PVRMSK", base.HEX)
	
	CCP_PAR_CA3_PVRMSK_DOWNLOAD.fields = {f_pvrmsk_ca3_opcode, f_pvrmsk_ca3_length, f_pvrmsk_ca3_rfu1, f_pvrmsk_ca3_pvrmsk_version, f_pvrmsk_ca3_rfu2, f_pvrmsk_ca3_pvrmsk}
	
	function CCP_PAR_CA3_PVRMSK_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3b then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t= root:add(CCP_PAR_CA3_PVRMSK_DOWNLOAD, buf(0,  2 + length))
		t:add(f_pvrmsk_ca3_opcode, buf(0,1))
		t:add(f_pvrmsk_ca3_length, buf(1,1))
		t:add(f_pvrmsk_ca3_rfu1, buf(2,1))
		t:add(f_pvrmsk_ca3_pvrmsk_version, buf(2,1))
		t:add(f_pvrmsk_ca3_rfu2, buf(2,1))
		t:add(f_pvrmsk_ca3_pvrmsk, buf(3, 16))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x103b, CCP_PAR_CA3_PVRMSK_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x103b] = {
						["dis"] = ccp_table:get_dissector(0x103b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[
Smart Card  :  0x38	HGPC Primary Secure Client Activation OPCODE 
--]]

	local CCP_PAR_HGPC_Primary = Proto("CCP_PAR_HGPC_Primary", "HGPC Primary Secure Client Activation OpCode")
	local CCP_PAR_HGPC_Primary_Each_Secondary = Proto("CCP_PAR_HGPC_Primary_Each_Secondary", "Secondary Clients")
	f_hgpc_primary_opcode = ProtoField.uint8("CCP_PAR_HGPC_Primary.opcode", "Opcode", base.HEX)
	f_hgpc_primary_length = ProtoField.uint8("CCP_PAR_HGPC_Primary.length", "Length", base.DEC)
	f_hgpc_primary_method = ProtoField.uint8("CCP_PAR_HGPC_Primary.method", "Method", base.HEX, {[0]='Disable',[1]='HNA/HNA',[2]='HNR/HNR',[3]='HNR/HNA'}, 0xc0)
	f_hgpc_primary_rfu = ProtoField.uint8("CCP_PAR_HGPC_Primary.rfu", "Rfu", base.HEX, nil, 0x3f)
	f_hgpc_primary_hgpc_key = ProtoField.bytes("CCP_PAR_HGPC_Primary.hgpc_key", "HGPC Key", base.HEX)
	f_hgpc_primary_hna_refresht = ProtoField.bytes("CCP_PAR_HGPC_Primary.refresht", "RefreshT", base.DEC)
	f_hgpc_primary_hna_repeat = ProtoField.bytes("CCP_PAR_HGPC_Primary.repeat", "Repeat", base.DEC)
	f_hgpc_primary_secondary_unique_address = ProtoField.bytes("CCP_PAR_HGPC_Primary.secondary_unique_address", "Secondary Unique Address", base.HEX)
	f_hgpc_primary_secondary_serial_number = ProtoField.bytes("CCP_PAR_HGPC_Primary.secondary_serial_number", "Secondary Serial Number", base.HEX)
	
	CCP_PAR_HGPC_Primary.fields = {f_hgpc_primary_opcode, f_hgpc_primary_length, f_hgpc_primary_method, f_hgpc_primary_rfu, f_hgpc_primary_hgpc_key, 
									f_hgpc_primary_hna_refresht, f_hgpc_primary_hna_repeat, f_hgpc_primary_secondary_unique_address,
									f_hgpc_primary_secondary_serial_number}
									
	function CCP_PAR_HGPC_Primary.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x38 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 2 then
			return false
		end		

		local t= root:add(CCP_PAR_HGPC_Primary, buf(0, 2+length))
		t:add(f_hgpc_primary_opcode, buf(0,1))
		t:add(f_hgpc_primary_length, buf(1,1))
		t:add(f_hgpc_primary_method, buf(2,1))
		t:add(f_hgpc_primary_rfu, buf(2,1))

		if (length > 1) then
			t:add(f_hgpc_primary_hgpc_key, buf(3,16))
			t:add(f_hgpc_primary_hna_refresht, buf(19,2))
			t:add(f_hgpc_primary_hna_repeat, buf(21,2))
		

			local secondary_nr = (length - 21) / 8
			for i=0, secondary_nr-1 do
				local sec = t:add(CCP_PAR_HGPC_Primary_Each_Secondary, buf(23 + i*8, 8))
				sec:add(f_hgpc_primary_secondary_unique_address, buf(23+i*8, 3))
				sec:add(f_hgpc_primary_secondary_serial_number, buf(26+i*8, 5))
			end
		
		end
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x0038, CCP_PAR_HGPC_Primary)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0038] = {
						["dis"] = ccp_table:get_dissector(0x0038),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[
Smart Card  :  0x39	HGPC Secondary Secure Client Activation OPCODE 
--]]

	local CCP_PAR_HGPC_Secondary = Proto("CCP_PAR_HGPC_Secondary", "HGPC Secondary Secure Client Activation OpCode")
	f_hgpc_secondary_opcode = ProtoField.uint8("CCP_PAR_HGPC_Secondary.opcode", "Opcode", base.HEX)
	f_hgpc_secondary_length = ProtoField.uint8("CCP_PAR_HGPC_Secondary.length", "Length", base.DEC)
	f_hgpc_secondary_method = ProtoField.uint8("CCP_PAR_HGPC_Secondary.method", "Method", base.HEX, {[0]='Disable',[1]='HNA/HNA',[2]='HNR/HNR',[3]='HNR/HNA'}, 0xc0)
	f_hgpc_secondary_rfu = ProtoField.uint8("CCP_PAR_HGPC_Secondary.rfu", "Rfu", base.HEX, nil, 0x3f)
	f_hgpc_secondary_hgpc_key = ProtoField.bytes("CCP_PAR_HGPC_Secondary.hgpc_key", "HGPC Key", base.HEX)
	f_hgpc_secondary_hna_t = ProtoField.bytes("CCP_PAR_HGPC_Secondary.hna_t", "HNA-T", base.DEC)
	f_hgpc_secondary_hnr_t = ProtoField.bytes("CCP_PAR_HGPC_Secondary.hnr_t", "HNR-T", base.DEC)
	f_hgpc_secondary_primary_unique_address = ProtoField.bytes("CCP_PAR_HGPC_Secondary.primary_unique_address", "Primary Card Unique Address", base.HEX)
	f_hgpc_secondary_primary_serial_number = ProtoField.bytes("CCP_PAR_HGPC_Secondary.primary_serial_number", "Primary Card Serial Number", base.HEX)
	f_hgpc_secondary_activation_code = ProtoField.bytes("CCP_PAR_HGPC_Secondary.activation_code", "Activation Code", base.HEX)
	
	CCP_PAR_HGPC_Secondary.fields = {f_hgpc_secondary_opcode, f_hgpc_secondary_length, f_hgpc_secondary_method, f_hgpc_secondary_rfu, f_hgpc_secondary_hgpc_key, 
									f_hgpc_secondary_hna_t, f_hgpc_secondary_hnr_t, f_hgpc_secondary_primary_unique_address,f_hgpc_secondary_primary_serial_number, f_hgpc_secondary_activation_code}
									
	function CCP_PAR_HGPC_Secondary.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x39 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 2 then
			return false
		end		

		local t= root:add(CCP_PAR_HGPC_Secondary, buf(0, 2+length))
		t:add(f_hgpc_secondary_opcode, buf(0,1))
		t:add(f_hgpc_secondary_length, buf(1,1))
		t:add(f_hgpc_secondary_method, buf(2,1))
		t:add(f_hgpc_secondary_rfu, buf(2,1))

		if (length > 1) then
			t:add(f_hgpc_secondary_hgpc_key, buf(3,16))
			t:add(f_hgpc_secondary_hna_t, buf(19,2))
			t:add(f_hgpc_secondary_hnr_t, buf(21,2))
			t:add(f_hgpc_secondary_primary_unique_address, buf(23, 3))
			t:add(f_hgpc_secondary_primary_serial_number, buf(26, 5))
			t:add(f_hgpc_secondary_activation_code, buf(31,2))
		end
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x0039, CCP_PAR_HGPC_Secondary)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0039] = {
						["dis"] = ccp_table:get_dissector(0x0039),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[
Smart Card  :  0x3a HGPC Force Renew OPCODE
--]]
	local CCP_PAR_HGPC_Force_Renew = Proto("CCP_PAR_HGPC_Force_Renew", "HGPC Force Renew OpCode")
	f_hgpc_force_renew_opcode = ProtoField.uint8("CCP_PAR_HGPC_Force_Renew.opcode", "Opcode", base.HEX)
	f_hgpc_force_renew_length = ProtoField.uint8("CCP_PAR_HGPC_Force_Renew.length", "Length", base.DEC)
	f_hgpc_force_renew_running_mode_filter = ProtoField.uint8("CCP_PAR_HGPC_Force_Renew.running_mode_filter", "Running Mode Filter", base.HEX, {[0]='Only-HNA',[1]='Only-HNR',[2]='Both(HNA and HNR)'}, 0xc0)
	f_hgpc_force_renew_rfu = ProtoField.uint8("CCP_PAR_HGPC_Force_Renew.rfu", "Rfu", base.HEX, nil, 0x3f)
	
	CCP_PAR_HGPC_Force_Renew.fields = {f_hgpc_force_renew_opcode, f_hgpc_force_renew_length, f_hgpc_force_renew_running_mode_filter, f_hgpc_force_renew_rfu}
									
	function CCP_PAR_HGPC_Force_Renew.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3a then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 2 then
			return false
		end		

		local t= root:add(CCP_PAR_HGPC_Force_Renew, buf(0, 2+length))
		t:add(f_hgpc_force_renew_opcode, buf(0,1))
		t:add(f_hgpc_force_renew_length, buf(1,1))
		t:add(f_hgpc_force_renew_running_mode_filter, buf(2,1))
		t:add(f_hgpc_force_renew_rfu, buf(2,1))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true					
	end
	
	ccp_table:add(0x003a, CCP_PAR_HGPC_Force_Renew)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003a] = {
						["dis"] = ccp_table:get_dissector(0x003a),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	
	--[[
	
	Smart Card  : EMM User Profile
	
	]]--
	local CCP_EMM_USER_PROFILE = Proto("CCP_EMM_USER_PROFILE", "User Profile")
	f_emm_user_profile_opcode = ProtoField.uint8("CCP_EMM_USER_PROFILE.Opcode", "Opcode", base.HEX)
	f_emm_user_profile_length = ProtoField.uint8("CCP_EMM_USER_PROFILE.Length", "Length", base.DEC)
	f_emm_user_profile_id = ProtoField.uint8("CCP_EMM_USER_PROFILE.ProfileID", "ProfileID", base.HEX, nil, 0xe0)
	f_emm_user_profile_PIN_present = ProtoField.uint8("CCP_EMM_USER_PROFILE.PINPresent", "PINPresent", base.HEX, nil, 0x10)
	f_emm_user_profile_user_age_level = ProtoField.uint8("CCP_EMM_USER_PROFILE.UserAgeLevel", "UserAgeLevel", base.HEX, nil, 0x0f)
	f_emm_user_profile_user_PIN = ProtoField.uint8("CCP_EMM_USER_PROFILE.UserPIN", "UserPIN", base.HEX)

	CCP_EMM_USER_PROFILE.fields = {f_emm_user_profile_opcode, f_emm_user_profile_length, f_emm_user_profile_id, f_emm_user_profile_PIN_present, f_emm_user_profile_user_age_level, f_emm_user_profile_user_PIN}
	
	function CCP_EMM_USER_PROFILE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3e then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_EMM_USER_PROFILE, buf(0,  2 + length))
		t:add( f_emm_user_profile_opcode, buf(0, 1))
		t:add( f_emm_user_profile_length, buf(1, 1))
		t:add( f_emm_user_profile_id, buf(2, 1))
		t:add( f_emm_user_profile_PIN_present, buf(2, 1))
		t:add( f_emm_user_profile_user_age_level, buf(2, 1))
		t:add( f_emm_user_profile_user_PIN, buf(3, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x003e, CCP_EMM_USER_PROFILE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003e] = {
						["dis"] = ccp_table:get_dissector(0x003e),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	
	--[[
	
	Smart Card  : ECM Maturity Rating Data CA3
	
	]]--
	local CCP_ECM_MATURITY_RATING_DATA_CA3 = Proto("CCP_ECM_MATURITY_RATING_DATA_CA3", "Maturity Rating Data CA3")
	local CCP_ECM_MATURITY_RATING_DATA_CA3_MRProfiles = Proto("CCP_ECM_MATURITY_RATING_DATA_CA3_MRProfiles", "MR Profiles CA3")
	f_ecm_maturity_rating_data_opcode = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA3.Opcode", "Opcode", base.HEX)
	f_ecm_maturity_rating_data_length = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA3.Length", "Length", base.DEC)
	f_ecm_maturity_rating_data_content_id = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA3.ContentID", "ContentID", base.HEX)
	f_ecm_maturity_rating_data_MR_profile_id = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA3.MRProfileID", "MRProfileID", base.HEX, nil, 0xf0)
	f_ecm_maturity_rating_data_MR_level = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA3.MRLevel", "MRLevel", base.HEX, nil, 0x0f)

	CCP_ECM_MATURITY_RATING_DATA_CA3.fields = {f_ecm_maturity_rating_data_opcode, f_ecm_maturity_rating_data_length, f_ecm_maturity_rating_data_content_id, f_ecm_maturity_rating_data_MR_profile_id, f_ecm_maturity_rating_data_MR_level}
	
	function CCP_ECM_MATURITY_RATING_DATA_CA3.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3c then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_ECM_MATURITY_RATING_DATA_CA3, buf(0,  2 + length))
	  	t:add( f_ecm_maturity_rating_data_opcode, buf(0, 1))
		t:add( f_ecm_maturity_rating_data_length, buf(1, 1))
		t:add( f_ecm_maturity_rating_data_content_id, buf(2, 2))
		
		local mr_profile_nr = (length - 2) 
		for i = 0, mr_profile_nr - 1 do
			local pt = t:add(CCP_ECM_MATURITY_RATING_DATA_CA3_MRProfiles, buf(4 + i, 1))
			pt:add( f_ecm_maturity_rating_data_MR_profile_id, buf(4 + i, 1))
			pt:add( f_ecm_maturity_rating_data_MR_level, buf(4 + i, 1))
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x003c, CCP_ECM_MATURITY_RATING_DATA_CA3)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003c] = {
						["dis"] = ccp_table:get_dissector(0x003c),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	
	--[[
	
	Smart Card  : ECM Maturity Rating Data CA2
	
	]]--
	local CCP_ECM_MATURITY_RATING_DATA_CA2 = Proto("CCP_ECM_MATURITY_RATING_DATA_CA2", "Maturity Rating Data CA2")
	local CCP_ECM_MATURITY_RATING_DATA_CA2_MRProfiles = Proto("CCP_ECM_MATURITY_RATING_DATA_CA2_MRProfiles", "MR Profiles CA2")
	f_ecm_maturity_rating_data_opcode = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA2.Opcode", "Opcode", base.HEX)
	f_ecm_maturity_rating_data_length = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA2.Length", "Length", base.DEC)
	f_ecm_maturity_rating_data_content_id = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA2.ContentID", "ContentID", base.HEX)
	f_ecm_maturity_rating_data_MR_profile_id = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA2.MRProfileID", "MRProfileID", base.HEX, nil, 0xf0)
	f_ecm_maturity_rating_data_MR_level = ProtoField.uint8("CCP_ECM_MATURITY_RATING_DATA_CA2.MRLevel", "MRLevel", base.HEX, nil, 0x0f)

	CCP_ECM_MATURITY_RATING_DATA_CA2.fields = {f_ecm_maturity_rating_data_opcode, f_ecm_maturity_rating_data_length, f_ecm_maturity_rating_data_content_id, f_ecm_maturity_rating_data_MR_profile_id, f_ecm_maturity_rating_data_MR_level}
	
	function CCP_ECM_MATURITY_RATING_DATA_CA2.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3f then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_ECM_MATURITY_RATING_DATA_CA2, buf(0,  2 + length))
	  	t:add( f_ecm_maturity_rating_data_opcode, buf(0, 1))
		t:add( f_ecm_maturity_rating_data_length, buf(1, 1))
		t:add( f_ecm_maturity_rating_data_content_id, buf(2, 2))
		
		local mr_profile_nr = (length - 2) 
		for i = 0, mr_profile_nr - 1 do
			local pt = t:add(CCP_ECM_MATURITY_RATING_DATA_CA2_MRProfiles, buf(4 + i, 1))
			pt:add( f_ecm_maturity_rating_data_MR_profile_id, buf(4 + i, 1))
			pt:add( f_ecm_maturity_rating_data_MR_level, buf(4 + i, 1))
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x003f, CCP_ECM_MATURITY_RATING_DATA_CA2)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003f] = {
						["dis"] = ccp_table:get_dissector(0x003f),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	
	--[[
	
	Smart Card  : EMM Maturity Rating Profile Create/Overwrite
	
	]]--
	local CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite = Proto("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite", "Maturity Rating Profile Create/Overwrite")
	f_emm_maturity_rating_profile_create_overwrite_opcode = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.Opcode", "Opcode", base.HEX)
	f_emm_maturity_rating_profile_create_overwrite_length = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.Length", "Length", base.DEC)
	f_emm_maturity_rating_profile_create_overwrite_profile_id = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.ProfileID", "Profile ID", base.HEX, nil, 0xf0)
	f_emm_maturity_rating_profile_create_overwrite_number_of_equal_PIN_digits = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.NumberOfEqualPINDigits", "No. Of Equal PIN Digits", base.HEX, nil, 0x0c)
	f_emm_maturity_rating_profile_create_overwrite_user_profile_update = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.UserProfileUpdate", "User Profile Update", base.HEX, nil, 0x02)
	f_emm_maturity_rating_profile_create_overwrite_disable_MR_blockout_allowed = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.DisableMRBlockoutAllowed", "Disable MR Block-out Allowed", base.HEX, nil, 0x01)	
	f_emm_maturity_rating_profile_create_overwrite_max_parental_PIN_retries = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.MaxParentalPINRetries", "Max Parental PIN Retries", base.HEX, nil, 0xf0)
	f_emm_maturity_rating_profile_create_overwrite_max_user_PIN_retries = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.MaxUserPINRetries", "Max User PIN Retries", base.HEX, nil, 0x0f)
	f_emm_maturity_rating_profile_create_overwrite_temporary_block_out = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.TemporaryBlockOut", "Temporary Block-Out", base.HEX, nil, 0xf0)
	f_emm_maturity_rating_profile_create_overwrite_rating = ProtoField.uint8("CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.Rating", "Rating", base.HEX, nil, 0x0f)
	
	CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.fields = {f_emm_maturity_rating_profile_create_overwrite_opcode, f_emm_maturity_rating_profile_create_overwrite_length,
	                                                           f_emm_maturity_rating_profile_create_overwrite_profile_id, f_emm_maturity_rating_profile_create_overwrite_number_of_equal_PIN_digits,
															   f_emm_maturity_rating_profile_create_overwrite_user_profile_update, f_emm_maturity_rating_profile_create_overwrite_disable_MR_blockout_allowed,
															   f_emm_maturity_rating_profile_create_overwrite_max_parental_PIN_retries, f_emm_maturity_rating_profile_create_overwrite_max_user_PIN_retries,
															   f_emm_maturity_rating_profile_create_overwrite_temporary_block_out, f_emm_maturity_rating_profile_create_overwrite_rating}
	
	function CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x3d then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite, buf(0,  2 + length))
	  	t:add( f_emm_maturity_rating_profile_create_overwrite_opcode, buf(0, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_length, buf(1, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_profile_id, buf(2, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_number_of_equal_PIN_digits, buf(2, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_user_profile_update, buf(2, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_disable_MR_blockout_allowed, buf(2, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_max_parental_PIN_retries, buf(3, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_max_user_PIN_retries, buf(3, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_temporary_block_out, buf(4, 1))
		t:add( f_emm_maturity_rating_profile_create_overwrite_rating, buf(4, 1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x003d, CCP_EMM_MATURITY_RATING_Profile_Create_Overwrite)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x003d] = {
						["dis"] = ccp_table:get_dissector(0x003d),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	

	--[[
	
	Smart Card  : EMM Nationality Filter
	
	]]--
	local CCP_EMM_NATIONALITY_FILTER = Proto("CCP_EMM_NATIONALITY_FILTER", "Nationality Filter")
	f_emm_reset_nationality_filter_opcode = ProtoField.uint8("CCP_EMM_NATIONALITY_FILTER.Opcode", "Opcode", base.HEX)
	f_emm_reset_nationality_filter_length = ProtoField.uint8("CCP_EMM_NATIONALITY_FILTER.Length", "Length", base.DEC)
	f_emm_reset_nationality_filter_nationality = ProtoField.uint8("CCP_EMM_NATIONALITY_FILTER.Nationality", "Nationality", base.HEX)

	CCP_EMM_NATIONALITY_FILTER.fields = {f_emm_reset_nationality_filter_opcode, f_emm_reset_nationality_filter_length, f_emm_reset_nationality_filter_nationality}
	
	function CCP_EMM_NATIONALITY_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xe2 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_EMM_NATIONALITY_FILTER, buf(0,  2 + length))
		t:add( f_emm_reset_nationality_filter_opcode, buf(0, 1))
		t:add( f_emm_reset_nationality_filter_length, buf(1, 1))
		t:add( f_emm_reset_nationality_filter_nationality, buf(2, 3))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00e2, CCP_EMM_NATIONALITY_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00e2] = {
						["dis"] = ccp_table:get_dissector(0x00e2),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	
	--[[
	
	Smart Card  :  CA3 Product Key Overwrite Opcode
	
	]]--

	local CCP_PAR_SC_PRODUCT_KEY_OVERWRITE = Proto("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE", "PKey Overwrite")
	f_pk_overwrite_ca3_opcode = ProtoField.uint8("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.opcode", "Opcode", base.HEX)
	f_pk_overwrite_ca3_length = ProtoField.uint16("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.length", "Length",base.DEC)
	f_pk_overwrite_ca3_key_index = ProtoField.string("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.key_index", "Key Index")
	f_pk_overwrite_ca3_selection = ProtoField.string("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.selection", "Selection")
	f_pk_overwrite_ca3_generation = ProtoField.string("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.generation", "Generation")
	f_pk_overwrite_ca3_pk = ProtoField.bytes("CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.pk", "Product Key", base.HEX)
	
	CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.fields = {f_pk_overwrite_ca3_opcode, f_pk_overwrite_ca3_length, f_pk_overwrite_ca3_key_index,
																						f_pk_overwrite_ca3_selection, f_pk_overwrite_ca3_generation, f_pk_overwrite_ca3_pk}
	
	function CCP_PAR_SC_PRODUCT_KEY_OVERWRITE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x50 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	

		local t= root:add(CCP_PAR_SC_PRODUCT_KEY_OVERWRITE, buf(0,  2 + length))
		t:add(f_pk_overwrite_ca3_opcode, opcode)
		t:add(f_pk_overwrite_ca3_length, length)		
		t:add(f_pk_overwrite_ca3_key_index, bit:_and(bit:_rshift(buf(2,1):uint(),3), 0x1f))
		t:add(f_pk_overwrite_ca3_selection, bit:_and(bit:_rshift(buf(2,1):uint(), 1), 0x3))
		t:add(f_pk_overwrite_ca3_generation, bit:_and(buf(2,1):uint(), 0x1))
		
		local selection = bit:_and(bit:_rshift(buf(2,1):uint(), 1), 0x3)
		local size = 0
		if selection == 0 then
			size = 16
		else
			size = 8
		end
		t:add(f_pk_overwrite_ca3_pk, buf(3, size))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	
	end
	
	ccp_table:add(0x0050, CCP_PAR_SC_PRODUCT_KEY_OVERWRITE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0050] = {
						["dis"] = ccp_table:get_dissector(0x0050),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  :  Sector Control Overwrite

--]]

	local CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE = Proto("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE", "Sector Control Overwrite")
	f_sector_control_overwrite_opcode = ProtoField.uint8("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.opcode", "Opcode", base.HEX)
	f_sector_control_overwrite_length = ProtoField.uint16("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.length", "Length", base.DEC)
	f_sector_control_overwrite_rfu = ProtoField.string("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.rfu", "RFU")
	f_sector_control_overwrite_sector_number = ProtoField.string("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.sector_number", "Sector Number")
	f_sector_control_overwrite_gk0 = ProtoField.bytes("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.gk0", "Group Key0", base.HEX)
	f_sector_control_overwrite_gk1 = ProtoField.bytes("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.gk1", "Group Key1", base.HEX)
	f_sector_control_overwrite_group_address = ProtoField.bytes("CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.group_address", "Group Address", base.HEX)
	
	CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.fields = {f_sector_control_overwrite_opcode, f_sector_control_overwrite_length, f_sector_control_overwrite_rfu,
																								f_sector_control_overwrite_sector_number, f_sector_control_overwrite_gk0, f_sector_control_overwrite_gk1, f_sector_control_overwrite_group_address}

	function CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x68 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE, buf(0,  2 + length))
		t:add(f_sector_control_overwrite_opcode, opcode)
		t:add(f_sector_control_overwrite_length, length)		
		t:add(f_sector_control_overwrite_rfu, bit:_and(bit:_rshift(buf(2,1):uint(),4),0xf))
		t:add(f_sector_control_overwrite_sector_number, bit:_and(buf(2,1):uint(),0xf))
		t:add(f_sector_control_overwrite_gk0, buf(3,16))
		t:add(f_sector_control_overwrite_gk1, buf(19, 16))
		t:add(f_sector_control_overwrite_group_address, buf(35, 3))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true		
	end
	
	ccp_table:add(0x0068, CCP_PAR_SC_SECTOR_CONTROL_OVERWRITE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0068] = {
						["dis"] = ccp_table:get_dissector(0x0068),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	
	
--[[

Smart Card  :   Extended Pairing Opcode

--]]

	local CCP_PAR_SC_EXTEND_PAIR = Proto("CCP_PAR_SC_EXTEND_PAIR", "Extended Pairing")
	f_extend_pair_opcode = ProtoField.uint8("CCP_PAR_SC_EXTEND_PAIR.opcode", "Opcode", base.HEX)
	f_extend_pair_length = ProtoField.uint16("CCP_PAR_SC_EXTEND_PAIR.length", "Length", base.DEC)
	f_extend_pair_algorithm = ProtoField.uint8("CCP_PAR_SC_EXTEND_PAIR.algorithm", "Algorithm",  base.HEX)
	f_extend_pair_config = ProtoField.uint8("CCP_PAR_SC_EXTEND_PAIR.config", "Config", base.HEX)
	f_extend_pair_cssn = ProtoField.bytes("CCP_PAR_SC_EXTEND_PAIR.cssn", "CSSN", base.HEX)
	f_extend_pair_sk = ProtoField.bytes("CCP_PAR_SC_EXTEND_PAIR.sk", "Session Key", base.HEX)
	f_extend_pair_alg_sk_uk = ProtoField.bytes("CCP_PAR_SC_EXTEND_PAIR.alg_sk_uk", "ALG CSSK", base.HEX)
	f_extend_pair_seq_number = ProtoField.uint8("CCP_PAR_SC_EXTEND_PAIR.seq_number", "Sequence Number CW", base.DEC)
	f_extend_pair_pvr_sk = ProtoField.bytes("CCP_PAR_SC_EXTEND_PAIR.pvr_sk", "PVR Session Key", base.HEX)
	f_extend_pair_pvr_alg_sk_uk = ProtoField.bytes("CCP_PAR_SC_EXTEND_PAIR.pvr_alg_sk_uk", "PVR ALG CSSK", base.HEX)
	f_extend_pvr_seq_number = ProtoField.uint8("CCP_PAR_SC_EXTEND_PAIR.pvr_seq_number", "PVR Sequence Number", base.DEC)
	
	CCP_PAR_SC_EXTEND_PAIR.fields = {f_extend_pair_opcode, f_extend_pair_length, f_extend_pair_algorithm,
																f_extend_pair_config, f_extend_pair_cssn, f_extend_pair_sk, f_extend_pair_alg_sk_uk,
																f_extend_pair_seq_number, f_extend_pair_pvr_sk, f_extend_pair_pvr_alg_sk_uk, f_extend_pvr_seq_number}

	function CCP_PAR_SC_EXTEND_PAIR.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x14 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CCP_PAR_SC_EXTEND_PAIR, buf(0,  2 + length))
		t:add(f_extend_pair_opcode, opcode)
		t:add(f_extend_pair_length, length)		
		t:add(f_extend_pair_algorithm, buf(2,1))
		t:add(f_extend_pair_config, buf(3,1))
		t:add(f_extend_pair_cssn, buf(4,4))
		t:add(f_extend_pair_sk, buf(8, 16))
		t:add(f_extend_pair_alg_sk_uk, buf(24, 16))
		t:add(f_extend_pair_seq_number, buf(40,1))
		
		if length > 39 then
			t:add(f_extend_pair_pvr_sk, buf(41, 16))
			t:add(f_extend_pair_pvr_alg_sk_uk, buf(57, 16))
			t:add(f_extend_pvr_seq_number, buf(73,1))
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true		
	end
	
	ccp_table:add(0x0014, CCP_PAR_SC_EXTEND_PAIR)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0014] = {
						["dis"] = ccp_table:get_dissector(0x0014),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	--[[
	
	Smart Card :  Chipset Pairing Opcode
	
	--]]
	
	local CCP_PAR_SC_CHIP_PAIR = Proto("CCP_PAR_SC_CHIP_PAIR", "ChipSet Pairing")
	f_chip_pair_opcode = ProtoField.uint8("CCP_PAR_SC_CHIP_PAIR.opcode", "Opcode", base.HEX)
	f_chip_pair_length = ProtoField.uint16("CCP_PAR_SC_CHIP_PAIR.length", "Length", base.DEC)
	f_chip_pair_cssn = ProtoField.bytes("CCP_PAR_SC_CHIP_PAIR.cssn", "Chipset Serial Number", base.HEX)
	f_chip_pair_cssk = ProtoField.bytes("CCP_PAR_SC_CHIP_PAIR.cssk", "Chipset Session Key", base.HEX)
	f_chip_pair_tdes_cssk = ProtoField.bytes("CCP_PAR_SC_CHIP_PAIR.tdes_cssk", "TDES Chipset Session Key", base.HEX)
	
	CCP_PAR_SC_CHIP_PAIR.fields = {f_chip_pair_opcode, f_chip_pair_length, f_chip_pair_cssn, f_chip_pair_cssk, f_chip_pair_tdes_cssk}
	
	function CCP_PAR_SC_CHIP_PAIR.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x0f then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CCP_PAR_SC_CHIP_PAIR, buf(0,  2 + length))
		t:add(f_chip_pair_opcode, opcode)
		t:add(f_chip_pair_length, length)		
		t:add(f_chip_pair_cssn, buf(2,4))
		t:add(f_chip_pair_cssk, buf(6,16))
		t:add(f_chip_pair_tdes_cssk, buf(22,16))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true			
	
	end
	
	ccp_table:add(0x000f, CCP_PAR_SC_CHIP_PAIR)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x000f] = {
						["dis"] = ccp_table:get_dissector(0x000f),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	--[[
	
	Smart Card :  Chipset Unpairing Opcode
	
	--]]
	
	local CC_PAR_SC_CHIP_UNPAIR = Proto("CC_PAR_SC_CHIP_UNPAIR", "Chipset Unpairing")
	f_chip_unpair_opcode = ProtoField.uint8("CC_PAR_SC_CHIP_UNPAIR.opcode", "Opcode", base.HEX)
	f_chip_unpair_length = ProtoField.uint16("CC_PAR_SC_CHIP_UNPAIR.length", "Length", base.DEC)
	f_chip_unpair_enforce_flag = ProtoField.string("CC_PAR_SC_CHIP_UNPAIR.enforce_flag", "Enforce Flag")
	f_chip_unpair_delete_flag = ProtoField.string("CC_PAR_SC_CHIP_UNPAIR.delete_flag", "Delete Flag")
	f_chip_unpair_reserved = ProtoField.string("CC_PAR_SC_CHIP_UNPAIR.reserved", "Reserved")
	f_chip_unpair_cssn = ProtoField.bytes("CC_PAR_SC_CHIP_UNPAIR.cssn", "Chipset Serial Number", base.HEX)
	
	CC_PAR_SC_CHIP_UNPAIR.fields = {f_chip_unpair_opcode, f_chip_unpair_length, f_chip_unpair_enforce_flag, f_chip_unpair_delete_flag, f_chip_unpair_reserved, f_chip_unpair_cssn}
	
	function CC_PAR_SC_CHIP_UNPAIR.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x12 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CC_PAR_SC_CHIP_UNPAIR, buf(0,  2 + length))
		t:add(f_chip_unpair_opcode, opcode)
		t:add(f_chip_unpair_length, length)		
		t:add(f_chip_unpair_enforce_flag, bit:_and(bit:_rshift(buf(2,1):uint(), 7), 1))
		t:add(f_chip_unpair_delete_flag,  bit:_and(bit:_rshift(buf(2,1):uint(), 6), 1))
		t:add(f_chip_unpair_reserved, bit:_and(buf(2,1):uint(), 0x3f))
		t:add(f_chip_unpair_cssn, buf(3,4))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true			
	
	end
	
	ccp_table:add(0x0012, CC_PAR_SC_CHIP_UNPAIR)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0012] = {
						["dis"] = ccp_table:get_dissector(0x0012),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	--[[
	
	Smart Card : Scs Control Opcode
	
	--]]
	
	local CCP_PAR_SC_SCS_CONTROL = Proto("CCP_PAR_SC_SCS_CONTROL", "Scs Control")
	f_scs_control_opcode = ProtoField.uint8("CCP_PAR_SC_SCS_CONTROL.opcode", "Opcode", base.HEX)
	f_scs_control_length = ProtoField.uint16("CCP_PAR_SC_SCS_CONTROL.length", "Length", base.DEC)
	f_scs_control_count_included = ProtoField.string("CCP_PAR_SC_SCS_CONTROL.count_included", "Count Included")
	f_scs_control_set_pairing_enforce = ProtoField.string("CCP_PAR_SC_SCS_CONTROL.set_pairing_enforce", "Set Pairing Enforcement")
	f_scs_control_pairing_enforced = ProtoField.string("CCP_PAR_SC_SCS_CONTROL.pairing_enforced", "Pairing Enforced")
	f_scs_control_pvr_sk_gen_included = ProtoField.string("CCP_PAR_SC_SCS_CONTROL.pvr_sk_gen_included", "PVR Session Generation Included")
	f_scs_control_rfu = ProtoField.string("CCP_PAR_SC_SCS_CONTROL.rfu", "RFU")
	f_scs_control_expiry_count = ProtoField.uint16("CCP_PAR_SC_SCS_CONTROL.expiry_count", "Expiry Count", base.DEC)
	f_scs_control_pvr_sk_gen = ProtoField.uint8("CCP_PAR_SC_SCS_CONTROL.pvr_sk_gen", "PVR Session Key Generation", base.DEC)
	
	CCP_PAR_SC_SCS_CONTROL.fields = {f_scs_control_opcode, f_scs_control_length, f_scs_control_count_included, f_scs_control_set_pairing_enforce,
																f_scs_control_pairing_enforced, f_scs_control_pvr_sk_gen_included, f_scs_control_rfu, f_scs_control_expiry_count, f_scs_control_pvr_sk_gen}
																
	function CCP_PAR_SC_SCS_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x98 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t= root:add(CCP_PAR_SC_SCS_CONTROL, buf(0,  2 + length))
		t:add(f_scs_control_opcode, opcode)
		t:add(f_scs_control_length, length)		
		t:add(f_scs_control_count_included, bit:_and(bit:_shift(buf(2,1):uint(), 7), 1))
		t:add(f_scs_control_set_pairing_enforce,  bit:_and(bit:_shift(buf(2,1):uint(), 6), 1))
		t:add(f_scs_control_pairing_enforced, bit:_and(bit:_shift(buf(2,1):uint(), 5), 1))
		t:add(f_scs_control_pvr_sk_gen_included, bit:_and(bit:_shift(buf(2,1):uint(), 4), 1))
		t:add(f_scs_control_rfu, bit:_and(buf(2,1):uint(), 0xf))
		
		local count_included = bit:_and(bit:_shift(buf(2,1):uint(), 7), 1)
		local pvr_sk_gen_included = bit:_and(bit:_shift(buf(2,1):uint(), 4), 1)
		index = 0
		if count_included == 1 then
			t:add(f_scs_control_expiry_count, buf(3,2))
			index = index + 2
		end
		if pvr_sk_gen_included == 1 then
			t:add(f_scs_control_pvr_sk_gen, buf(3+index, 1))
			index = index + 1
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true			
	
	end
	
	ccp_table:add(0x0098, CCP_PAR_SC_SCS_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0098] = {
						["dis"] = ccp_table:get_dissector(0x0098),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card :  PVRMSK Download Opocde

--]]	

	local CCP_PAR_SC_PVRMSK_DOWNLOAD = Proto("CCP_PAR_SC_PVRMSK_DOWNLOAD", "PVRMSK Download")
	f_pvrmsk_sc_opcode = ProtoField.uint8("CCP_PAR_SC_PVRMSK_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_pvrmsk_sc_length = ProtoField.uint16("CCP_PAR_SC_PVRMSK_DOWNLOAD.length", "Length", base.DEC)
	f_pvrmsk_sc_pvrmsk = ProtoField.bytes("CCP_PAR_SC_PVRMSK_DOWNLOAD.pvrmsk", "PVR MSK", base.HEX)
	f_pvrmsk_sc_reck_algorithm = ProtoField.bytes("CCP_PAR_SC_PVRMSK_DOWNLOAD.reck_algorithm", "Reck Alogorithm", base.HEX)
	
	CCP_PAR_SC_PVRMSK_DOWNLOAD.fields = {f_pvrmsk_sc_opcode, f_pvrmsk_sc_length, f_pvrmsk_sc_pvrmsk, f_pvrmsk_sc_reck_algorithm}
	
	function CCP_PAR_SC_PVRMSK_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xbb then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_PVRMSK_DOWNLOAD, buf(0,  2 + length))
		t:add(f_pvrmsk_sc_opcode, opcode)
		t:add(f_pvrmsk_sc_length, length)
		t:add(f_pvrmsk_sc_pvrmsk, buf(2,16))
		t:add(f_pvrmsk_sc_reck_algorithm, buf(18, 1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x00bb, CCP_PAR_SC_PVRMSK_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00bb] = {
						["dis"] = ccp_table:get_dissector(0x00bb),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card :  TWEAK KEY Opocde

--]]	

	local CCP_PAR_SC_TWEAK_KEY = Proto("CCP_PAR_SC_TWEAK_KEY", "Tweak Key")
	f_tweak_sc_opcode = ProtoField.uint8("CCP_PAR_SC_TWEAK_KEY.opcode", "Opcode", base.HEX)
	f_tweak_sc_length = ProtoField.uint16("CCP_PAR_SC_TWEAK_KEY.length", "Length", base.DEC)
	f_tweak_sc_tweak0 = ProtoField.bytes("CCP_PAR_SC_TWEAK_KEY.tweak0", "Tweak0", base.HEX)
	f_tweak_sc_reck_tweak1 = ProtoField.bytes("CCP_PAR_SC_TWEAK_KEY.tweak1", "Tweak1", base.HEX)
	
	CCP_PAR_SC_TWEAK_KEY.fields = {f_tweak_sc_opcode, f_tweak_sc_length, f_tweak_sc_tweak0, f_tweak_sc_reck_tweak1}
	
	function CCP_PAR_SC_TWEAK_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x13 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_TWEAK_KEY, buf(0,  2 + length))
		t:add(f_tweak_sc_opcode, opcode)
		t:add(f_tweak_sc_length, length)
		t:add(f_tweak_sc_tweak0, buf(2,8))
		t:add(f_tweak_sc_reck_tweak1, buf(10, 8))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0013, CCP_PAR_SC_TWEAK_KEY)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0013] = {
						["dis"] = ccp_table:get_dissector(0x0013),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
						}
						
--[[

Smart Card :  Patch Level Update Opocde

--]]	

	local CCP_PAR_SC_PATCH_LEVEL_UPDATE = Proto("CCP_PAR_SC_PATCH_LEVEL_UPDATE", "Patch Level Update")
	f_patch_level_opcode = ProtoField.uint8("CCP_PAR_SC_PATCH_LEVEL_UPDATE.opcode", "Opcode", base.HEX)
	f_patch_level_length = ProtoField.uint16("CCP_PAR_SC_PATCH_LEVEL_UPDATE.length", "Length", base.DEC)
	f_patch_level_pl = ProtoField.uint16("CCP_PAR_SC_PATCH_LEVEL_UPDATE.patch_level", "Patch Level", base.HEX)
	f_patch_level_platform_arch = ProtoField.bytes("CCP_PAR_SC_PATCH_LEVEL_UPDATE.pa", "Card Platform Architecture", base.HEX)
	f_patch_level_package_info = ProtoField.bytes("CCP_PAR_SC_PATCH_LEVEL_UPDATE.package_info", "Package Info", base.HEX)
	
	CCP_PAR_SC_PATCH_LEVEL_UPDATE.fields = {f_patch_level_opcode, f_patch_level_length, f_patch_level_pl, f_patch_level_platform_arch, f_patch_level_package_info}
	
	function CCP_PAR_SC_PATCH_LEVEL_UPDATE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x43 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_PATCH_LEVEL_UPDATE, buf(0,  2 + length))
		t:add(f_patch_level_opcode, opcode)
		t:add(f_patch_level_length, length)
		t:add(f_patch_level_pl, buf(2,2))
		t:add(f_patch_level_platform_arch, buf(4, 1))
		
		local index = 3
		while index < length do
			t:add(f_patch_level_package_info, buf(index+2, 3))
			index = index + 3
		
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0043, CCP_PAR_SC_PATCH_LEVEL_UPDATE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0043] = {
						["dis"] = ccp_table:get_dissector(0x0043),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
						}
						
--[[

Smart Card :  Package Download Opocde

--]]	

	local CCP_PAR_SC_PACKAGE_DOWNLOAD= Proto("CCP_PAR_SC_PACKAGE_DOWNLOAD", "Package Download Opcode")
	f_package_download_opcode = ProtoField.uint8("CCP_PAR_SC_PACKAGE_DOWNLOAD.opcode", "Opcode", base.HEX)
	f_package_download_length = ProtoField.uint16("CCP_PAR_SC_PACKAGE_DOWNLOAD.length", "Length", base.DEC)
	f_package_download_ptid = ProtoField.uint8("CCP_PAR_SC_PACKAGE_DOWNLOAD.ptid", "Package Transport Id", base.DEC)
	f_package_download_offset = ProtoField.bytes("CCP_PAR_SC_PACKAGE_DOWNLOAD.offset", "Offset", base.HEX)
	f_package_download_package_data = ProtoField.bytes("CCP_PAR_SC_PACKAGE_DOWNLOAD.package_data", "Package Data", base.HEX)
	
	CCP_PAR_SC_PACKAGE_DOWNLOAD.fields = {f_package_download_opcode, f_package_download_length, f_package_download_ptid, f_package_download_offset, f_package_download_package_data}
	
	function CCP_PAR_SC_PACKAGE_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x42 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_PACKAGE_DOWNLOAD, buf(0,  2 + length))
		t:add(f_patch_level_opcode, opcode)
		t:add(f_patch_level_length, length)
		t:add(f_package_download_ptid, buf(2,1))
		t:add(f_package_download_offset, buf(3, 2))
		t:add(f_package_download_package_data, buf(5, length - 3))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0042, CCP_PAR_SC_PACKAGE_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0042] = {
						["dis"] = ccp_table:get_dissector(0x0042),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
						}
						
--[[

Smart Card :  Package Initiation Opocde

--]]	

	local CCP_PAR_SC_PACKAGE_INITIATION = Proto("CCP_PAR_SC_PACKAGE_INITIATION", "Package Initiation Opcode")
	local PACKAGE_INITIATION_DEPENDENCY_INFO = Proto("PACKAGE_INITIATION_DEPENDENCY_INFO", "Dependency Info")
	f_package_initiation_opcode = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.opcode", "Opcode", base.HEX)
	f_package_initiation_length = ProtoField.uint16("CCP_PAR_SC_PACKAGE_INITIATION.length", "Length", base.DEC)
	f_package_initiation_ptid = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.ptid", "Package Transport Id", base.HEX)
	f_package_initiation_pa = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.offset", "Card Platform Architecture", base.HEX)
	f_package_initiation_pid = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.package_data", "Package Id", base.DEC)
	f_package_initiation_major_vn = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.package_data", "Major Version Number", base.HEX)
	f_package_initiation_minor_vn = ProtoField.uint8("CCP_PAR_SC_PACKAGE_INITIATION.package_data", "Minor Version Number", base.HEX)
	f_package_initiation_dependency_list = ProtoField.bytes("CCP_PAR_SC_PACKAGE_INITIATION.dependecy_list", "Dependency List", base.HEX)
	
	CCP_PAR_SC_PACKAGE_INITIATION.fields = {f_package_initiation_opcode, f_package_initiation_length, f_package_initiation_ptid, f_package_initiation_pa, f_package_initiation_pid,
										f_package_initiation_major_vn, f_package_initiation_minor_vn, f_package_initiation_dependency_list}
	
	function CCP_PAR_SC_PACKAGE_INITIATION.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x41 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_PACKAGE_INITIATION, buf(0,  2 + length))
		t:add(f_patch_level_opcode, opcode)
		t:add(f_patch_level_length, length)
		t:add(f_package_download_ptid, buf(2,1))
		t:add(f_package_initiation_pa, buf(3,1))
		t:add(f_package_initiation_pid, buf(4,1))
		t:add(f_package_initiation_major_vn, buf(5,1))
		t:add(f_package_initiation_minor_vn, buf(6,1))
		
		local index = 5
		while index < length do
			local sub = t:add(PACKAGE_INITIATION_DEPENDENCY_INFO, buf(index+2, 3))
			sub:add(f_package_initiation_pid, buf(index+2, 1))
			sub:add(f_package_initiation_major_vn, buf(index+3, 1))
			sub:add(f_package_initiation_minor_vn, buf(index+4, 1))
			index = index + 3
		
		end
		


		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0041, CCP_PAR_SC_PACKAGE_INITIATION)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0041] = {
						["dis"] = ccp_table:get_dissector(0x0041),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
						}
						
						
	--[[

	Smart Card :  Local Session Key Cycling Control Filter Opocde

	--]]	

	local CCP_PAR_SC_LSKC_Control_Filter = Proto("CCP_PAR_SC_LSKC_Control_Filter", "Local Session Key Cycling Control Filter")
	f_lskc_control_filter_opcode = ProtoField.uint8("CCP_PAR_SC_LSKC_Control_Filter.opcode", "Opcode", base.HEX)
	f_lskc_control_filter_length = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.length", "Length", base.DEC)
	f_lskc_control_filter_flags = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags", "Flags", base.HEX)
	f_lskc_control_filter_grace_period = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.grace_period", "Grace Period", base.DEC)
	f_lskc_control_filter_resync_limit = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.resync_limit", "Resync Limit", base.DEC)
	f_lskc_control_filter_indicator_list = ProtoField.bytes("CCP_PAR_SC_LSKC_Control_Filter.indicator_list", "Indicator List", base.HEX)
	
	f_lskc_control_filter_flags_indicator_flag = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_indicator_flag", "Indicator Flag", base.HEX, nil, 0x80)
	f_lskc_control_filter_flags_mark = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_mark", "Mark", base.HEX, nil, 0x40)
	f_lskc_control_filter_flags_unmark = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_unmark", "Unmark", base.HEX, nil, 0x20)
	f_lskc_control_filter_flags_resync = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_resync", "Resync", base.HEX, nil, 0x10)
	f_lskc_control_filter_flags_set_grace_period = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_set_grace_period", "Set Grace Period", base.HEX, nil, 0x08)
	f_lskc_control_filter_flags_set_resync_limit = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_set_resync_limit", "Set Resync Limit", base.HEX, nil, 0x04)
	f_lskc_control_filter_flags_block = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_block", "Block", base.HEX, nil, 0x02)
	f_lskc_control_filter_flags_destroy = ProtoField.uint16("CCP_PAR_SC_LSKC_Control_Filter.flags_destroy", "Destroy", base.HEX, nil, 0x01)
	
	CCP_PAR_SC_LSKC_Control_Filter.fields = {f_lskc_control_filter_opcode, f_lskc_control_filter_length, f_lskc_control_filter_flags, f_lskc_control_filter_grace_period, 
											f_lskc_control_filter_resync_limit, f_lskc_control_filter_indicator_list,
											f_lskc_control_filter_flags_indicator_flag, f_lskc_control_filter_flags_mark, f_lskc_control_filter_flags_unmark,
											f_lskc_control_filter_flags_resync, f_lskc_control_filter_flags_set_grace_period, f_lskc_control_filter_flags_set_resync_limit, 
											f_lskc_control_filter_flags_block, f_lskc_control_filter_flags_destroy}
	
	function CCP_PAR_SC_LSKC_Control_Filter.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x44 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			

		local t= root:add(CCP_PAR_SC_LSKC_Control_Filter, buf(0,  2 + length))
		t:add(f_lskc_control_filter_opcode, opcode)
		t:add(f_lskc_control_filter_length, length)
		local st = t:add(f_lskc_control_filter_flags, buf(2,1))
		st:add(f_lskc_control_filter_flags_indicator_flag, buf(2,1))
		st:add(f_lskc_control_filter_flags_mark, buf(2,1))		
		st:add(f_lskc_control_filter_flags_unmark, buf(2,1))
		st:add(f_lskc_control_filter_flags_resync, buf(2,1))
		st:add(f_lskc_control_filter_flags_set_grace_period, buf(2,1))
		st:add(f_lskc_control_filter_flags_set_resync_limit, buf(2,1))
		st:add(f_lskc_control_filter_flags_block, buf(2,1))
		st:add(f_lskc_control_filter_flags_destroy, buf(2,1))
		
		local index = 3
		local set_grace_period = bit:_rshift((bit:_and(buf(2, 1):uint(), 0x08)),3)
		if set_grace_period == 1 then
			t:add(f_lskc_control_filter_grace_period, buf(index, 1))
			index = index + 1	
		end
		
		local set_resync_limit = bit:_rshift((bit:_and(buf(2, 1):uint(), 0x04)),2)
		if set_resync_limit == 1 then
			t:add(f_lskc_control_filter_resync_limit, buf(index, 3))
			index = index + 3						
		end
		
		if index <= length then
			st = t:add(f_lskc_control_filter_indicator_list, buf(index, length-index+2))
			local indicator_flag = bit:_rshift((bit:_and(buf(2, 1):uint(), 0x80)),7)
			local subIndex = 1
			if indicator_flag == 1 then --By CSSNs
				while index < length do
					st:add(tostring(subIndex)..':  '..tostring(buf(index, 4))..'  ('..(buf(index, 4)):uint()..')')
					index = index + 4	
					subIndex = subIndex + 1
				end
			elseif indicator_flag == 0 then -- By Key File ID ranges
				while index < length do
					st:add(tostring(subIndex)..':  '..tostring(buf(index, 2))..','..tostring(buf(index+2, 2))..'  ('..(buf(index, 2)):uint()..','..(buf(index+2, 2)):uint()..')')
					index = index + 4	
					subIndex = subIndex + 1				
				end
			end
		end
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true				
	end
	
	ccp_table:add(0x0044, CCP_PAR_SC_LSKC_Control_Filter)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0044] = {
						["dis"] = ccp_table:get_dissector(0x0044),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
						}
						
	--[[
	
	Smart Card  :  Package Level Filter Opcode
	
	]]--
	local CCP_PAR_PACKAGE_LEVEL_FILTER = Proto("CCP_PAR_PACKAGE_LEVEL_FILTER", "Package Level Filter")
	--0,1
	f_package_level_filter_opcode = ProtoField.uint8("CCP_PAR_PACKAGE_LEVEL_FILTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_package_level_filter_length = ProtoField.uint8("CCP_PAR_PACKAGE_LEVEL_FILTER.Length", "Length", base.DEC)
	--2,1 0,6
	f_package_level_filter_required_pl = ProtoField.bytes("CCP_PAR_PACKAGE_LEVEL_FILTER.required_pl", "Required Package Level", base.HEX)
	--2,1 6,2
	f_package_level_filter_grace_duration = ProtoField.uint16("CCP_PAR_PACKAGE_LEVEL_FILTER.grace_duration", "Grace Duration", base.DEC)

	CCP_PAR_PACKAGE_LEVEL_FILTER.fields = {f_package_level_filter_opcode, f_package_level_filter_length, f_package_level_filter_required_pl, f_package_level_filter_grace_duration}
	
	function CCP_PAR_PACKAGE_LEVEL_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc4 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_PACKAGE_LEVEL_FILTER, buf(0,  2 + length))
		t:add( f_package_level_filter_opcode, buf(0, 1))
		t:add( f_package_level_filter_length, buf(1, 1))
		t:add( f_package_level_filter_required_pl, buf(2,2))
		if length == 3 then
			t:add( f_package_level_filter_grace_duration, buf(4,1))
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c4, CCP_PAR_PACKAGE_LEVEL_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c4] = {
						["dis"] = ccp_table:get_dissector(0x00c4),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	ccp_opcodes_protos[0x02c4] = {
						["dis"] = ccp_table:get_dissector(0x00c4),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  Patch Data Download Opcode
	
	]]--
	local CCP_PAR_PATCH_DATA_DOWNLOAD = Proto("CCP_PAR_PATCH_DATA_DOWNLOAD", "Patch Data Download Opcode")
	--0,1
	f_patch_data_download_opcode = ProtoField.uint8("CCP_PAR_PATCH_DATA_DOWNLOAD.Opcode", "Opcode", base.HEX)
	--1,1
	f_patch_data_download_length = ProtoField.uint8("CCP_PAR_PATCH_DATA_DOWNLOAD.Length", "Length", base.DEC)
	--2,1 0,6
	f_patch_data_download_patch_id = ProtoField.uint16("CCP_PAR_PATCH_DATA_DOWNLOAD.patch_id", "Patch Id", base.HEX)
	--2,1 6,2
	f_patch_data_download_offset = ProtoField.uint16("CCP_PAR_PATCH_DATA_DOWNLOAD.offset", "Offset", base.HEX)
	f_patch_data_download_patch_data = ProtoField.bytes("CCP_PAR_PATCH_DATA_DOWNLOAD.patch_data", "Patch Data", base.HEX)

	CCP_PAR_PATCH_DATA_DOWNLOAD.fields = {f_patch_data_download_opcode, f_patch_data_download_length, f_patch_data_download_patch_id, f_patch_data_download_offset, f_patch_data_download_patch_data}
	
	function CCP_PAR_PATCH_DATA_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x02 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_PATCH_DATA_DOWNLOAD, buf(0,  2 + length))
		t:add( f_patch_data_download_opcode, buf(0, 1))
		t:add( f_patch_data_download_length, buf(1, 1))
		t:add( f_patch_data_download_patch_id, buf(2,2))
		t:add( f_patch_data_download_offset, buf(4,2))
		t:add( f_patch_data_download_patch_data, buf(6, length - 4))
		

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0002, CCP_PAR_PATCH_DATA_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0002] = {
						["dis"] = ccp_table:get_dissector(0x0002),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  Patch Initiate Opcode
	
	]]--
	local CCP_PAR_PATCH_INITIATE = Proto("CCP_PAR_PATCH_INITIATE", "Patch Initiate Opcode")
	f_patch_initiate_opcode = ProtoField.uint8("CCP_PAR_PATCH_INITIATE.Opcode", "Opcode", base.HEX)
	f_patch_initiate_length = ProtoField.uint8("CCP_PAR_PATCH_INITIATE.Length", "Length", base.DEC)
	f_patch_initiate_required_model = ProtoField.bytes("CCP_PAR_PATCH_INITIATE.required_model", "Required Model", base.HEX)
	f_patch_initiate_target_patch_level = ProtoField.bytes("CCP_PAR_PATCH_INITIATE.target_patch_level", "Target Patch Level", base.HEX)
	f_patch_initiate_patch_id = ProtoField.bytes("CCP_PAR_PATCH_INITIATE.patch_id", "Patch Id", base.HEX)
	f_patch_initiate_required_patch_level = ProtoField.bytes("CCP_PAR_PATCH_INITIATE.required_patch_level", "Required Patch Level", base.HEX)

	CCP_PAR_PATCH_INITIATE.fields = {f_patch_initiate_opcode, f_patch_initiate_length, f_patch_initiate_required_model, f_patch_initiate_target_patch_level, f_patch_initiate_patch_id, f_patch_initiate_required_patch_level}
	
	function CCP_PAR_PATCH_INITIATE.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x01 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_PATCH_INITIATE, buf(0,  2 + length))
		t:add( f_patch_initiate_opcode, buf(0, 1))
		t:add( f_patch_initiate_length, buf(1, 1))
		t:add( f_patch_initiate_required_model, buf(2,3))
		t:add( f_patch_initiate_target_patch_level, buf(5,2))
		t:add( f_patch_initiate_patch_id, buf(7, 2))
		t:add( f_patch_initiate_required_patch_level, buf(9,2))
		

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0001, CCP_PAR_PATCH_INITIATE)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0001] = {
						["dis"] = ccp_table:get_dissector(0x0001),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  Patch Level Filter Opcode
	
	]]--
	local CCP_PAR_PATCH_LEVEL_FILTER = Proto("CCP_PAR_PATCH_LEVEL_FILTER", "Patch Level Filter Opcode")
	f_patch_level_filter_opcode = ProtoField.uint8("CCP_PAR_PATCH_LEVEL_FILTER.Opcode", "Opcode", base.HEX)
	f_patch_level_filter_length = ProtoField.uint8("CCP_PAR_PATCH_LEVEL_FILTER.Length", "Length", base.DEC)
	f_patch_level_filter_required_patch_level = ProtoField.uint16("CCP_PAR_PATCH_LEVEL_FILTER.required_patch_level", "Required Patch Level", base.HEX)

	CCP_PAR_PATCH_LEVEL_FILTER.fields = {f_patch_level_filter_opcode, f_patch_level_filter_length, f_patch_level_filter_required_patch_level}
	
	function CCP_PAR_PATCH_LEVEL_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x04 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_PATCH_LEVEL_FILTER, buf(0,  2 + length))
		t:add( f_patch_level_filter_opcode, buf(0, 1))
		t:add( f_patch_level_filter_length, buf(1, 1))
		t:add( f_patch_level_filter_required_patch_level, buf(2,2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0004, CCP_PAR_PATCH_LEVEL_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0004] = {
						["dis"] = ccp_table:get_dissector(0x0004),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  PIT-O Download Opcode
	
	]]--
	local CCP_PAR_PITO_DOWNLOAD = Proto("CCP_PAR_PITO_DOWNLOAD", "Pito Download Opcode")
	f_pito_download_opcode = ProtoField.uint8("CCP_PAR_PITO_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_pito_download_length = ProtoField.uint8("CCP_PAR_PITO_DOWNLOAD.Length", "Length", base.DEC)
	f_pito_download_pito = ProtoField.bytes("CCP_PAR_PITO_DOWNLOAD.pito", "PITO Key", base.HEX)

	CCP_PAR_PITO_DOWNLOAD.fields = {f_pito_download_opcode, f_pito_download_length, f_pito_download_pito}
	
	function CCP_PAR_PITO_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x19 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_PITO_DOWNLOAD, buf(0,  2 + length))
		t:add( f_pito_download_opcode, buf(0, 1))
		t:add( f_pito_download_length, buf(1, 1))
		t:add( f_pito_download_pito, buf(2,16))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0019, CCP_PAR_PITO_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0019] = {
						["dis"] = ccp_table:get_dissector(0x0019),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  OVK Download Opcode
	
	]]--
	local CCP_PAR_OVK_DOWNLOAD = Proto("CCP_PAR_OVK_DOWNLOAD", "OVK Download Opcode")
	f_ovk_download_opcode = ProtoField.uint8("CCP_PAR_OVK_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_ovk_download_length = ProtoField.uint8("CCP_PAR_OVK_DOWNLOAD.Length", "Length", base.DEC)
	f_ovk_download_ovk_index = ProtoField.uint8("CCP_PAR_OVK_DOWNLOAD.ovk_index", "OVK Index", base.HEX, nil, 0xe0)
	f_ovk_download_ovk_rfu = ProtoField.uint8("CCP_PAR_OVK_DOWNLOAD.rfu", "RFU", base.HEX, nil, 0x18)
	f_ovk_download_ovk_version = ProtoField.uint8("CCP_PAR_OVK_DOWNLOAD.ovk_version", "OVK Version", base.HEX, nil, 0x07)
	f_ovk_download_ovk = ProtoField.bytes("CCP_PAR_OVK_DOWNLOAD.ovk", "OVK", base.HEX)
	f_ovk_download_signature = ProtoField.bytes("CCP_PAR_OVK_DOWNLOAD.signature", "Signature", base.HEX)

	CCP_PAR_OVK_DOWNLOAD.fields = {f_ovk_download_opcode, f_ovk_download_length, f_ovk_download_ovk_index, f_ovk_download_ovk_rfu, f_ovk_download_ovk_version, f_ovk_download_ovk, f_ovk_download_signature}
	
	function CCP_PAR_OVK_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x15 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_OVK_DOWNLOAD, buf(0,  2 + length))
		t:add( f_ovk_download_opcode, buf(0, 1))
		t:add( f_ovk_download_length, buf(1, 1))
		t:add( f_ovk_download_ovk_index, buf(2, 1))
		t:add( f_ovk_download_ovk_rfu, buf(2,1))
		t:add( f_ovk_download_ovk_version, buf(2,1))
		t:add( f_ovk_download_ovk, buf(3,64))
		t:add( f_ovk_download_signature, buf(67, 64))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0015, CCP_PAR_OVK_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0015] = {
						["dis"] = ccp_table:get_dissector(0x0015),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  Update TKc Opcode
	
	]]--
	local CCP_PAR_UPDATE_TKC = Proto("CCP_PAR_UPDATE_TKC", "Update TKc Opcode")
	f_update_tkc_opcode = ProtoField.uint8("CCP_PAR_UPDATE_TKC.Opcode", "Opcode", base.HEX)
	f_update_tkc_length = ProtoField.uint8("CCP_PAR_UPDATE_TKC.Length", "Length", base.DEC)
	f_update_tkc_rfu = ProtoField.uint8("CCP_PAR_UPDATE_TKC.rfu", "RFU", base.HEX, nil, 0xf8)
	f_update_tkc_sector = ProtoField.uint8("CCP_PAR_UPDATE_TKC.sector", "Sector", base.HEX, nil, 0x07)
	f_update_tkc_tkc0 = ProtoField.bytes("CCP_PAR_UPDATE_TKC.tkc0", "TKC0", base.HEX)
	f_update_tkc_tkc1 = ProtoField.bytes("CCP_PAR_UPDATE_TKC.tkc1", "TKC1", base.HEX)

	CCP_PAR_UPDATE_TKC.fields = {f_update_tkc_opcode, f_update_tkc_length, f_update_tkc_rfu, f_update_tkc_sector, f_update_tkc_tkc0, f_update_tkc_tkc1}
	
	function CCP_PAR_UPDATE_TKC.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x18 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_UPDATE_TKC, buf(0,  2 + length))
		t:add( f_update_tkc_opcode, buf(0, 1))
		t:add( f_update_tkc_length, buf(1, 1))
		t:add( f_update_tkc_rfu, buf(2, 1))
		t:add( f_update_tkc_sector, buf(2, 1))
		t:add( f_update_tkc_tkc0, buf(3, 16))
		t:add( f_update_tkc_tkc1, buf(19, 16))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0018, CCP_PAR_UPDATE_TKC)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0018] = {
						["dis"] = ccp_table:get_dissector(0x0018),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  IPPV Debit Limit Opcode
	
	]]--
	local CCP_PAR_IPPV_DEBIT_LIMIT = Proto("CCP_PAR_IPPV_DEBIT_LIMIT", "IPPV Debit Limit Opcode")
	f_ippv_debit_limit_opcode = ProtoField.uint8("CCP_PAR_IPPV_DEBIT_LIMIT.Opcode", "Opcode", base.HEX)
	f_ippv_debit_limit_length = ProtoField.uint8("CCP_PAR_IPPV_DEBIT_LIMIT.Length", "Length", base.DEC)
	f_ippv_debit_limit_dl = ProtoField.uint16("CCP_PAR_IPPV_DEBIT_LIMIT.dl", "Debit Limit", base.HEX)

	CCP_PAR_IPPV_DEBIT_LIMIT.fields = {f_ippv_debit_limit_opcode, f_ippv_debit_limit_length, f_ippv_debit_limit_dl}
	
	function CCP_PAR_IPPV_DEBIT_LIMIT.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x58 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_IPPV_DEBIT_LIMIT, buf(0,  2 + length))
		t:add( f_ippv_debit_limit_opcode, buf(0, 1))
		t:add( f_ippv_debit_limit_length, buf(1, 1))
		t:add( f_ippv_debit_limit_dl, buf(2, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0058, CCP_PAR_IPPV_DEBIT_LIMIT)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0058] = {
						["dis"] = ccp_table:get_dissector(0x0058),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  IPPV Feedback Phone Number Download Opcode
	
	]]--
	local CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD = Proto("CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD", "IPPV Feedback PhoneNumber Download")
	f_ippv_pn_download_opcode = ProtoField.uint8("CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_ippv_pn_download_length = ProtoField.uint8("CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD.Length", "Length", base.DEC)
	f_ippv_pn_download_pn = ProtoField.bytes("CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD.pn", "Phone Number", base.HEX)

	CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD.fields = {f_ippv_pn_download_opcode, f_ippv_pn_download_length, f_ippv_pn_download_pn}
	
	function CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x59 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD, buf(0,  2 + length))
		t:add( f_ippv_pn_download_opcode, buf(0, 1))
		t:add( f_ippv_pn_download_length, buf(1, 1))
		t:add( f_ippv_pn_download_pn, buf(2, 8))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0059, CCP_PAR_IPPV_PHONENUMBER_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0059] = {
						["dis"] = ccp_table:get_dissector(0x0059),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  IPPV Feedback Key Download Opcode
	
	]]--
	local CCP_PAR_IPPV_KEY_DOWNLOAD = Proto("CCP_PAR_IPPV_KEY_DOWNLOAD", "IPPV Feedback Key Download Opcode")
	f_ippv_key_download_opcode = ProtoField.uint8("CCP_PAR_IPPV_KEY_DOWNLOAD.Opcode", "Opcode", base.HEX)
	f_ippv_key_download_length = ProtoField.uint8("CCP_PAR_IPPV_KEY_DOWNLOAD.Length", "Length", base.DEC)
	f_ippv_key_download_session_number = ProtoField.uint16("CCP_PAR_IPPV_KEY_DOWNLOAD.sn", "Session Number", base.DEC)
	f_ippv_key_download_feedback_key = ProtoField.bytes("CCP_PAR_IPPV_KEY_DOWNLOAD.fk", "Feedback Key", base.HEX)

	CCP_PAR_IPPV_KEY_DOWNLOAD.fields = {f_ippv_key_download_opcode, f_ippv_key_download_length, f_ippv_key_download_session_number, f_ippv_key_download_feedback_key}
	
	function CCP_PAR_IPPV_KEY_DOWNLOAD.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x5a then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_IPPV_KEY_DOWNLOAD, buf(0,  2 + length))
		t:add( f_ippv_key_download_opcode, buf(0, 1))
		t:add( f_ippv_key_download_length, buf(1, 1))
		t:add( f_ippv_key_download_session_number, buf(2, 2))
		t:add( f_ippv_key_download_feedback_key, buf(4, 16))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x005a, CCP_PAR_IPPV_KEY_DOWNLOAD)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x005a] = {
						["dis"] = ccp_table:get_dissector(0x005a),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	Smart Card  :  IPPV Initiate Callback Opcode
	
	]]--
	local CCP_PAR_IPPV_INITIATE_CALLBACK = Proto("CCP_PAR_IPPV_INITIATE_CALLBACK", "IPPV Initiate Callback Opcode")
	f_ippv_initiate_callback_opcode = ProtoField.uint8("CCP_PAR_IPPV_INITIATE_CALLBACK.Opcode", "Opcode", base.HEX)
	f_ippv_initiate_callback_length = ProtoField.uint8("CCP_PAR_IPPV_INITIATE_CALLBACK.Length", "Length", base.DEC)
	f_ippv_initiate_callback_control = ProtoField.uint8("CCP_PAR_IPPV_INITIATE_CALLBACK.control", "Control", base.DEC)
	f_ippv_initiate_callback_pn_delay = ProtoField.uint16("CCP_PAR_IPPV_INITIATE_CALLBACK.pn_delay", "Phone Delay", base.DEC)

	CCP_PAR_IPPV_INITIATE_CALLBACK.fields = {f_ippv_initiate_callback_opcode, f_ippv_initiate_callback_length, f_ippv_initiate_callback_control, f_ippv_initiate_callback_pn_delay}
	
	function CCP_PAR_IPPV_INITIATE_CALLBACK.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x5b then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_PAR_IPPV_INITIATE_CALLBACK, buf(0,  2 + length))
		t:add( f_ippv_initiate_callback_opcode, buf(0, 1))
		t:add( f_ippv_initiate_callback_length, buf(1, 1))
		t:add( f_ippv_initiate_callback_control, buf(2, 1))
		t:add( f_ippv_initiate_callback_pn_delay, buf(3, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x005b, CCP_PAR_IPPV_INITIATE_CALLBACK)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x005b] = {
						["dis"] = ccp_table:get_dissector(0x005b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	

	--[[
	
	Smart Card  : EMM Reset PIN
	
	]]--
	local CCP_EMM_RESET_PIN = Proto("CCP_OPCODE_EMM_RESET_PIN", "RESET PIN")
	f_emm_reset_pin_opcode = ProtoField.uint8("CCP_EMM_RESET_PIN.Opcode", "Opcode", base.HEX)
	f_emm_reset_pin_length = ProtoField.uint8("CCP_EMM_RESET_PIN.Length", "Length", base.DEC)
	f_emm_reset_password_index = ProtoField.uint8("CCP_EMM_RESET_PIN.PasswordIndex", "PasswordIndex", base.HEX)
	f_emm_reset_reset_value = ProtoField.uint8("CCP_EMM_RESET_PIN.ResetValue", "ResetValue", base.HEX)

	CCP_EMM_RESET_PIN.fields = {f_emm_reset_pin_opcode, f_emm_reset_pin_length, f_emm_reset_password_index, f_emm_reset_reset_value}
	
	function CCP_EMM_RESET_PIN.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x5c then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_EMM_RESET_PIN, buf(0,  2 + length))
		t:add( f_emm_reset_pin_opcode, buf(0, 1))
		t:add( f_emm_reset_pin_length, buf(1, 1))
		t:add( f_emm_reset_password_index, buf(2, 1))
		t:add( f_emm_reset_reset_value, buf(3, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x005c, CCP_EMM_RESET_PIN)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x005c] = {
						["dis"] = ccp_table:get_dissector(0x005c),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	
	--[[
	
	Smart Card  : EMM Reset PASSWORD Control
	
	]]--
	local CCP_EMM_RESET_PASSWORD_CONTROL = Proto("CCP_EMM_RESET_PASSWORD_CONTROL", "RESET Password Control")
	f_emm_reset_password_control_opcode = ProtoField.uint8("CCP_EMM_RESET_PASSWORD_CONTROL.Opcode", "Opcode", base.HEX)
	f_emm_reset_password_control_length = ProtoField.uint8("CCP_EMM_RESET_PASSWORD_CONTROL.Length", "Length", base.DEC)
	f_emm_reset_password_control_reserved = ProtoField.uint8("CCP_EMM_RESET_PASSWORD_CONTROL.Reserved", "Reserved", base.HEX, nil, 0xfc)
	f_emm_reset_password_control_index = ProtoField.uint8("CCP_EMM_RESET_PASSWORD_CONTROL.PasswordIndex", "PINIndex", base.HEX, nil, 0x03)
	f_emm_reset_password_control_value = ProtoField.uint8("CCP_EMM_RESET_PASSWORD_CONTROL.ResetValue", "PINValue", base.HEX)

	CCP_EMM_RESET_PIN.fields = {f_emm_reset_password_control_opcode, f_emm_reset_password_control_length, f_emm_reset_password_control_reserved, f_emm_reset_password_control_index, f_emm_reset_password_control_value}
	
	function CCP_EMM_RESET_PASSWORD_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x5f then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
      
		local t = root:add(CCP_EMM_RESET_PASSWORD_CONTROL, buf(0,  2 + length))
		t:add( f_emm_reset_password_control_opcode, buf(0, 1))
		t:add( f_emm_reset_password_control_length, buf(1, 1))
		t:add( f_emm_reset_password_control_reserved, buf(2, 1))
		t:add( f_emm_reset_password_control_index, buf(2, 1))
		t:add( f_emm_reset_password_control_value, buf(3, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x005f, CCP_EMM_RESET_PASSWORD_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x005f] = {
						["dis"] = ccp_table:get_dissector(0x005f),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	
	--[[
	
	Smart Card  :  Group Vector Filter Opcode
	
	]]--
	
	local CCP_PAR_GROUP_VECTOR_FILTER = Proto("CCP_PAR_GROUP_VECTOR_FILTER", "Group Vector Filter Opcode")
	f_group_vector_opcode = ProtoField.uint8("CCP_PAR_GROUP_VECTOR_FILTER.Opcode", "Opcode", base.HEX)
	f_group_vector_length = ProtoField.uint8("CCP_PAR_GROUP_VECTOR_FILTER.Length", "Length", base.DEC)
	f_group_vector_field = ProtoField.bytes("CCP_PAR_GROUP_VECTOR_FILTER.field", "Group Vector Field", base.HEX)

	CCP_PAR_GROUP_VECTOR_FILTER.fields = {f_group_vector_opcode, f_group_vector_length, f_group_vector_field}
	
	function CCP_PAR_GROUP_VECTOR_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		local buf_len = buf:len()
		if opcode ~= 0xcb then
			return false
		end

		local length = buf(1, 1) : uint()
      
		local t = root:add(CCP_PAR_GROUP_VECTOR_FILTER, buf(0,  2 + length))
		t:add( f_group_vector_opcode, buf(0, 1))
		t:add( f_group_vector_length, buf(1, 1))
		t:add( f_group_vector_field, buf(2, length))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00cb, CCP_PAR_GROUP_VECTOR_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00cb] = {
						["dis"] = ccp_table:get_dissector(0x00cb),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	

	--[[
	
	Smart Card  :  Product Vector Opcode
	
	]]--
	
	local CCP_PAR_PRODUCT_VECTOR = Proto("CCP_PAR_PRODUCT_VECTOR", "Product Vector Opcode")
	local PRODUCT_RECORD = Proto("CA_PRODUCT_RECORD", "Product Record")
	f_product_vector_opcode = ProtoField.uint8("CCP_PAR_PRODUCT_VECTOR.Opcode", "Opcode", base.HEX)
	f_product_vector_length = ProtoField.uint8("CCP_PAR_PRODUCT_VECTOR.Length", "Length", base.DEC)
	f_product_vector_pid = ProtoField.uint16("CCP_PAR_PRODUCT_VECTOR.pid", "Product Id", base.DEC)
	f_product_vector_pstart_data = ProtoField.uint16("CCP_PAR_PRODUCT_VECTOR.start_date", "Start Date", base.DEC)
	f_product_vector_pduration = ProtoField.uint8("CCP_PAR_PRODUCT_VECTOR.duration", "Duration", base.DEC)
	f_product_vector_pstatus = ProtoField.uint8("CCP_PAR_PRODUCT_VECTOR.status", "Status", base.HEX)
	f_product_vector_vec = ProtoField.bytes("CCP_PAR_PRODUCT_VECTOR.vec", "Vector", base.HEX)
	

	CCP_PAR_PRODUCT_VECTOR.fields = {f_product_vector_opcode, f_product_vector_length, f_product_vector_pid, f_product_vector_pstart_data, f_product_vector_pduration, f_product_vector_pstatus, f_product_vector_vec}
	
	function CCP_PAR_PRODUCT_VECTOR.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		local buf_len = buf:len()
		if opcode ~= 0x25 then
			return false
		end

		local length = buf(1, 1) : uint()
		local t = root:add(CCP_PAR_PRODUCT_VECTOR, buf(0,  2+length))
		t:add( f_product_vector_opcode, buf(0, 1))
		t:add( f_product_vector_length, buf(1, 1))
		
		local prod_nr = (length - 32) / 6

		for i=0, prod_nr-1 do
			local st = t:add(PRODUCT_RECORD, buf(2 + i*6, 6))
			st:add(f_product_vector_pid, buf(2+i*6,2))
			st:add(f_product_vector_pstart_data, buf(4+i*6,2))
			st:add(f_product_vector_pstatus, buf(6+i*6, 1))
			st:add(f_product_vector_pstatus, buf(7+i*6, 1))
		end

		t:add(f_product_vector_vec, buf(length -30, 32))
		

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0025, CCP_PAR_PRODUCT_VECTOR)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0025] = {
						["dis"] = ccp_table:get_dissector(0x0025),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[

	ECM Opcode List for IUC
	0x8a	----------						Service Key Opcode
	0x8b	----------						Product Pointer Opcode
	0x8d	----------						Service Data Opcode
	0xc0	----------						Client Type Filter Opcode
	0xc2	----------						Macrovision Control Opcode
	0xc4	----------						Client Bitmap Filter Opcode
	0x95	----------						Content Right Opcode
	0xc6	----------						Blockout Filter Opcode
	0xc7	----------						Spotbeam Filter Opcode
	0x93	----------						VOD Asset ID Opcode
	0x91	----------						IUC Stuffing Opcode
	0x99    ----------                      Time Stamp Opcode
	0x9c    ----------                      Key ID Opcode
	0xa3	----------						Channel Id Opcode
	
	ECM Opcode List for Smart Card
	
	0x40	----------						Date Code Opcode
	0xfc		----------						Time Stamp Filter Opcode
	0xc5	----------						CI Layer Level Filter Opcode
	0x06	----------						Channel Id Opcode
	0xa1	----------						Preview Control Opcode
	0x78	----------						Smart Card Service Key Opcode
	0x79    ----------                      Scrambler Key Opcode
	0x17	----------						Uder Info Opcode
	0xce	----------						Expression Filter Opcode
	0x7b	----------						Extended Scrambler Key Opcode
	0x5d	----------						Macrovision Control Opcode
	0xdc    ----------						IPPV Control Opcode
	0xa2	----------						IPPV Preview Opcode
	0xca	----------						Product ID Filter Opcode
	0xc0 	----------						OVK Version Filter Opcode
	0x44    ----------						Local Session Key Cycling Control Filter Opcode

	--]]

	
---------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------ECM OPCODES FOR IUC-----------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------		
	
--[[
	IUC  :  Service Key Opcode
	]]--
	local CCP_PAR_SERVICE_KEY = Proto("CCP_PAR_SERVICE_KEY", "Service key")
	f_service_key_opcode = ProtoField.uint8("CCP_PAR_SERVICE_KEY.OpCode", "Opcode", base.HEX)
	f_service_key_length = ProtoField.uint16("CCP_PAR_SERVICE_KEY.Length", "Length", base.DEC)
	--3,1
	f_service_key_transform_generation = ProtoField.uint8("CCP_PAR_SERVICE_KEY.TransformGeneration", "TransformGeneration", base.HEX)
	--4,1
	f_service_key_cwdk_version = ProtoField.uint8("CCP_PAR_SERVICE_KEY.CwdkVersion", "CwdkVersion",base.HEX)
	--5,1 0,0
	f_service_key_decoder_identify = ProtoField.uint8("CCP_PAR_SERVICE_KEY.DecoderIdentify", "DecoderIdentify", base.DEC, nil, 0x80)
	--5,1 1,3
	f_service_key_next_key_cipher_mode = ProtoField.uint8("CCP_PAR_SERVICE_KEY.NextKeyCipherMode", "NextKeyCipherMode", base.DEC, nil, 0x70)
	--5,1 4,6
	f_service_key_current_key_cipher_mode = ProtoField.uint8("CCP_PAR_SERVICE_KEY.CurrentKeyCipherMode", "CurrentKeyCipherMode", base.DEC, nil, 0x0e)
	--5,1 7
	f_service_key_next_key_indicator = ProtoField.uint8("CCP_PAR_SERVICE_KEY.NextKeyIndicator", "NextKeyIndicator", base.DEC, nil, 0x01)
	--6,16
	f_service_key_even_cwd = ProtoField.bytes("CCP_PAR_SERVICE_KEY.EvenCwd", "EvenCwd")
	--22,16
	f_service_key_odd_cwd = ProtoField.bytes("CCP_PAR_SERVICE_KEY.OddCwd", "OddCwd")
	--38,16
	f_service_key_cwdk1 = ProtoField.bytes("CCP_PAR_SERVICE_KEY.Cwdk1", "Cwdk1")
	--54,16
	f_service_key_cwdk2 = ProtoField.bytes("CCP_PAR_SERVICE_KEY.Cwdk2", "Cwdk2")


	CCP_PAR_SERVICE_KEY.fields = {f_service_key_opcode, f_service_key_length, f_service_key_transform_generation, f_service_key_cwdk_version,
	f_service_key_decoder_identify, f_service_key_next_key_cipher_mode, f_service_key_current_key_cipher_mode, f_service_key_next_key_indicator, f_service_key_even_cwd, f_service_key_odd_cwd, f_service_key_cwdk1, f_service_key_cwdk2}
	function CCP_PAR_SERVICE_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x8a then
			return false
		end

		local length = buf(1, 1):uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
		
		local cwdk_double_flag = true
		if length == 51 then
			cwdk_double_flag = false
		end
		
		local emergency_mode_flag = false
		if length == 35 then
			emergency_mode_flag = true
		end		

		local t = root:add(CCP_PAR_SERVICE_KEY, buf(0,  2 + length))
		t:add( f_service_key_opcode, buf(0, 1))
		t:add( f_service_key_length, buf(1, 1))
		t:add( f_service_key_transform_generation, buf(2, 1))
		t:add( f_service_key_cwdk_version, buf(3, 1))
		t:add( f_service_key_decoder_identify,buf(4, 1)) --bit:_rshift((bit:_and(buf(4, 1):uint(), 0x80)),7))
		t:add( f_service_key_next_key_cipher_mode,buf(4, 1)) --bit:_rshift(bit:_and(buf(4,1):uint(), 0x70), 4))
		t:add( f_service_key_current_key_cipher_mode,buf(4, 1)) --bit:_rshift(bit:_and(buf(4,1):uint(), 0x0E), 1))
		t:add( f_service_key_next_key_indicator,buf(4, 1)) --bit:_and(buf(4,1):uint(), 0x01))
	    t:add( f_service_key_even_cwd, buf(5, 16))
		t:add( f_service_key_odd_cwd, buf(21, 16))
		if emergency_mode_flag == false then
			t:add( f_service_key_cwdk1, buf(37, 16))
			if cwdk_double_flag == true then
				t:add( f_service_key_cwdk2, buf(53, 16))
			end
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x008a, CCP_PAR_SERVICE_KEY)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x008a] = {
						["dis"] = ccp_table:get_dissector(0x008a),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Product Pointer Opcode
	]]--
	local CCP_PAR_PRODUCT_POINTER = Proto("CCP_PAR_PRODUCT_POINTER", "Product Pointer" )
	--0,1
	f_product_pointer_opcode = ProtoField.uint8("CCP_PAR_PRODUCT_POINTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_product_pointer_length = ProtoField.uint8("CCP_PAR_PRODUCT_POINTER.Length", "Length", base.DEC)
	--2,2
	f_product_pointer_product_referral = ProtoField.uint16("CCP_PAR_PRODUCT_POINTER.ProductReferral", "ProductReferral", base.HEX)
	--4,1
	f_product_pointer_cwdk_number = ProtoField.uint8("CCP_PAR_PRODUCT_POINTER.CwdkNumber", "CwdkNumber",base.DEC)
	--5,1 0,6
	f_product_pointer_rfu = ProtoField.string("CCP_PAR_PRODUCT_POINTER.Rfu", "Rfu")
	--5,1 6,1
	f_product_pointer_previous_cwdk = ProtoField.string("CCP_PAR_PRODUCT_POINTERY.PreviousCwdk", "PreviousCwdk")
	--5,1 7,1
	f_product_pointer_current_cwdk = ProtoField.string("CCP_PAR_PRODUCT_POINTER.CurrentCwdk", "CurrentCwdk")

	CCP_PAR_PRODUCT_POINTER.fields = {f_product_pointer_opcode, f_product_pointer_length, f_product_pointer_product_referral, f_product_pointer_cwdk_number, f_product_pointer_rfu, f_product_pointer_previous_cwdk, f_product_pointer_current_cwdk}
	function CCP_PAR_PRODUCT_POINTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x8b then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_PRODUCT_POINTER, buf(0,  1 + length))
		t:add( f_product_pointer_opcode, buf(0, 1))
		t:add( f_product_pointer_length, buf(1, 1))
		t:add( f_product_pointer_product_referral, buf(2, 2))
		t:add( f_product_pointer_cwdk_number, buf(4, 1))
		t:add( f_product_pointer_rfu, bit:_rshift((bit:_and(buf(5, 1):uint(), 0xFC)),2))
		t:add( f_product_pointer_previous_cwdk, bit:_rshift(bit:_and(buf(5,1):uint(), 0x02), 1))
		t:add( f_product_pointer_current_cwdk, bit:_and(buf(5,1):uint(), 0x01))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x008b, CCP_PAR_PRODUCT_POINTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x008b] = {
						["dis"] = ccp_table:get_dissector(0x008b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Service Data Opcode
	]]--
	local CCP_PAR_SERVICE_DATA = Proto("CCP_PAR_SERVICE_DATA", "Service Data")
	--0,1
	f_service_data_opcode = ProtoField.uint8("CCP_PAR_SERVICE_DATA.Opcode", "Opcode", base.HEX)
	--1,1
	f_service_data_length = ProtoField.uint8("CCP_PAR_SERVICE_DATA.Length", "Length", base.DEC)
	--2,1
	f_service_data_message_type = ProtoField.uint8("CCP_PAR_SERVICE_DATA.Message_Type", "Message Type", base.DEC,  {[0] = "CIPlusURI", [2] = "ECP", [3]= "SKELP", [5] = "DRMPVRTrickMode"})
	--3,3
	f_service_data = ProtoField.uint8("CCP_PAR_SERVICE_DATA.Data", "Data", base.DEC)
	f_service_data_enhanced_copy_protection = ProtoField.bytes("CCP_PAR_SERVICE_DATA.Enchanced_Copy_protection", "Enhanced Copy Protection Message", base.HEX)
	f_service_data_drm_pvr_trick_mode = ProtoField.bytes("CCP_PAR_SERVICE_DATA.trickmode", "DRM/PVR Trick Mode", base.HEX)

	--Protocol Version, 8 bits
	f_service_data_protocol_version = ProtoField.uint8("CCP_PAR_SERVICE_DATA.protocol_version", "Protocol Version", base.DEC)
	
	--APS copy control info, 2 bits
	f_service_data_aps_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_aps_cci", "APS Copy Control Info(2bits)", base.DEC, nil, 0xc000)
	
	--EMI copy control info, 2 bits
	f_service_data_emi_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_emi_cci", "EMI Copy Control Info(2bits)", base.DEC,nil, 0x3000)
	
	--ICT Copy control info, 1 bit
	f_service_data_ict_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_ict_cci", "ICT Copy Control Info(1bits)", base.DEC, nil, 0x0800)
	
	--RCT copy control info, 1 bit.     
	f_service_data_rct_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_rct_cci", "RCT Copy Control Info(1bits)", base.DEC, nil, 0x0400)
	
	--reserved for future use for URI Version1, 4 bit
	f_service_data_rfu_version1 = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_rct_cci", "Reserved for future use for Version1 (4 bit)", base.DEC, nil, 0x03c0)
	
	--RL copy control info for URI Version1, 6 bits
	f_service_data_rl_cci_version1 = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_rl_cci", "RL Copy Control Info for Version 1 (6 bits)", base.DEC,nil, 0x003f)
	
	--reserved for future use, 1 bit
	f_service_data_rfu = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_rct_cci", "Reserved for future use for version 2,3 (1 bit)", base.DEC, nil, 0x0200)
	
	--DOT copy control info, 1 bit.    
	f_service_data_dot_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_dot_cci", "DOT Copy Control Info for version 2,3 (1 bit)", base.DEC, nil, 0x0100)
	
    --RL copy control info, 8 bits,     
	f_service_data_rl_cci = ProtoField.uint16("CCP_PAR_SERVICE_DATA.protocol_rl_cci", "RL Copy Control Info for version 2,3 (8 bits)", base.DEC,nil, 0x00ff)

	--trick mode control info, 1 bit.   
	f_service_data_trick_mci = ProtoField.uint8("CCP_PAR_SERVICE_DATA.protocol_trick_mci", "Trick mode control info, 1 bit", base.DEC, nil, 0x80)
    
	--Reserved for future use, 39 bits for version 3
	f_service_data_rfu1_1 = ProtoField.uint8("f_service_data_rfu1", "Reserved for future use_1, 7 bits", base.HEX, nil, 0x7f)	
	f_service_data_rfu1_2 = ProtoField.uint32("f_service_data_rfu1", "Reserved for future use_2, 32 bits", base.HEX, nil, 0xffffffff)	

	--Enhanced Copy Protection
	--Global PVR Flag
	f_service_data_enhanced_copy_protection_global_pvr_allowable = ProtoField.uint8("CCP_PAR_SERVICE_DATA.global_pvr_allowable", "Global PVR", base.HEX,nil,0x80)
	--Image Constraint
	f_service_data_enhanced_copy_protection_image_contraint = ProtoField.uint8("CCP_PAR_SERVICE_DATA.image_contraint", "Image Constraint", base.HEX,nil,0x40)	
	--Stream to unmanaged
	f_service_data_enhanced_copy_protection_stream_to_unmanaged = ProtoField.uint8("CCP_PAR_SERVICE_DATA.stream_to_unmanaged", "Stream To Unmanaged", base.HEX,nil,0x20)	
	--Airplay
	f_service_data_enhanced_copy_protection_airplay = ProtoField.uint8("CCP_PAR_SERVICE_DATA.airplay", "AirPlay", base.HEX,nil,0x10)	
	--Reserved1
	f_service_data_enhanced_copy_protection_reserved = ProtoField.uint8("CCP_PAR_SERVICE_DATA.reserved", "Reserved", base.HEX,nil,0x0f)	
	--HDCP
	f_service_data_enhanced_copy_protection_hdcp = ProtoField.uint8("CCP_PAR_SERVICE_DATA.hdcp", "HDCP", base.HEX,nil,0x80)	
	--HDCP 2.2+
	f_service_data_enhanced_copy_protection_hdcp_22plus = ProtoField.uint8("CCP_PAR_SERVICE_DATA.hdcp_22plus", "HDCP 2.2+", base.HEX,nil,0x70)	
	--PlayReady
	f_service_data_enhanced_copy_protection_playready = ProtoField.uint8("CCP_PAR_SERVICE_DATA.playready", "Play Ready", base.HEX,nil,0x08)	
	--SKE
	f_service_data_enhanced_copy_protection_ske = ProtoField.uint8("CCP_PAR_SERVICE_DATA.ske", "SKE", base.HEX,nil,0x04)	
	--DTCP-IP Clear
	f_service_data_enhanced_copy_protection_dtcp_ip_clear = ProtoField.uint8("CCP_PAR_SERVICE_DATA.dtcp_ip_clear", "DTCP-IP Clear", base.HEX,nil,0x02)
	--DTCP-IP DTCP
	f_service_data_enhanced_copy_protection_dtcp_ip_dtcp = ProtoField.uint8("CCP_PAR_SERVICE_DATA.dtcp_ip_dtcp", "DTCP-IP DTCP", base.HEX,nil,0x01)

	--DVM PVR Trick Mode
	--Trick Mode control
	f_service_data_trick_mode_control = ProtoField.uint8("CCP_PAR_SERVICE_DATA.trick_mode_control", "Trick Mode Control", base.HEX,nil,0xE0)	
	--Trick Mode control Reserved bit
	f_service_data_trick_mode_control_rfu = ProtoField.uint8("CCP_PAR_SERVICE_DATA.trick_mode_control_rfu", "Trick mode control reserved", base.HEX,nil,0x1C)	
	--Reserved For Future Use
	f_service_data_rfu1 = ProtoField.uint8("CCP_PAR_SERVICE_DATA.rfu1", "Reserved Bit For Future", base.HEX,nil,0x03)	
	--Reserved For Future Use
	f_service_data_rfu2 = ProtoField.uint8("CCP_PAR_SERVICE_DATA.rfu2", "Reserved Byte For Future", base.HEX)	

	CCP_PAR_SERVICE_DATA.fields = {f_service_data_opcode, f_service_data_length, f_service_data, f_service_data_message_type, f_service_data_protocol_version, f_service_data_dot_cci,
								f_service_data_aps_cci, f_service_data_emi_cci, f_service_data_ict_cci, f_service_data_rct_cci, f_service_data_rfu_version1,f_service_data_rl_cci_version1,
								f_service_data_rfu, f_service_data_rl_cci, f_service_data_trick_mci, f_service_data_rfu1_1, f_service_data_rfu1_2,f_service_data_enhanced_copy_protection, 
								f_service_data_enhanced_copy_protection_global_pvr_allowable, f_service_data_enhanced_copy_protection_image_contraint,
								f_service_data_enhanced_copy_protection_stream_to_unmanaged, f_service_data_enhanced_copy_protection_airplay, f_service_data_enhanced_copy_protection_reserved, 
								f_service_data_enhanced_copy_protection_hdcp, f_service_data_enhanced_copy_protection_hdcp_22plus, f_service_data_enhanced_copy_protection_playready, 
								f_service_data_enhanced_copy_protection_ske, f_service_data_enhanced_copy_protection_dtcp_ip_clear, f_service_data_enhanced_copy_protection_dtcp_ip_dtcp,
								f_service_data_drm_pvr_trick_mode, f_service_data_trick_mode_control, f_service_data_trick_mode_control_rfu, f_service_data_rfu1, f_service_data_rfu2}
	
	function CCP_PAR_SERVICE_DATA.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x8d then
			return false
		end

		local length = buf(1, 1) : uint()
             	local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
		
		local message_type = buf(2,1):uint()
		local t = root:add(CCP_PAR_SERVICE_DATA, buf(0,  2 + length))
		t:add( f_service_data_opcode, buf(0, 1))
		t:add( f_service_data_length, buf(1, 1))
		
		local offset = 2
		while offset < buf_len do
			t:add( f_service_data_message_type, buf(offset, 1))
			local message_type = buf(offset,1):uint()
			local message_length = buf(offset + 1,1):uint()

			offset = offset + 1
			if message_type == 0 then --CI+
			    st = t:add(f_user_info_ciplus, buf(offset, length-1))
				st:add(f_service_data_protocol_version, buf(offset, 1))
			    st:add(f_service_data_aps_cci, buf(offset+1,2))
				st:add(f_service_data_emi_cci, buf(offset+1,2))
				st:add(f_service_data_ict_cci, buf(offset+1,2))
				
				local emi = tostring(bit:_and(buf(offset+1,1):uint(),48))
				
				if buf(offset, 1):uint() == 0x03 then -- if protocol version is 0x03
				    st:add(f_service_data_rct_cci, buf(offset+1,2))
					st:add(f_service_data_rfu, buf(offset+1,2))
					st:add(f_service_data_dot_cci, buf(offset+1,2))
					st:add(f_service_data_rl_cci, buf(offset+1,2))
					
					st:add(f_service_data_trick_mci, buf(offset+3,1))
					st:add(f_service_data_rfu1_1, buf(offset+3,1))
					st:add(f_service_data_rfu1_2, buf(offset+4,4))

	            elseif buf(offset, 1):uint() == 0x02 then -- if protocol version is 0x02
				    st:add(f_service_data_rct_cci, buf(offset+1,2))
					st:add(f_service_data_rfu, buf(offset+1,2))
					st:add(f_service_data_dot_cci, buf(offset+1,2))
					st:add(f_service_data_rl_cci, buf(offset+1,2))

                else -- if protocol version is 0x01
				    st:add(f_service_data_rct_cci, buf(offset+1,2))
					st:add(f_service_data_rfu_version1, buf(offset+1,2))			
					st:add(f_service_data_rl_cci_version1, buf(offset+1,2))
				end
				
				offset = offset + buf_len

			elseif message_type == 2 then --Enhanced Copy Protection
				st = t:add(f_service_data_enhanced_copy_protection, buf(offset, length - 1))
				st:add(f_service_data_enhanced_copy_protection_global_pvr_allowable, buf(offset, 1))
				st:add(f_service_data_enhanced_copy_protection_image_contraint, buf(offset,1))
				st:add(f_service_data_enhanced_copy_protection_stream_to_unmanaged, buf(offset,1))
				st:add(f_service_data_enhanced_copy_protection_airplay, buf(offset,1))
				st:add(f_service_data_enhanced_copy_protection_reserved, buf(offset,1))
				if length > 2 then
					st:add(f_service_data_enhanced_copy_protection_hdcp, buf(offset+1,1))
					st:add(f_service_data_enhanced_copy_protection_hdcp_22plus, buf(offset+1,1))
					st:add(f_service_data_enhanced_copy_protection_playready, buf(offset+1,1))
					st:add(f_service_data_enhanced_copy_protection_ske, buf(offset+1,1))
					st:add(f_service_data_enhanced_copy_protection_dtcp_ip_clear, buf(offset+1,1))
					st:add(f_service_data_enhanced_copy_protection_dtcp_ip_dtcp, buf(offset+1,1))
				end
				offset = offset + buf_len

			elseif message_type == 5 then -- DRM/PVR Trick Mode
				st = t:add(f_service_data_drm_pvr_trick_mode, buf(offset + 1, message_length))
				st:add(f_service_data_trick_mode_control, buf(offset+1,1))
				st:add(f_service_data_trick_mode_control_rfu, buf(offset+1,1))
				st:add(f_service_data_rfu1, buf(offset+1,1))
				st:add(f_service_data_rfu2, buf(offset+2,2))
				
			else
				t:add(f_service_data, buf(offset, length))
			end
			
			offset = offset + buf_len
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x008d, CCP_PAR_SERVICE_DATA)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x008d] = {
						["dis"] = ccp_table:get_dissector(0x008d),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Client Filter Opcode
	]]--
	local CCP_PAR_CLIENT_FILTER = Proto("CCP_PAR_CLIENT_FILTER", "client filter")
	--0,1
	f_client_filter_opcode = ProtoField.uint8("CCP_PAR_CLIENT_FILTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_client_filter_length = ProtoField.uint8("CCP_PAR_CLIENT_FILTER.Length", "Length", base.DEC)
	--2,1
	f_client_filter_criteria = ProtoField.uint8("CCP_PAR_CLIENT_FILTER.Criteria", "Criteria", base.DEC)

	CCP_PAR_CLIENT_FILTER.fields = {f_client_filter_opcode, f_client_filter_length, f_client_filter_criteria}
	function CCP_PAR_CLIENT_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc0 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_CLIENT_FILTER, buf(0,  2 + length))
		t:add( f_client_filter_opcode, buf(0, 1))
		t:add( f_client_filter_length, buf(1, 1))
		t:add( f_client_filter_criteria, buf(2, 1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c0, CCP_PAR_CLIENT_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c0] = {
						["dis"] = ccp_table:get_dissector(0x00c0),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	
	--[[
	IUC  :  Macrovision control Opcode
	]]--
	local CCP_PAR_MACROVISION_CONTROL = Proto("CCP_PAR_MACROVISION_CONTROL", "Macrovision Control")
	--0,1
	f_macrovision_Control_opcode = ProtoField.uint8("CCP_PAR_MACROVISION_CONTROL.Opcode", "Opcode", base.HEX)
	--1,1
	f_macrovision_Control_length = ProtoField.uint8("CCP_PAR_MACROVISION_CONTROL.Length", "Length", base.DEC)
	--2,1 0,6
	f_macrovision_Control_bits = ProtoField.string("CCP_PAR_MACROVISION_CONTROL.Bits", "Bits")
	--2,1 6,2
	f_macrovision_Control_reserved = ProtoField.string("CCP_PAR_MACROVISION_CONTROL.Reserved", "Reserved")

	CCP_PAR_MACROVISION_CONTROL.fields = {f_macrovision_Control_opcode, f_macrovision_Control_length, f_macrovision_Control_bits, f_macrovision_Control_reserved}
	function CCP_PAR_MACROVISION_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc2 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_MACROVISION_CONTROL, buf(0,  2 + length))
		t:add( f_macrovision_Control_opcode, buf(0, 1))
		t:add( f_macrovision_Control_length, buf(1, 1))
		t:add( f_macrovision_Control_bits, bit:_rshift((bit:_and(buf(2, 1):uint(), 0xFC)),2))
		t:add( f_macrovision_Control_reserved, bit:_and((buf(2, 1)):uint(), 0x03))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c2, CCP_PAR_MACROVISION_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c2] = {
						["dis"] = ccp_table:get_dissector(0x00c2),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Bitmap filter Opcode
	]]--
	local CCP_PAR_BITMAP_FILTER = Proto("CCP_PAR_BITMAP_FILTER", "Bitmap Filter")
	--0,1
	f_bitmap_filter_opcode = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_bitmap_filter_length = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.Length", "Length", base.DEC)
	--2,1 0,6
	f_bitmap_filter_cluster_size = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.ClusterSize", "ClusterSize", base.DEC, nil, 0xc0)
	--2,1 6,2
	f_bitmap_filter_cluster_bitmap= Proto("CCP_PAR_BITMAP_FILTER.ClusterBitmap", "ClusterBitmap")
	f_bitmap_filter_cluster_bitmap_b0 = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.ClusterBitmap.bit0", "Secure Chipset 3DES", base.HEX, nil ,0x1)
	f_bitmap_filter_cluster_bitmap_b1 = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.ClusterBitmap.bit1", "Security ID", base.HEX, nil ,0x2)
	f_bitmap_filter_cluster_bitmap_b2 = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.ClusterBitmap.bit2", "Secure Chipset AES", base.HEX, nil ,0x4)
	f_bitmap_filter_cluster_bitmap_b3_5 = ProtoField.uint8("CCP_PAR_BITMAP_FILTER.ClusterBitmap.bit3_5", "RFU", base.HEX, nil ,0x38)

	CCP_PAR_BITMAP_FILTER.fields = {f_bitmap_filter_opcode, f_bitmap_filter_length, f_bitmap_filter_cluster_size,
									f_bitmap_filter_cluster_bitmap_b3_5, f_bitmap_filter_cluster_bitmap_b2,
									f_bitmap_filter_cluster_bitmap_b1, f_bitmap_filter_cluster_bitmap_b0}
	function CCP_PAR_BITMAP_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc4 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_BITMAP_FILTER, buf(0,  2 + length))
		t:add( f_bitmap_filter_opcode, buf(0, 1))
		t:add( f_bitmap_filter_length, buf(1, 1))
		t:add( f_bitmap_filter_cluster_size, buf(2, 1))
		tt = t:add( f_bitmap_filter_cluster_bitmap, buf(2, 1))
		tt:add(f_bitmap_filter_cluster_bitmap_b3_5, buf(2,1))
		tt:add(f_bitmap_filter_cluster_bitmap_b2, buf(2,1))
		tt:add(f_bitmap_filter_cluster_bitmap_b1, buf(2,1))
		tt:add(f_bitmap_filter_cluster_bitmap_b0, buf(2,1))
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x01c4, CCP_PAR_BITMAP_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x01c4] = {
						["dis"] = ccp_table:get_dissector(0x01c4),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Content rights Opcode
	]]--
	local CCP_PAR_CONTENT_RIGHTS = Proto("CCP_PAR_CONTENT_RIGHTS", "Content Rights")
	--0,1
	f_content_rights_opcode = ProtoField.uint8("CCP_PAR_CONTENT_RIGHTS.Opcode", "Opcode", base.HEX)
	--1,1
	f_content_rights_length = ProtoField.uint8("CCP_PAR_CONTENT_RIGHTS.Length", "Length", base.DEC)
	--2,1 0,2
	f_content_rights_window_type = ProtoField.string("CCP_PAR_CONTENT_RIGHTS.WindowType", "WindowType")
	--2,1 2,4
	f_content_rights_reserved1 = ProtoField.string("CCP_PAR_CONTENT_RIGHTS.Reserved1", "Reserved1")
	--2,1 6,1
	f_content_rights_sequence_marker = ProtoField.string("CCP_PAR_CONTENT_RIGHTS.SequenceMarker", "SequenceMarker")
	--2,1 7,1
	f_content_rights_reserved2 = ProtoField.string("CCP_PAR_CONTENT_RIGHTS.Reserved2", "Reserved2")
	--3,4
	f_content_rights_duration_time= ProtoField.bytes("CCP_PAR_CONTENT_RIGHTS.DurationTime", "DurationTime")

	CCP_PAR_CONTENT_RIGHTS.fields = {f_content_rights_opcode, f_content_rights_length, f_content_rights_window_type, f_content_rights_reserved1, f_content_rights_sequence_marker, f_content_rights_reserved2, f_content_rights_duration_time}
	function CCP_PAR_CONTENT_RIGHTS.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x95 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_CONTENT_RIGHTS, buf(0,  2 + length))
		t:add( f_content_rights_opcode, buf(0, 1))
		t:add( f_content_rights_length, buf(1, 1))
		t:add( f_content_rights_window_type, bit:_rshift((bit:_and(buf(2, 1):uint(), 0xC0)),6))
		t:add( f_content_rights_reserved1, bit:_rshift((bit:_and((buf(2, 1)):uint(), 0x3C)),2))
		t:add( f_content_rights_sequence_marker, bit:_rshift((bit:_and((buf(2, 1)):uint(), 0x02)),1))
		t:add( f_content_rights_reserved2, bit:_and((buf(2, 1)):uint(), 0x01))
		t:add( f_content_rights_duration_time, buf(3, 4))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0095, CCP_PAR_CONTENT_RIGHTS)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0095] = {
						["dis"] = ccp_table:get_dissector(0x0095),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Blackout filter Opcode
	]]--
	local CCP_PAR_BLACKOUT_FILTER = Proto("CCP_PAR_BLACKOUT_FILTER", "Blackout Filter")
	--0,1
	f_blackout_filter_opcode = ProtoField.uint8("CCP_PAR_BLACKOUT_FILTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_blackout_filter_length = ProtoField.uint8("CCP_PAR_BLACKOUT_FILTER.Length", "Length", base.DEC)
	--2,2
	f_blackout_filter_product_id = ProtoField.bytes("CCP_PAR_BLACKOUT_FILTER.ProductId", "ProductId")

	CCP_PAR_BLACKOUT_FILTER.fields = {f_blackout_filter_opcode, f_blackout_filter_length, f_blackout_filter_product_id}
	function CCP_PAR_BLACKOUT_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc6 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_BLACKOUT_FILTER, buf(0,  2 + length))
		t:add( f_blackout_filter_opcode, buf(0, 1))
		t:add( f_blackout_filter_length, buf(1, 1))
		t:add( f_blackout_filter_product_id, buf(2, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2+ length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c6, CCP_PAR_BLACKOUT_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c6] = {
						["dis"] = ccp_table:get_dissector(0x00c6),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	--[[
	IUC  :  Spotbeam filter Opcode
	]]--
	local CCP_PAR_SPOTBEAM_FILTER = Proto("CCP_PAR_SPOTBEAM_FILTER", "Spotbeam Filter")
	--0,1
	f_spotbeam_filter_opcode = ProtoField.uint8("CCP_PAR_SPOTBEAM_FILTER.Opcode", "Opcode", base.HEX)
	--1,1
	f_spotbeam_filter_length = ProtoField.uint8("CCP_PAR_SPOTBEAM_FILTER.Length", "Length", base.DEC)
	--2,2
	f_spotbeam_filter_product_id = ProtoField.bytes("CCP_PAR_SPOTBEAM_FILTER.ProductId", "ProductId")

	CCP_PAR_SPOTBEAM_FILTER.fields = {f_spotbeam_filter_opcode, f_spotbeam_filter_length, f_spotbeam_filter_product_id}
	function CCP_PAR_SPOTBEAM_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc7 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_SPOTBEAM_FILTER, buf(0,  2 + length))
		t:add( f_spotbeam_filter_opcode, buf(0, 1))
		t:add( f_spotbeam_filter_length, buf(1, 1))
		t:add( f_spotbeam_filter_product_id, buf(2, 2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00c7, CCP_PAR_SPOTBEAM_FILTER)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00c7] = {
						["dis"] = ccp_table:get_dissector(0x00c7),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	
	--[[
	
	IUC  :  VOD Asser ID ECM Opcode
	
	--]]
	
	local CCP_PAR_ECM_VOD_ASSET_ID = Proto("CCP_PAR_ECM_VOD_ASSET_ID", "VOD Asset ID")
	--0,1
	f_vod_asset_id_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_VOD_ASSET_ID.Opcode", "Opcode", base.HEX)
	--1,1
	f_vod_asset_id_ecm_length = ProtoField.uint8("CCP_PAR_ECM_VOD_ASSET_ID.Length", "Length", base.DEC)
	--2,2
	f_vod_asset_id_ecm_asset_id = ProtoField.uint16("CCP_PAR_ECM_VOD_ASSET_ID.Asset_Id", "Asset Id", base.DEC)

	CCP_PAR_ECM_VOD_ASSET_ID.fields = {f_vod_asset_id_ecm_opcode, f_vod_asset_id_ecm_length, f_vod_asset_id_ecm_asset_id}
	function CCP_PAR_ECM_VOD_ASSET_ID.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x93 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_ECM_VOD_ASSET_ID, buf(0,  2 + length))
		t:add( f_vod_asset_id_ecm_opcode, buf(0, 1))
		t:add( f_vod_asset_id_ecm_length, buf(1, 1))
		t:add( f_vod_asset_id_ecm_asset_id, buf(2, 4))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0093, CCP_PAR_ECM_VOD_ASSET_ID)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0093] = {
						["dis"] = ccp_table:get_dissector(0x0093),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	

	--[[
	
	IUC  :  Time Stamp Opcode
	
	--]]
	local CCP_PAR_TIME_STAMP = Proto("CCP_PAR_TIME_STAMP", "Time Stamp")
	f_time_stamp_opcode = ProtoField.uint8("CCP_PAR_TIME_STAMP.Opcode", "Opcode", base.HEX)
	f_time_stamp_length = ProtoField.uint16("CCP_PAR_TIME_STAMP.Length", "Length", base.DEC)
	f_time_stamp_rfu = ProtoField.uint8("CCP_PAR_TIME_STAMP.Rfu", "Rfu", base.DEC)
	f_time_stamp_starttime = ProtoField.bytes("CCP_PAR_TIME_STAMP.Starttime", "Starttime")

	CCP_PAR_TIME_STAMP.fields = {f_time_stamp_opcode, f_time_stamp_length, f_time_stamp_rfu, f_time_stamp_starttime}
	
	function CCP_PAR_TIME_STAMP.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x99 then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_TIME_STAMP, buf(0,  2 + length))
		t:add( f_time_stamp_opcode, buf(0, 1))
		t:add( f_time_stamp_length, buf(1, 1))
		t:add( f_time_stamp_rfu, buf(2, 1))
		t:add( f_time_stamp_starttime, buf(3, 4))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x0099, CCP_PAR_TIME_STAMP)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0099] = {
						["dis"] = ccp_table:get_dissector(0x0099),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	
	IUC  :  Key ID Opcode
	
	--]]
	local CCP_PAR_KEY_ID = Proto("CCP_PAR_KEY_ID", "Key Identifier")
	f_key_id_opcode = ProtoField.uint8("CCP_PAR_KEY_ID.Opcode", "Opcode", base.HEX)
	f_key_id_length = ProtoField.uint16("CCP_PAR_KEY_ID.Length", "Length", base.DEC)
	f_key_id_rfu = ProtoField.uint8("CCP_PAR_KEY_ID.Rfu", "Rfu", base.DEC)
	f_key_id_KeyIdentifier = ProtoField.bytes("CCP_PAR_KEY_ID.KeyIdentifier", "KeyIdentifier")

	CCP_PAR_KEY_ID.fields = {f_key_id_opcode, f_key_id_length, f_key_id_rfu, f_key_id_KeyIdentifier}
	
	function CCP_PAR_KEY_ID.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x9c then
			return false
		end

		local length = buf(1, 1) : uint()
             local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_KEY_ID, buf(0,  2 + length))
		t:add( f_key_id_opcode, buf(0, 1))
		t:add( f_key_id_length, buf(1, 1))
		t:add( f_key_id_rfu, buf(2, 1))
		t:add( f_key_id_KeyIdentifier, buf(3, 1))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end		

		return true
    end
	ccp_table:add(0x009c, CCP_PAR_KEY_ID)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x009c] = {
						["dis"] = ccp_table:get_dissector(0x009c),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	--[[
	
	IUC  :  Channel ID
	
	--]]
	local CCP_PAR_ECM_CCA_CHANNEL_ID = Proto("CCP_PAR_ECM_CCA_CHANNEL_ID", "Cca Channel ID")
	f_cca_channel_id_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_CCA_CHANNEL_ID.opcode", "Opcode", base.HEX)
	f_cca_channel_id_ecm_length = ProtoField.uint16("CCP_PAR_ECM_CCA_CHANNEL_ID.length", "Lenngth", base.DEC)
	f_cca_channel_id_ecm_channel_id = ProtoField.uint16("CCP_PAR_ECM_CCA_CHANNEL_ID.channel_id", "Channel ID", base.HEX)
	f_cca_channel_id_ecm_sequence_number = ProtoField.uint16("CCP_PAR_ECM_CCA_CHANNEL_ID.sequence_number", "Sequence Number", base.DEC)
	
	CCP_PAR_ECM_CCA_CHANNEL_ID.fields = {f_cca_channel_id_ecm_opcode, f_cca_channel_id_ecm_length, f_cca_channel_id_ecm_channel_id, f_cca_channel_id_ecm_sequence_number}
	
	function CCP_PAR_ECM_CCA_CHANNEL_ID.dissector(buf, pkt ,root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xa3 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 2 then
			return false
		end	
		
		local t = root:add(CCP_PAR_ECM_CCA_CHANNEL_ID, buf(0,  2 + length))
		t:add(f_cca_channel_id_ecm_opcode, buf(0,1))
		t:add(f_cca_channel_id_ecm_length, buf(1,1))
		t:add(f_cca_channel_id_ecm_channel_id, buf(2,2))
		t:add(f_cca_channel_id_ecm_sequence_number, buf(4,1))
	
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	ccp_table:add(0x01a3, CCP_PAR_ECM_CCA_CHANNEL_ID)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x01a3] = {
						["dis"] = ccp_table:get_dissector(0x01a3),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
---------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------ECM OPCODES FOR SMART CARD----------------------------------------
---------------------------------------------------------------------------------------------------------------------------------	

--[[
	
	0x40	----------						Date Code Opcode
	0xfc	----------						Time Stamp Filter Opcode
	0xc5	----------						CI Layer Level Filter Opcode
	0x06	----------						Channel Id Opcode
	0xa1	----------						Preview Control Opcode
	0x78	----------						Service Key Opcode
	0x79	----------						Scrambler Key Opcode
	0x17	----------						User Info Opcode
	0xce	----------						Expression Filter Opcode
	0x7b	----------						Extended Scrambler Key Opcode
	0xba	----------						Content Rights Opcode
	0xdc	----------						IPPV Control Opcode
	0xa2	----------						IPPV Preview Opcode
	0xca	----------						Product ID Filter Opcode
	0x44    ----------						Local Session Key Cycling Control Filter Opcode

-]]


--[[

Smart Card  :  Date Code Opcode

--]]

	local CCP_PAR_ECM_SC_DATE_CDOE = Proto("CCP_PAR_ECM_SC_DATE_CDOE" , "Date Code")
	f_date_code_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_DATE_CDOE.opcode", "Opcode", base.HEX)
	f_date_code_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_DATE_CDOE.length", "Length", base.DEC)
	f_date_code_ecm_datecode = ProtoField.uint16("CCP_PAR_ECM_SC_DATE_CDOE.datecode", "Date Code", base.DEC)

	CCP_PAR_ECM_SC_DATE_CDOE.fields = {f_date_code_ecm_opcode, f_date_code_ecm_length, f_date_code_ecm_datecode}

	function CCP_PAR_ECM_SC_DATE_CDOE.dissector(buf, pkt ,root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x40 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
	
		local t = root:add(CCP_PAR_ECM_SC_DATE_CDOE, buf(0,  2 + length))
		t:add(f_date_code_ecm_opcode, buf(0,1))
		t:add(f_date_code_ecm_length, buf(1,1))
		t:add(f_date_code_ecm_datecode, buf(2,2))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
		
	end
	ccp_table:add(0x0040, CCP_PAR_ECM_SC_DATE_CDOE)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0040] = {
						["dis"] = ccp_table:get_dissector(0x0040),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

--[[

Smart Card  :  Time Stamp Filter Opcode

--]]

	local CCP_PAR_ECM_SC_TIME_STAMP_FILTER = Proto("CCP_PAR_ECM_SC_TIME_FILTER", "Time Stamp Filter")
	f_time_stamp_filter_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_TIME_FILTER.opcode", "Opcode", base.HEX)
	f_time_stamp_filter_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_TIME_FILTER.length", "Length", base.DEC)
	f_time_stamp_filter_ecm_time_stamp = ProtoField.bytes("CCP_PAR_ECM_SC_TIME_FILTER", "Time Stamp", base.HEX)
	
	CCP_PAR_ECM_SC_TIME_STAMP_FILTER.fields = {f_time_stamp_filter_ecm_opcode, f_time_stamp_filter_ecm_length, f_time_stamp_filter_ecm_time_stamp}
	
	function CCP_PAR_ECM_SC_TIME_STAMP_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xfc then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
	
		local t = root:add(CCP_PAR_ECM_SC_TIME_STAMP_FILTER, buf(0,  2 + length))
		t:add(f_time_stamp_filter_ecm_opcode, buf(0,1))
		t:add(f_time_stamp_filter_ecm_length, buf(1,1))
		t:add(f_time_stamp_filter_ecm_time_stamp, buf(2,4))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	
	end
	ccp_table:add(0x00fc, CCP_PAR_ECM_SC_TIME_STAMP_FILTER)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00fc] = {
						["dis"] = ccp_table:get_dissector(0x00fc),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

	Smart Card  :  CI Layer Level Filter Opcode

--]]
	
	local CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER = Proto("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER", "CI Layer Level Filter")
	f_ci_layer_level_filter_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.opcode", "Opcode", base.HEX)
	f_ci_layer_level_filter_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.length", "Length", base.DEC)
	f_ci_layer_level_filter_ecm_enforce_ipr = ProtoField.uint8("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.enforce_ipr", "Enforce IPR", base.HEX, nil, 0x80)
	f_ci_layer_level_filter_ecm_security_level = ProtoField.uint8("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.security_level", "Security Level", base.HEX, nil, 0x70)
	f_ci_layer_level_filter_ecm_rfu = ProtoField.uint8("CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER", "RFU", base.HEX, nil, 0x0f)
	
	CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.fields = {f_ci_layer_level_filter_ecm_opcode, f_ci_layer_level_filter_ecm_length, f_ci_layer_level_filter_ecm_enforce_ipr,
																						f_ci_layer_level_filter_ecm_security_level, f_ci_layer_level_filter_ecm_rfu
																						}
																				
	function CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc5 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	
		
		local t = root:add(CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER, buf(0,  2 + length))
		t:add(f_ci_layer_level_filter_ecm_opcode, buf(0,1))
		t:add(f_ci_layer_level_filter_ecm_length, buf(1,1))
		t:add(f_ci_layer_level_filter_ecm_enforce_ipr, buf(2,1))
		t:add(f_ci_layer_level_filter_ecm_security_level, buf(2,1))
		t:add(f_ci_layer_level_filter_ecm_rfu, buf(2,1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	
	end
	ccp_table:add(0x02c5, CCP_PAR_ECM_SC_CI_LAYER_LEVEL_FILTER)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x02c5] = {
						["dis"] = ccp_table:get_dissector(0x02c5),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

Smart Card  :  Channel Id Opcode

--]]

	local CCP_PAR_ECM_SC_CHANNEL_ID = Proto("CCP_PAR_ECM_SC_CHANNEL_ID", "Channel ID")
	f_channel_id_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_CHANNEL_ID.opcode", "Opcode", base.HEX)
	f_channel_id_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_CHANNEL_ID.length", "Lenngth", base.DEC)
	f_channel_id_ecm_channel_id = ProtoField.uint16("CCP_PAR_ECM_SC_CHANNEL_ID.channel_id", "Channel ID", base.DEC)
	f_channel_id_ecm_sequence_number = ProtoField.uint16("CCP_PAR_ECM_SC_CHANNEL_ID.sequence_number", "Sequence Number", base.DEC)
	
	CCP_PAR_ECM_SC_CHANNEL_ID.fields = {f_channel_id_ecm_opcode, f_channel_id_ecm_length, f_channel_id_ecm_channel_id, f_channel_id_ecm_sequence_number}
	
	function CCP_PAR_ECM_SC_CHANNEL_ID.dissector(buf, pkt ,root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x06 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	
		
		local t = root:add(CCP_PAR_ECM_SC_CHANNEL_ID, buf(0,  2 + length))
		t:add(f_channel_id_ecm_opcode, buf(0,1))
		t:add(f_channel_id_ecm_length, buf(1,1))
		t:add(f_channel_id_ecm_channel_id, buf(2,2))
		t:add(f_channel_id_ecm_sequence_number, buf(4,1))
	
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	ccp_table:add(0x0006, CCP_PAR_ECM_SC_CHANNEL_ID)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0006] = {
						["dis"] = ccp_table:get_dissector(0x0006),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

Smart Card  :  CA2 Preview Control Opcode

--]]

	local CCP_PAR_ECM_SC_PREVIEW_CONTROL = Proto("CCP_PAR_ECM_SC_PREVIEW_CONTROL", "CA2 Preview Control")
	f_preview_control_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_PREVIEW_CONTROL.opcode", "Opcode", base.HEX)
	f_preview_control_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_PREVIEW_CONTROL.length", "Length", base.DEC)
	f_preview_control_ecm_cpsta = ProtoField.bytes("CCP_PAR_ECM_SC_PREVIEW_CONTROL.cpsta", "Start Time CP", base.HEX)
	f_preview_control_ecm_cplen = ProtoField.uint16("CCP_PAR_ECM_SC_PREVIEW_CONTROL.cplen", "CP Length", base.DEC)
	f_preview_control_ecm_cseq = ProtoField.uint16("CCP_PAR_ECM_SC_PREVIEW_CONTROL.cseq", "Epoch Sequence Number", base.DEC)
	f_preview_control_ecm_rfu = ProtoField.uint8("CCP_PAR_ECM_SC_PREVIEW_CONTROL.rfu", "RFU", base.HEX, nil, 0xe0)
	f_preview_control_ecm_ppid = ProtoField.uint8("CCP_PAR_ECM_SC_PREVIEW_CONTROL.ppid", "Preview Package ID", base.DEC, nil, 0x1f)
	f_preview_control_ecm_pptl = ProtoField.uint16("CCP_PAR_ECM_SC_PREVIEW_CONTROL.pptl", "Preview Package Time Limit", base.DEC)
	
	CCP_PAR_ECM_SC_PREVIEW_CONTROL.fields = {f_preview_control_ecm_opcode, f_preview_control_ecm_length, f_preview_control_ecm_cpsta, f_preview_control_ecm_cseq,
										f_preview_control_ecm_cplen, f_preview_control_ecm_rfu, f_preview_control_ecm_ppid, f_preview_control_ecm_pptl}
																				
	function CCP_PAR_ECM_SC_PREVIEW_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xa1 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t = root:add(CCP_PAR_ECM_SC_PREVIEW_CONTROL, buf(0,  2 + length))
		t:add(f_preview_control_ecm_opcode, buf(0,1))
		t:add(f_preview_control_ecm_length, buf(1,1))
		t:add(f_preview_control_ecm_cpsta, buf(2,4))
		t:add(f_preview_control_ecm_cplen, buf(6,1))
		t:add(f_preview_control_ecm_cseq, buf(7,1))
		t:add(f_preview_control_ecm_rfu, buf(8,1))
		t:add(f_preview_control_ecm_ppid, buf(8,1))
		t:add(f_preview_control_ecm_pptl, buf(9,1))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x00a1, CCP_PAR_ECM_SC_PREVIEW_CONTROL)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00a1] = {
						["dis"] = ccp_table:get_dissector(0x00a1),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  : CA3 Preview Control Opcode

--]]

	local CCP_PAR_ECM_CA3_PREVIEW_CONTROL = Proto("CCP_PAR_ECM_CA3_PREVIEW_CONTROL", "CA3 Preview Control")
	f_preview_control_ca3_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.opcode", "Opcode", base.HEX)
	f_preview_control_ca3_ecm_length = ProtoField.uint16("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.length", "Length", base.DEC)
	f_preview_control_ca3_ecm_cpsta = ProtoField.bytes("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.cpsta", "Start Time CP", base.HEX)
	f_preview_control_ca3_ecm_cplen = ProtoField.uint16("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.cplen", "CP Length", base.DEC)
	f_preview_control_ca3_ecm_cseq = ProtoField.uint16("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.cseq", "Epoch Sequence Number", base.DEC)
	f_preview_control_ca3_ecm_rfu = ProtoField.uint8("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.rfu", "RFU", base.HEX, nil, 0xe0)
	f_preview_control_ca3_ecm_ppid = ProtoField.uint8("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.ppid", "Preview Package ID", base.DEC, nil, 0x1f)
	f_preview_control_ca3_ecm_pptl = ProtoField.uint16("CCP_PAR_ECM_CA3_PREVIEW_CONTROL.pptl", "Preview Package Time Limit", base.DEC)
	
	CCP_PAR_ECM_CA3_PREVIEW_CONTROL.fields = {f_preview_control_ca3_ecm_opcode, f_preview_control_ca3_ecm_length, f_preview_control_ca3_ecm_cpsta, f_preview_control_ca3_ecm_cseq,
										f_preview_control_ca3_ecm_cplen, f_preview_control_ca3_ecm_rfu, f_preview_control_ca3_ecm_ppid, f_preview_control_ca3_ecm_pptl}
																				
	function CCP_PAR_ECM_CA3_PREVIEW_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xd1 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		
		
		local t = root:add(CCP_PAR_ECM_CA3_PREVIEW_CONTROL, buf(0,  2 + length))
		t:add(f_preview_control_ca3_ecm_opcode, buf(0,1))
		t:add(f_preview_control_ca3_ecm_length, buf(1,1))
		t:add(f_preview_control_ca3_ecm_cpsta, buf(2,4))
		t:add(f_preview_control_ca3_ecm_cplen, buf(6,1))
		t:add(f_preview_control_ca3_ecm_cseq, buf(7,1))
		t:add(f_preview_control_ca3_ecm_rfu, buf(8,1))
		t:add(f_preview_control_ca3_ecm_ppid, buf(8,1))
		t:add(f_preview_control_ca3_ecm_pptl, buf(9,1))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x00d1, CCP_PAR_ECM_CA3_PREVIEW_CONTROL)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00d1] = {
						["dis"] = ccp_table:get_dissector(0x00d1),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

Smart Card  :  Service Key Opcode

--]]

	local CCP_PAR_ECM_SC_SERVICE_KEY = Proto("CCP_PAR_ECM_SC_SERVICE_KEY", "Service Key")
	f_service_key_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.opcode", "Opcode", base.HEX)
	f_service_key_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_SERVICE_KEY.length", "Length", base.DEC)
	f_service_key_ecm_reserved = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.reserved", "Reserved", base.HEX, nil, 0xc0)
	f_service_key_ecm_pk_index = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.pk_index", "PK Index", base.DEC, nil, 0x3e)
	f_service_key_ecm_key_gen = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.key_gen", "Key Generation", base.HEX, nil, 0x01)
	f_service_key_ecm_decoder_id = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.decoder_id", "Decoder Identify", base.HEX, nil, 0x80)
	f_service_key_ecm_next_key_cipher_mode = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.next_key_cipher_mode", "Next Key Cipher Mode", base.HEX, nil, 0x70)
	f_service_key_ecm_cur_key_cipher_mode = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.cur_key_cipher_mode", "Current Key Cipher Mode", base.HEX, nil, 0x0e)
	f_service_key_ecm_next_key_indicator = ProtoField.uint8("CCP_PAR_ECM_SC_SERVICE_KEY.next_key_indicator", "Next Key Indicator", base.HEX, nil, 0x01)
	f_service_key_ecm_even_cw = ProtoField.bytes("CCP_PAR_ECM_SC_SERVICE_KEY.even_cw", "Even CW", base.HEX)
	f_service_key_ecm_odd_cw = ProtoField.bytes("CCP_PAR_ECM_SC_SERVICE_KEY.odd_cw", "Odd CW", base.HEX)
	
	CCP_PAR_ECM_SC_SERVICE_KEY.fields = {f_service_key_ecm_opcode, f_service_key_ecm_length, f_service_key_ecm_reserved, f_service_key_ecm_pk_index,
																f_service_key_ecm_key_gen, f_service_key_ecm_decoder_id, f_service_key_ecm_next_key_cipher_mode, f_service_key_ecm_cur_key_cipher_mode,
																f_service_key_ecm_next_key_indicator, f_service_key_ecm_even_cw, f_service_key_ecm_odd_cw}
	
	function CCP_PAR_ECM_SC_SERVICE_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x78 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t = root:add(CCP_PAR_ECM_SC_SERVICE_KEY, buf(0,  2 + length))
		t:add(f_service_key_ecm_opcode, buf(0,1))
		t:add(f_service_key_ecm_length, buf(1,1))
		t:add(f_service_key_ecm_reserved, buf(2,1))
		t:add(f_service_key_ecm_pk_index, buf(2,1))
		t:add(f_service_key_ecm_key_gen, buf(2,1))
		t:add(f_service_key_ecm_decoder_id, buf(3,1))
		t:add(f_service_key_ecm_next_key_cipher_mode, buf(3,1))
		t:add(f_service_key_ecm_cur_key_cipher_mode, buf(3,1))
		t:add(f_service_key_ecm_next_key_indicator, buf(3,1))
		t:add(f_service_key_ecm_even_cw, buf(4,8))
		t:add(f_service_key_ecm_odd_cw, buf(12,8))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	
	end
	ccp_table:add(0x0078, CCP_PAR_ECM_SC_SERVICE_KEY)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0078] = {
						["dis"] = ccp_table:get_dissector(0x0078),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		

--[[

Smart Card  :  Scrambler Key Opcode

--]]

	local CCP_PAR_ECM_SC_SCRAMBLER_KEY = Proto("CCP_PAR_ECM_SC_SCRAMBLER_KEY", "Scrambler Key")
	f_scrambler_key_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.opcode", "Opcode", base.HEX)
	f_scrambler_key_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_SCRAMBLER_KEY.length", "Length", base.DEC)
	f_scrambler_key_ecm_key_indicator = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.key_indicator", "Key Indicator", base.HEX)
	f_scrambler_key_ecm_decoder_id = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.decoder_id", "Decoder Identify", base.HEX, nil, 0x80)
	f_scrambler_key_ecm_cur_key_cipher_mode  = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.cur_key_cipher_mode", "Current Key Cipher Mode", base.HEX, nil, 0x70)
	f_scrambler_key_ecm_next_key_cipher_mode = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.next_key_cipher_mode", "Next Key Cipher Mode", base.HEX, nil, 0x0e)
	f_scrambler_key_ecm_next_key_indicator = ProtoField.uint8("CCP_PAR_ECM_SC_SCRAMBLER_KEY.next_key_indicator", "Next Key Indicator", base.HEX, nil, 0x01)
	f_scrambler_key_ecm_even_cw = ProtoField.bytes("CCP_PAR_ECM_SC_SCRAMBLER_KEY.even_cw", "Even CW", base.HEX)
	f_scrambler_key_ecm_odd_cw = ProtoField.bytes("CCP_PAR_ECM_SC_SCRAMBLER_KEY.odd_cw", "Odd CW", base.HEX)
	
	CCP_PAR_ECM_SC_SCRAMBLER_KEY.fields = {f_scrambler_key_ecm_opcode, f_scrambler_key_ecm_length, f_scrambler_key_ecm_key_indicator, f_scrambler_key_ecm_decoder_id,
											f_scrambler_key_ecm_cur_key_cipher_mode, f_scrambler_key_ecm_next_key_cipher_mode, f_scrambler_key_ecm_next_key_indicator,
											f_scrambler_key_ecm_even_cw, f_scrambler_key_ecm_odd_cw}
	
	function CCP_PAR_ECM_SC_SCRAMBLER_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x79 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t = root:add(CCP_PAR_ECM_SC_SCRAMBLER_KEY, buf(0,  2 + length))
		t:add(f_scrambler_key_ecm_opcode, buf(0,1))
		t:add(f_scrambler_key_ecm_length, buf(1,1))
		t:add(f_scrambler_key_ecm_key_indicator, buf(2,1))
		t:add(f_scrambler_key_ecm_decoder_id, buf(3,1))
		t:add(f_scrambler_key_ecm_cur_key_cipher_mode, buf(3,1))
		t:add(f_scrambler_key_ecm_next_key_cipher_mode, buf(3,1))
		t:add(f_scrambler_key_ecm_next_key_indicator, buf(3,1))
		t:add(f_scrambler_key_ecm_even_cw, buf(4,16))
		t:add(f_scrambler_key_ecm_odd_cw, buf(20,16))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	
	end
	ccp_table:add(0x0079, CCP_PAR_ECM_SC_SCRAMBLER_KEY)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0079] = {
						["dis"] = ccp_table:get_dissector(0x0079),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
--[[

	Smart Card  :  User Info Opcode

--]]

	local CCP_PAR_SC_USER_INFO = Proto("CCP_PAR_SC_USER_INFO", "User Info")
	f_user_info_opcode = ProtoField.uint8("CCP_PAR_SC_USER_INFO.opcode", "Opcode", base.HEX)
	f_user_info_length = ProtoField.uint16("CCP_PAR_SC_USER_INFO.length", "Length", base.DEC)
	f_user_info_message_type = ProtoField.uint8("CCP_PAR_SC_USER_INFO.msg_type", "Message Type", base.DEC, {[1] = "CIPlusURI", [2] = "ECP", [3]= "SKELP", [6] = "DRMPVRTrickMode"})
	f_user_info_message_len = ProtoField.uint8("CCP_PAR_SC_USER_INFO.msg_len", "Message Length", base.DEC)
	f_user_info_user_info = ProtoField.bytes("CCP_PAR_SC_USER_INFO.user_info", "User Info", base.HEX)
	f_user_info_enhanced_copy_protection = ProtoField.bytes("CCP_PAR_SC_USER_INFO.Enchanced_Copy_protection", "Enhanced Copy Protection Message", base.HEX)
	f_user_info_ciplus = ProtoField.bytes("CCP_PAR_SC_USER_INFO.CiPlus", "CI+ Message", base.HEX)
	f_user_info_skelp = ProtoField.bytes("CCP_PAR_SC_USER_INFO.skelkp", "SKE Link Protection", base.HEX)
	f_user_info_drm_pvr_trick_mode = ProtoField.bytes("CCP_PAR_SC_USER_INFO.trickmode", "DRM/PVR Trick Mode", base.HEX)
	
	--Protocol Version
	f_user_info_protocol_version = ProtoField.uint8("CCP_PAR_SC_USER_INFO.protocol_version", "Protocol Version", base.DEC)
	
	--APS copy control info
	f_user_info_aps_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_aps_cci", "APS Copy Control Info", base.HEX, nil, 0xc000)
	
	--EMI copy control info
	f_user_info_emi_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_emi_cci", "EMI Copy Control Info", base.HEX, nil, 0x3000)
	
	--ICT Copy control info
	f_user_info_ict_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_ict_cci", "ICT Copy Control Info", base.HEX, nil, 0x0800)
	
	--RCT copy control info
	f_user_info_rct_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_rct_cci", "RCT Copy Control Info", base.HEX, nil, 0x0400)
	
	--RFU
	f_user_info_rfu = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_rct_cci", "Reserved for future use", base.HEX, nil, 0x0200)
	f_user_info_rfu_version1 = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_rfu_version1", "RFU", base.HEX, nil, 0x03c0)
	
	--RL copy control info
	f_user_info_rl_cci_version1 = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_rl_cci_version1", "RL Copy Control Info", base.HEX, nil, 0x003f)
	
	--DOT copy control info
	f_user_info_dot_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_dot_cci", "DOT Copy Control Info", base.HEX, nil, 0x0100)
	
	--RL copy control info
	f_user_info_rl_cci = ProtoField.uint16("CCP_PAR_SC_USER_INFO.protocol_rl_cci", "RL Copy Control Info", base.HEX, nil, 0x00ff)
	
	--trick mode control info, 1 bit.    if emi_copy_control_info == 10
	f_user_info_trick_mci = ProtoField.uint8("f_user_info_trick_mci", "Trick mode control info, 1 bit", base.DEC, nil, 0x80)

	--Reserved for future use, 39 bits for version 3	
	f_user_info_rfu1_1 = ProtoField.uint8("f_user_info_rfu1", "Reserved for future use_1, 7 bits", base.HEX, nil, 0x7f)	
	f_user_info_rfu1_2 = ProtoField.uint32("f_user_info_rfu2", "Reserved for future use_2, 32 bits", base.HEX, nil, 0xffffffff)	
	
	--Enhanced Copy Protection Message Type
	f_user_info_enhanced_copy_protection_message_type = ProtoField.uint8("CCP_PAR_SC_USER_INFO.message_type", "ECP Message Type", base.DEC)

	--Enhanced Copy Protection Message Length
	f_user_info_enhanced_copy_protection_message_length = ProtoField.uint8("CCP_PAR_SC_USER_INFO.message_length", "ECP Message Length", base.DEC)

	--Enhanced Copy Protection
	--GlovalPVR Flag info
	f_user_info_enhanced_copy_protection_global_pvr_allowable = ProtoField.uint8("CCP_PAR_SC_USER_INFO.global_pvr_allowable", "Global PVR", base.HEX,nil,0x80)	
	--Image Constraint
	f_user_info_enhanced_copy_protection_image_contraint = ProtoField.uint8("CCP_PAR_SC_USER_INFO.image_contraint", "Image Constraint", base.HEX,nil,0x40)	
	--Stream to unmanaged
	f_user_info_enhanced_copy_protection_stream_to_unmanaged = ProtoField.uint8("CCP_PAR_SC_USER_INFO.stream_to_unmanaged", "Stream To Unmanaged", base.HEX,nil,0x20)	
	--Airplay
	f_user_info_enhanced_copy_protection_airplay = ProtoField.uint8("CCP_PAR_SC_USER_INFO.airplay", "AirPlay", base.HEX,nil,0x10)	
	--Reserved1
	f_user_info_enhanced_copy_protection_reserved = ProtoField.uint8("CCP_PAR_SC_USER_INFO.reserved1", "Reserved", base.HEX,nil,0x0f)	
	--HDCP
	f_user_info_enhanced_copy_protection_hdcp = ProtoField.uint8("CCP_PAR_SC_USER_INFO.hdcp", "HDCP", base.HEX,nil,0x80)	
	--HDCP 2.2+
	f_user_info_enhanced_copy_protection_hdcp_22plus = ProtoField.uint8("CCP_PAR_SC_USER_INFO.hdcp_22plus", "HDCP 2.2+", base.HEX,nil,0x70)	
	--PlayReady
	f_user_info_enhanced_copy_protection_playready = ProtoField.uint8("CCP_PAR_SC_USER_INFO.playready", "Play Ready", base.HEX,nil,0x08)	
	--SKE
	f_user_info_enhanced_copy_protection_ske = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske", "SKE", base.HEX,nil,0x04)	
	--DTCP-IP Clear
	f_user_info_enhanced_copy_protection_dtcp_ip_clear = ProtoField.uint8("CCP_PAR_SC_USER_INFO.dtcp_ip_clear", "DTCP-IP Clear", base.HEX,nil,0x02)
	--DTCP-IP DTCP
	f_user_info_enhanced_copy_protection_dtcp_ip_dtcp = ProtoField.uint8("CCP_PAR_SC_USER_INFO.dtcp_ip_dtcp", "DTCP-IP DTCP", base.HEX,nil,0x01)
	
	--SKE Link Protection
	f_user_info_ske_key_type = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_key_type", "SKELP Type", base.DEC, {[0]="Reserved", [1]="SKE Serverkey private encrypted by SKEPK public", [2]="SKE Systemkey public", [3]="Reserved"})
	f_user_info_ske_key_length = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_length", "Length", base.DEC)
	f_user_info_ske_key_indicator = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_indicator", "SKE Key Indicator", base.DEC, {[0]='SKE Key Not Applicable', [1]='SKE Key Applicable'},0x80)
	f_user_info_ske_key_reserved = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_reserved", "Reserved", base.HEX, nil, 0x7f)
	f_user_info_ske_key_public_length = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_public_length", "Server Key Public Length", base.DEC)
	f_user_info_ske_key_public = ProtoField.bytes("CCP_PAR_SC_USER_INFO.ske_public", "Server Key Public", base.HEX)
	f_user_info_ske_key_private_length = ProtoField.uint8("CCP_PAR_SC_USER_INFO.ske_private_length", "Server Key Private Length", base.DEC)
	f_user_info_ske_key_private = ProtoField.bytes("CCP_PAR_SC_USER_INFO.ske_public", "Server Key Private", base.HEX)
	f_user_info_ske_crc16 = ProtoField.bytes("CCP_PAR_SC_USER_INFO.ske_crc16", "CRC16", base.HEX)

	--DRM PVR Trick Mode
	--Trick Mode control
	f_user_info_trick_mode_control = ProtoField.uint8("CCP_PAR_SC_USER_INFO.trick_mode_control", "Trick Mode Control", base.HEX,nil,0xE0)	
	--Trick Mode control Reserved bit
	f_user_info_trick_mode_control_rfu = ProtoField.uint8("CCP_PAR_SC_USER_INFO.trick_mode_control_rfu", "Trick mode control Reserved", base.HEX,nil,0x1C)	
	--Reserved For Future Use
	f_user_info_rfu1 = ProtoField.uint8("CCP_PAR_SC_USER_INFO.rfu1", "Reserved Bit For Future", base.HEX,nil,0x03)	
	--Reserved For Future Use
	f_user_info_rfu2 = ProtoField.uint8("CCP_PAR_SC_USER_INFO.rfu2", "Reserved Byte For Future", base.HEX)	
	
	CCP_PAR_SC_USER_INFO.fields = {f_user_info_opcode, f_user_info_length, f_user_info_message_type, f_user_info_message_len, f_user_info_user_info,
									f_user_info_ciplus,f_user_info_skelp, f_user_info_drm_pvr_trick_mode, f_user_info_protocol_version, f_user_info_aps_cci, 
									f_user_info_emi_cci, f_user_info_ict_cci, f_user_info_rct_cci, f_user_info_rfu, f_user_info_rfu_version1,f_user_info_rl_cci_version1,
									f_user_info_dot_cci, f_user_info_rl_cci, f_user_info_trick_mci,f_user_info_rfu1_1,f_user_info_rfu1_2,
									f_user_info_enhanced_copy_protection_message_type,f_user_info_enhanced_copy_protection_message_length,
									f_user_info_enhanced_copy_protection, f_user_info_enhanced_copy_protection_global_pvr_allowable,
									f_user_info_enhanced_copy_protection_image_contraint, f_user_info_enhanced_copy_protection_stream_to_unmanaged,
									f_user_info_enhanced_copy_protection_airplay, f_user_info_enhanced_copy_protection_reserved,
									f_user_info_enhanced_copy_protection_hdcp, f_user_info_enhanced_copy_protection_hdcp_22plus,
									f_user_info_enhanced_copy_protection_playready, f_user_info_enhanced_copy_protection_ske, 
									f_user_info_enhanced_copy_protection_dtcp_ip_clear,f_user_info_enhanced_copy_protection_dtcp_ip_dtcp,
									f_user_info_ske_key_type,f_user_info_ske_key_length,f_user_info_ske_key_indicator,f_user_info_ske_key_reserved,
									f_user_info_ske_key_public_length,f_user_info_ske_key_public, f_user_info_ske_key_private_length,f_user_info_ske_key_private, f_user_info_ske_crc16,
									f_user_info_trick_mode_control, f_user_info_trick_mode_control_rfu, f_user_info_rfu1, f_user_info_rfu2}
	
 	function CCP_PAR_SC_USER_INFO.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x17 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
	
		local t = root:add(CCP_PAR_SC_USER_INFO, buf(0,  2 + length))
		t:add( f_user_info_opcode, buf(0, 1))
		t:add( f_user_info_length, buf(1, 1))
		
		local offset = 2
		while offset < length + 2 do
			t:add( f_user_info_message_type, buf(offset, 1))
			t:add( f_user_info_message_len, buf(offset+1, 1))
			local message_type = buf(offset,1):uint()
			local message_length = buf(offset+1, 1):uint()
			
			offset = offset + 2
			if message_type == 1 then --Transfer URI for CI+
				st = t:add(f_user_info_ciplus, buf(offset, message_length))
				st:add(f_user_info_protocol_version, buf(offset, 1))
				st:add(f_user_info_aps_cci, buf(offset+1,2))
				st:add(f_user_info_emi_cci, buf(offset+1,2))
				st:add(f_user_info_ict_cci, buf(offset+1,2))
				
				if buf(offset, 1):uint() == 0x03 then -- if protocol version is 0x03
					st:add(f_user_info_rct_cci, buf(offset+1,2))
					st:add(f_user_info_rfu, buf(offset+1,2))
					st:add(f_user_info_dot_cci, buf(offset+1,2))
					st:add(f_user_info_rl_cci, buf(offset+1,2))
					
					st:add(f_service_data_trick_mci, buf(offset+3,1))
					st:add(f_service_data_rfu1_1, buf(offset+3,1))
					st:add(f_service_data_rfu1_2, buf(offset+4,4))

	            elseif buf(offset, 1):uint() == 0x02 then -- if protocol version is 0x02
					st:add(f_user_info_rct_cci, buf(offset+1,2))
					st:add(f_user_info_rfu, buf(offset+1,2))
					st:add(f_user_info_dot_cci, buf(offset+1,2))
					st:add(f_user_info_rl_cci, buf(offset+1,2))

                else -- if protocol version is 0x01
				    st:add(f_user_info_rct_cci, buf(offset+1,2))
					st:add(f_user_info_rfu_version1, buf(offset+1,2))			
					st:add(f_user_info_rl_cci_version1, buf(offset+1,2))

				end
				
			elseif message_type == 2 then --Enhanced Copy Protection
				st = t:add(f_user_info_enhanced_copy_protection, buf(offset, message_length))
				st:add(f_user_info_enhanced_copy_protection_global_pvr_allowable, buf(offset, 1))
				st:add(f_user_info_enhanced_copy_protection_image_contraint, buf(offset,1))
				st:add(f_user_info_enhanced_copy_protection_stream_to_unmanaged, buf(offset,1))
				st:add(f_user_info_enhanced_copy_protection_airplay, buf(offset,1))
				st:add(f_user_info_enhanced_copy_protection_reserved, buf(offset,1))
				if message_length > 1 then
					st:add(f_user_info_enhanced_copy_protection_hdcp, buf(offset+1,1))
					st:add(f_user_info_enhanced_copy_protection_hdcp_22plus, buf(offset+1,1))
					st:add(f_user_info_enhanced_copy_protection_playready, buf(offset+1,1))
					st:add(f_user_info_enhanced_copy_protection_ske, buf(offset+1,1))
					st:add(f_user_info_enhanced_copy_protection_dtcp_ip_clear, buf(offset+1,1))
					st:add(f_user_info_enhanced_copy_protection_dtcp_ip_dtcp, buf(offset+1,1))
				end
				
			elseif message_type == 3 then -- SKE Server Key
				st = t:add(f_user_info_skelp, buf(offset, message_length))
				st:add(f_user_info_ske_key_type, buf(offset+0,1))
				st:add(f_user_info_ske_key_length, buf(offset+1,1))
				local length = buf(offset+1,1):uint()
				st:add(f_user_info_ske_key_indicator, buf(offset+2,1))
				local indicator = bit:_rshift(buf(offset+2,1):uint(), 7)
				st:add(f_user_info_ske_key_reserved, buf(offset+2,1))
				st:add(f_user_info_ske_key_public_length, buf(offset+3,1))
				local publickey_len = buf(offset+3,1):uint()
				st:add(f_user_info_ske_key_public, buf(offset+4,publickey_len))
				local delta = offset+4+publickey_len
				
				local privatekey_len = 0
				if indicator == 0x01 then
					st:add(f_user_info_ske_key_private_length, buf(offset+4+publickey_len, 1))
					privatekey_len = buf(offset+4+publickey_len, 1):uint()
					st:add(f_user_info_ske_key_private, buf(offset+5+publickey_len, privatekey_len))
					delta = delta+1+privatekey_len
				end
				
				st:add(f_user_info_ske_crc16, buf(delta, 2))

			elseif message_type == 6 then -- DRM/PVR Trick Mode
				st = t:add(f_user_info_drm_pvr_trick_mode, buf(offset, message_length))
				st:add(f_user_info_trick_mode_control, buf(offset+0,1))
				st:add(f_user_info_trick_mode_control_rfu, buf(offset+0,1))
				st:add(f_user_info_rfu1, buf(offset+0,1))
				st:add(f_user_info_rfu2, buf(offset+1,2))
								
			else
				t:add(f_user_info_user_info, buf(offset, message_length))
			end
			
			offset = offset + message_length
		end
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x0017, CCP_PAR_SC_USER_INFO)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0017] = {
						["dis"] = ccp_table:get_dissector(0x0017),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		

--[[

Smart Card  :  Extended Scrambler Key Opcode

--]]

	local CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY = Proto("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY", "Extended Scrambler Key")
	f_ext_scrambler_key_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.opcode", "Opcode", base.HEX)
	f_ext_scrambler_key_length = ProtoField.uint16("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.length", "Length", base.DEC)
	f_ext_scrambler_key_key_cipher_mode = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.key_cipher_mode", "Key Cipher Mode", base.HEX, nil, 0xf0)
	f_ext_scrambler_key_rfu = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.rfu", "RFU", base.HEX, nil, 0x0e)
	f_ext_scrambler_key_seq_key_indicator = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.seq_key_indicator", "Sequential Key Indicator", base.HEX, nil, 0x01)
	f_ext_scrambler_key_key_indicator_length = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.key_indicator_length", "Key Indicator Length", base.DEC, nil, 0xf0)
	f_ext_scrambler_key_sk_len = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.sk_len", "Scrambler Key Length", base.DEC, nil, 0x0e)
	f_ext_scrambler_key_decoder_id = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.decoder_id", "Decoder Identify", base.HEX, nil, 0x01)
	f_ext_scrambler_key_key_indicator = ProtoField.bytes("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.key_indicator", "Key Indicator", base.HEX)
	f_ext_scrambler_key_cur_cw = ProtoField.bytes("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.cur_cw", "Current CW", base.HEX)
	f_ext_scrambler_key_next_cw = ProtoField.bytes("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.next_cw", "Next CW", base.HEX)
	f_ext_scrambler_key_arp_trigger = ProtoField.uint8("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.arp_trigger", "ARP Trigger", base.HEX, nil, 0x80)
	f_ext_scrambler_key_channel_id = ProtoField.uint16("CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.channel_id", "Channel Id", base.HEX,nil, 0x7fff)
	
	CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.fields = {f_ext_scrambler_key_opcode, f_ext_scrambler_key_length, f_ext_scrambler_key_key_cipher_mode,
																					f_ext_scrambler_key_rfu, f_ext_scrambler_key_seq_key_indicator, f_ext_scrambler_key_key_indicator_length,
																					f_ext_scrambler_key_sk_len, f_ext_scrambler_key_decoder_id, f_ext_scrambler_key_key_indicator,
																					f_ext_scrambler_key_cur_cw, f_ext_scrambler_key_next_cw, f_ext_scrambler_key_arp_trigger, f_ext_scrambler_key_channel_id}
																					
	function CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0x7b then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t = root:add(CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY, buf(0,  2 + length))
		t:add(f_ext_scrambler_key_opcode, buf(0,1))
		t:add(f_ext_scrambler_key_length, buf(1,1))
		t:add(f_ext_scrambler_key_key_cipher_mode, buf(2,1))
		t:add(f_ext_scrambler_key_rfu, buf(2,1))
		t:add(f_ext_scrambler_key_seq_key_indicator, buf(2,1))
		t:add(f_ext_scrambler_key_key_indicator_length, buf(3,1))
		t:add(f_ext_scrambler_key_sk_len, buf(3,1))
		t:add(f_ext_scrambler_key_decoder_id, buf(3,1))
		
		local key_indicator_length = bit:_and(bit:_rshift(buf(3,1):uint(), 4), 0xf)
		t:add(f_ext_scrambler_key_key_indicator, buf(4, key_indicator_length))
		
		local offset = 2 + key_indicator_length
		local cw_size = 0
		
		if length >= 35 then
			cw_size = 16
		else
			cw_size = 8
		end
		
		t:add(f_ext_scrambler_key_cur_cw, buf(4+key_indicator_length, cw_size))
		t:add(f_ext_scrambler_key_next_cw, buf(4+key_indicator_length+cw_size, cw_size))
		
		offset = offset + 2*cw_size
		if offset < length then
			t:add(f_ext_scrambler_key_arp_trigger, buf(4+key_indicator_length+2*cw_size, 1))
			t:add(f_ext_scrambler_key_channel_id, buf(4+key_indicator_length+2*cw_size, 2))
		end
	
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x007b, CCP_PAR_ECM_SC_EXT_SCRAMBLER_KEY)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x007b] = {
						["dis"] = ccp_table:get_dissector(0x007b),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		
	
--[[

Smart Card  :  Expression Filter Opcode
TODO: Needs to parse the expression
--]]

	local CCP_PAR_ECM_SC_EXPRESSION_FILTER = Proto("CCP_PAR_ECM_SC_EXPRESSION_FILTER", "Expression Filter")
	f_express_filter_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_EXPRESSION_FILTER.opcode", "Opcode", base.HEX)
	f_express_filter_length = ProtoField.uint16("CCP_PAR_ECM_SC_EXPRESSION_FILTER.length", "Length", base.DEC)
	f_express_filter_expression = ProtoField.bytes("CCP_PAR_ECM_SC_EXPRESSION_FILTER.expression", "Expression", base.HEX)
	f_express_filter_string = ProtoField.string("CCP_PAR_ECM_SC_EXPRESSION_FILTER.exp_str", "Parsed Expression")
	
	CCP_PAR_ECM_SC_EXPRESSION_FILTER.fields = {f_express_filter_opcode, f_express_filter_length, f_express_filter_expression, f_express_filter_string}
	
	local token_string = {
							[0] = '_Prod_ID_',
							[1] = '_Not_',
							[2] = '_And_',
							[3] = '_Or'
						}
						
	local function max_v(a,b)
		if a>=b then
			return a
		else
			return b
		end
	end
	
	local function expression_parse(buf)
		local exp_string = ''
		local all_data_bin = ''
		local buf_len = buf:len()
		
		local databinary = bitop:Hex2Bin(tostring(buf))
		local nrBits = databinary:len()
		local nZeroToPad = max_v( buf_len * 8 - nrBits, 0)
		if nZeroToPad ~= 0 then
			for i=1,nZeroToPad do
				all_data_bin = all_data_bin..'0'
			end
		end
		all_data_bin = all_data_bin..databinary
		local all_nrBits = all_data_bin:len()
		local padding_len = tonumber(bitop:Bin2Dec(all_data_bin:sub(0,2)))
		local bits_left = buf_len * 8 - (padding_len * 2) - 2
		-- chop the padding bits at the end s owe have only the bits of the data to parse
		if padding_len > 0 then
			all_data_bin = all_data_bin:sub(0, all_nrBits - padding_len * 2)
		end
		
		local i = 3 --offset/position in the bitstring
		while  bits_left > 0 do
			local token = all_data_bin:sub(i, i+1)
			exp_string = exp_string..token_string[tonumber(bitop:Bin2Dec(token))]
			i = i + 2
			bits_left = bits_left - 2
			
			if token == '00' then
				local product_id = bitop:Bin2Dec(all_data_bin:sub(i, i+15))
				exp_string = exp_string .. tostring(product_id)
				i = i + 16
				bits_left = bits_left - 16
			end
		
		end
		
		return exp_string
	end
	
	function CCP_PAR_ECM_SC_EXPRESSION_FILTER.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xce then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end		

		local t = root:add(CCP_PAR_ECM_SC_EXPRESSION_FILTER, buf(0,  2 + length))
		t:add(f_express_filter_opcode, buf(0,1))
		t:add(f_express_filter_length, buf(1,1))	
		
		t:add(f_express_filter_expression, buf(2, length))
		local exp_str = expression_parse(buf(2,length))
		t:add(f_express_filter_string, exp_str)
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true		
	
	end
	
	ccp_table:add(0x00ce, CCP_PAR_ECM_SC_EXPRESSION_FILTER)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00ce] = {
						["dis"] = ccp_table:get_dissector(0x00ce),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		
	

--[[

	Smart Card  :  Content Rights Opcode

--]]

	local CCP_PAR_ECM_SC_CONTENT_RIGHTS = Proto("CCP_PAR_ECM_SC_CONTENT_RIGHTS", "DRM Content Rights")
	f_content_rights_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_CONTENT_RIGHTS.opcode", "Opcode", base.HEX)
	f_content_rights_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_CONTENT_RIGHTS.length", "Length", base.DEC)
	f_content_rights_ecm_crid = ProtoField.bytes("CCP_PAR_ECM_SC_CONTENT_RIGHTS.crid", "CRID", base.HEX)
	f_content_rights_ecm_window_type = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.window_type", "Window Type")
	f_content_rights_ecm_dccbits =ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.dccbits", "DCCbits",base.HEX)
	f_content_rights_ecm_nrofplayback_flag = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.nrofplayback", "NrOfPlayback Flag")
	f_content_rights_ecm_return_data_flag = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.return_data", "Return Data Flag")
	f_content_rights_ecm_sequence_maker = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.sequence_maker", "Sequence Maker")
	f_content_rights_ecm_reserved = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.reserved", "Reserved")
	f_content_rights_ecm_start_time = ProtoField.bytes("CCP_PAR_ECM_SC_CONTENT_RIGHTS.start_time", "Start Time", base.HEX)
	f_content_rights_ecm_end_time = ProtoField.bytes("CCP_PAR_ECM_SC_CONTENT_RIGHTS.end_time", "End Time", base.HEX)
	f_content_rights_ecm_duration_time = ProtoField.bytes("CCP_PAR_ECM_SC_CONTENT_RIGHTS.duration_time", "Duration Time", base.HEX)
	f_content_rights_ecm_nrofplayback = ProtoField.uint8("CCP_PAR_ECM_SC_CONTENT_RIGHTS.nrofplayback", "NrofPlayBack", base.DEC)
	f_content_rights_ecm_return_data = ProtoField.bytes("CCP_PAR_ECM_SC_CONTENT_RIGHTS.return_data", "Return Data", base.HEX)
	f_content_rights_ecm_clear_flag = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.clear_flag", "Clear Flag")
	f_content_rights_ecm_dtcpip_flag = ProtoField.string("CCP_PAR_ECM_SC_CONTENT_RIGHTS.dtcpip_flag", "DTCP-IP Flag")
	
	
	CCP_PAR_ECM_SC_CONTENT_RIGHTS.fields = {f_content_rights_ecm_opcode, f_content_rights_ecm_length, f_content_rights_ecm_crid, f_content_rights_ecm_window_type,
										f_content_rights_ecm_dccbits, f_content_rights_ecm_nrofplayback_flag, f_content_rights_ecm_return_data_flag,
										f_content_rights_ecm_sequence_maker, f_content_rights_ecm_reserved, f_content_rights_ecm_start_time, f_content_rights_ecm_end_time,
										f_content_rights_ecm_duration_time, f_content_rights_ecm_nrofplayback, f_content_rights_ecm_return_data,
										f_content_rights_ecm_clear_flag, f_content_rights_ecm_dtcpip_flag}
	
	function CCP_PAR_ECM_SC_CONTENT_RIGHTS.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xba then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end			
	
		local t = root:add(CCP_PAR_ECM_SC_CONTENT_RIGHTS, buf(0,  2 + length))
        local index = 7
        local window_type = bit:_and(bit:_rshift(buf(6,1):uint(), 6), 3)
        local nrplayback_falg =  bit:_and(bit:_rshift(buf(6,1):uint(), 3), 1)
        local return_data_falg = bit:_and(bit:_rshift(buf(6,1):uint(), 2), 1)
		t:add(f_content_rights_ecm_opcode, buf(0,1))
		t:add(f_content_rights_ecm_length, buf(1,1))
		t:add(f_content_rights_ecm_crid, buf(2,4))
		t:add(f_content_rights_ecm_reserved, bit:_and(buf(6,1):uint(), 1))
		t:add(f_content_rights_ecm_sequence_maker, bit:_and(bit:_rshift(buf(6,1):uint(), 1), 1))
        t:add(f_content_rights_ecm_return_data_flag, bit:_and(bit:_rshift(buf(6,1):uint(), 2), 1))
        t:add(f_content_rights_ecm_nrofplayback_flag, bit:_and(bit:_rshift(buf(6,1):uint(), 3), 1))
        t:add(f_content_rights_ecm_dccbits, bit:_and(bit:_rshift(buf(6,1):uint(), 4), 3))
        t:add(f_content_rights_ecm_window_type, bit:_and(bit:_rshift(buf(6,1):uint(), 6), 3))
        
        if window_type == 1 then
            t:add(f_content_rights_ecm_start_time, buf(index, 4))
            index = index +4
            t:add(f_content_rights_ecm_end_time, buf(index, 4))
            index = index +4
            
        elseif window_type == 2 or window_type == 3 then
            t:add(f_content_rights_ecm_duration_time, buf(index, 4))
            index= index+4
        
        end
        
        if nrplayback_falg == 1 then
            t:add(f_content_rights_ecm_nrofplayback, buf(index, 1))
            index = index + 1
        end
        
        if return_data_falg == 1 then
			t:add(f_content_rights_ecm_dtcpip_flag, bit:_and(buf(index, 1):uint(), 1))
			t:add(f_content_rights_ecm_clear_flag, bit:_and(bit:_rshift(buf(index, 1):uint(), 1), 1))
            t:add(f_content_rights_ecm_return_data, buf(index, 2+length-index))
        end
        
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	
	ccp_table:add(0x00ba, CCP_PAR_ECM_SC_CONTENT_RIGHTS)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00ba] = {
						["dis"] = ccp_table:get_dissector(0x00ba),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}		
	
	--[[
	Smart Card  :  IPPV Control Opcode
	]]--
	local CCP_PAR_IPPV_CONTROL = Proto("CCP_PAR_IPPV_CONTROL", "IPPV Control")
	--0,1
	f_ippv_control_opcode = ProtoField.uint8("CCP_PAR_IPPV_CONTROL.Opcode", "Opcode", base.HEX)
	--1,1
	f_ippv_control_length = ProtoField.uint8("CCP_PAR_IPPV_CONTROL.Length", "Length", base.DEC)
	--2,2
	f_ippv_control_event_id = ProtoField.uint16("CCP_PAR_IPPV_CONTROL.event_id", "Event Id", base.DEC)
	
	f_ippv_control_last_completed_eventid = ProtoField.uint16("CCP_PAR_IPPV_CONTROL.last_completed_id", "Last Completed Id", base.DEC)
	f_ippv_control_event_cost = ProtoField.uint16("CCP_PAR_IPPV_CONTROL.event_cost", "Event Cost", base.DEC)
	f_ippv_control_preview_time = ProtoField.uint8("CCP_PAR_IPPV_CONTROL.preview_time", "Preview Time", base.DEC, {[0] = "Not in Preview", [1] = "In Preview"})
	f_ippv_control_clock = ProtoField.uint8("CCP_PAR_IPPV_CONTROL.clock", "Clock", base.DEC)

	CCP_PAR_IPPV_CONTROL.fields = {f_ippv_control_opcode, f_ippv_control_length, f_ippv_control_event_id, f_ippv_control_last_completed_eventid, f_ippv_control_event_cost,
									f_ippv_control_preview_time, f_ippv_control_clock}
	function CCP_PAR_IPPV_CONTROL.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xdc then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_IPPV_CONTROL, buf(0,  2 + length))
		t:add( f_ippv_control_opcode, buf(0, 1))
		t:add( f_ippv_control_length, buf(1, 1))
		t:add( f_ippv_control_event_id, buf(2, 2))
		t:add( f_ippv_control_last_completed_eventid, buf(4, 2))
		t:add( f_ippv_control_event_cost, buf(6, 2))
		t:add( f_ippv_control_preview_time, buf(8, 1))
		t:add( f_ippv_control_clock, buf(9, 1))

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x00dc, CCP_PAR_IPPV_CONTROL)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x00dc] = {
						["dis"] = ccp_table:get_dissector(0x00dc),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	--[[
	Smart Card  :  IPPV Preview Opcode
	]]--
	local CCP_PAR_IPPV_PREVIEW = Proto("CCP_PAR_IPPV_PREVIEW", "IPPV Preview")
	--0,1
	f_ippv_preview_opcode = ProtoField.uint8("CCP_PAR_IPPV_PREVIEW.Opcode", "Opcode", base.HEX)
	--1,1
	f_ippv_preview_length = ProtoField.uint8("CCP_PAR_IPPV_PREVIEW.Length", "Length", base.DEC)
	--2,2
	f_ippv_preview_cpsta = ProtoField.bytes("CCP_PAR_IPPV_PREVIEW.cpsta", "Crypto Period Start time", base.HEX)
	
	f_ippv_preview_cplen = ProtoField.uint8("CCP_PAR_IPPV_PREVIEW.cplen", "Crypto Period Length", base.DEC)
	f_ippv_preview_rfu = ProtoField.uint8("CCP_PAR_IPPV_PREVIEW.rfu", "RFU", base.DEC)
	f_ippv_preview_bwl = ProtoField.string("CCP_PAR_IPPV_PREVIEW.bwl", "Buy Window Left", base.DEC)
	f_ippv_preview_ptt = ProtoField.string("CCP_PAR_IPPV_PREVIEW.ptt", "Preview Time Total Limit", base.DEC)

	CCP_PAR_IPPV_PREVIEW.fields = {f_ippv_preview_opcode, f_ippv_preview_length, f_ippv_preview_cpsta, f_ippv_preview_cplen, f_ippv_preview_rfu,
									f_ippv_preview_bwl, f_ippv_preview_ptt}
	function CCP_PAR_IPPV_PREVIEW.dissector(buf, pkt, root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xa2 then
			return false
		end

		local length = buf(1, 1) : uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end

		local t = root:add(CCP_PAR_IPPV_PREVIEW, buf(0,  2 + length))
		t:add( f_ippv_preview_opcode, buf(0, 1))
		t:add( f_ippv_preview_length, buf(1, 1))
		t:add( f_ippv_preview_cpsta, buf(2, 4))
		t:add( f_ippv_preview_cplen, buf(6, 1))
		t:add( f_ippv_preview_rfu, buf(7, 1))
		local bwl_unit_indicator = bit:_rshift(buf(8,1):uint(), 7)
		if bwl_unit_indicator == 0 then
			t:add( f_ippv_preview_bwl, bit:_and(buf(8, 1):uint(), 0x7f).. ' Seconds')
		else
			t:add( f_ippv_preview_bwl, bit:_and(buf(8, 1):uint(), 0x7f).. ' Minutes')
		end
		
		local ptt_unit_indicator = bit:_rshift(buf(9,1):uint(), 7)
		if ptt_unit_indicator == 0 then
			t:add( f_ippv_preview_ptt, bit:_and(buf(9, 1):uint(), 0x7f).. ' Seconds')
		else
			t:add( f_ippv_preview_ptt, bit:_and(buf(9, 1):uint(), 0x7f).. ' Minutes')
		end

		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
    end
	ccp_table:add(0x01a2, CCP_PAR_IPPV_PREVIEW)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x01a2] = {
						["dis"] = ccp_table:get_dissector(0x01a2),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}	
	
	
--[[

Smart Card  :  Product Id Filter Opcode

--]]

	local CCP_PAR_ECM_SC_PRODUCT_ID_FILTER = Proto("CCP_PAR_ECM_SC_PRODUCT_ID_FILTER", "Product ID Filter")
	f_product_id_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_PRODUCT_ID_FILTER.opcode", "Opcode", base.HEX)
	f_product_id_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_PRODUCT_ID_FILTER.length", "Lenngth", base.DEC)
	f_product_id_ecm_id = ProtoField.uint16("CCP_PAR_ECM_SC_PRODUCT_ID_FILTER.product_id", "Product ID", base.HEX)
	
	CCP_PAR_ECM_SC_PRODUCT_ID_FILTER.fields = {f_product_id_ecm_opcode, f_product_id_ecm_length, f_product_id_ecm_id}
	
	function CCP_PAR_ECM_SC_PRODUCT_ID_FILTER.dissector(buf, pkt ,root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xca then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	
		
		local t = root:add(CCP_PAR_ECM_SC_PRODUCT_ID_FILTER, buf(0,  2 + length))
		t:add(f_product_id_ecm_opcode, buf(0,1))
		t:add(f_product_id_ecm_length, buf(1,1))
		t:add(f_product_id_ecm_id, buf(2,2))
	
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	ccp_table:add(0x00ca, CCP_PAR_ECM_SC_PRODUCT_ID_FILTER)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00ca] = {
						["dis"] = ccp_table:get_dissector(0x00ca),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
--[[

Smart Card  :  OVK Version Filter Opcode

--]]

	local CCP_PAR_ECM_SC_OVK_VERSION_FILTER = Proto("CCP_PAR_ECM_SC_OVK_VERSION_FILTER", "OVK Version Filter")
	f_ovk_version_filter_ecm_opcode = ProtoField.uint8("CCP_PAR_ECM_SC_OVK_VERSION_FILTER.opcode", "Opcode", base.HEX)
	f_ovk_version_filter_ecm_length = ProtoField.uint16("CCP_PAR_ECM_SC_OVK_VERSION_FILTER.length", "Lenngth", base.DEC)
	f_ovk_version_filter_ecm_ovk_index = ProtoField.uint8("CCP_PAR_ECM_SC_OVK_VERSION_FILTER.ovk_index", "OVK Index", base.HEX, nil, 0xe0)
	f_ovk_version_filter_ecm_rfu = ProtoField.uint8("CCP_PAR_ECM_SC_OVK_VERSION_FILTER.rfu", "RFU", base.HEX, nil, 0x18)
	f_ovk_version_filter_ecm_ovk_version = ProtoField.uint8("CCP_PAR_ECM_SC_OVK_VERSION_FILTER.ovk_version", "OVK Version", base.HEX, nil, 0x07)
	
	CCP_PAR_ECM_SC_OVK_VERSION_FILTER.fields = {f_ovk_version_filter_ecm_opcode, f_ovk_version_filter_ecm_length, f_ovk_version_filter_ecm_ovk_index, f_ovk_version_filter_ecm_rfu, f_ovk_version_filter_ecm_ovk_version}
	
	function CCP_PAR_ECM_SC_OVK_VERSION_FILTER.dissector(buf, pkt ,root)
		local opcode = buf(0, 1):uint()
		if opcode ~= 0xc0 then
			return false
		end

		local length = buf(1, 1) : uint()
		local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end	
		
		local t = root:add(CCP_PAR_ECM_SC_OVK_VERSION_FILTER, buf(0,  2 + length))
		t:add(f_ovk_version_filter_ecm_opcode, buf(0,1))
		t:add(f_ovk_version_filter_ecm_length, buf(1,1))
		t:add(f_ovk_version_filter_ecm_ovk_index, buf(2,1))
		t:add(f_ovk_version_filter_ecm_rfu, buf(2,1))
		t:add(f_ovk_version_filter_ecm_ovk_version, buf(2,1))
	
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end

		return true
	end
	ccp_table:add(0x02c0, CCP_PAR_ECM_SC_OVK_VERSION_FILTER)
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x02c0] = {
						["dis"] = ccp_table:get_dissector(0x02c0),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	
-------------------------------------------
---------- STUFFING OPCODE ----------------
-------------------------------------------

	local CCP_PAR_STUFFING= Proto("CCP_PAR_STUFFING", "Stuffing Opcode")
	f_stuffing_opcode = ProtoField.uint8("CCP_PAR_STUFFING.Opcode", "Opcode", base.HEX)
	f_stuffing_opcode_length = ProtoField.uint8("CCP_PAR_STUFFING.Opcode_Length", "Stuffing Length", base.DEC)
	f_stuffing_bytes = ProtoField.bytes("CCP_PAR_STUFFING.Stuffing_Bytes", "Stuffing Bytes", base.HEX)

	CCP_PAR_STUFFING.fields = {f_stuffing_opcode, f_stuffing_opcode_length, f_stuffing_bytes}

	function CCP_PAR_STUFFING.dissector(buf, pkt, root)
		local opcode = buf(0,1):uint()
		if not is_stuffing_opcode(opcode) then
			return false
		end
		
		local length = buf(1,1):uint()
        local buf_len = buf:len()
		if buf_len < length + 1 then
			return false
		end
		
		local t= root:add(CCP_PAR_STUFFING, buf(0,length))
		t:add(f_stuffing_opcode, opcode)
		t:add(f_stuffing_opcode_length,buf(1,1))
		t:add(f_stuffing_bytes, buf(2,length))
		
		if ( buf_len - 2 - length > 0) then
			local next_buf = buf( 2 + length, buf_len - 2 - length)
			return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
		end
		
		return true
	end

	ccp_table:add(0x0091, CCP_PAR_STUFFING)
	ccp_table:add(0x008f, CCP_PAR_STUFFING)
	ccp_table:add(0x0003, CCP_PAR_STUFFING)
	ccp_table:add(0x00ff, CCP_PAR_STUFFING)

	-- register ccp opcodes table
	ccp_opcodes_protos[0x0091] = {
						["dis"] = ccp_table:get_dissector(0x0091),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}

	-- register ccp opcodes table
	ccp_opcodes_protos[0x008f] = {
						["dis"] = ccp_table:get_dissector(0x008f),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x0003] = {
						["dis"] = ccp_table:get_dissector(0x0003),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
	
	-- register ccp opcodes table
	ccp_opcodes_protos[0x00ff] = {
						["dis"] = ccp_table:get_dissector(0x00ff),
						["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
	}
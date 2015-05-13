--[[
msp.lua

Inlcudes the Multichoice Standard Protocol dissector function, this file will be loaded by init.lua
Now only support IUC function, other function will be implemented in the future, if you extend the
file, please update the table listed below, thanks for your contribution.

MSP:

Function			Name			Connection			Type			Implemented or Not (Y: Support    X: TODO in Future)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

			Unique EMM    		0x8E			0x12			Y
			Group EMM     		0x8E			0x14			Y
			Global EMM     		0x8E			0x13			Y
IUC			---------------------------------------------------------------------------------------------------------------------------------------------------
			ECM(Secure Chipset)	0x8F			0x12			Y
			ECM(Generic)		0x8F			0x14			Y
					ECM Decryption      0x8F			0x15			Y
					ECM Replacement     0x8F			0x16			Y
			Generic ECM Replacement	0x8F			0x17			Y
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CMD			Shared Transcribe Command 0x45		0x01			Y
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

					Unique EMM			0x0E			0x02			Y
CA2 				Group EMM			0x0E			0x04			Y
Legacy				Global EMM			0x0E			0x06			Y
			---------------------------------------------------------------------------------------------------------------------------------------------------
					ECM					0x0F			0x02			Y

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Support Messages 	RSA Sign 0/1		0x12			0x01			X
Legacy				Get Random Data		0x12			0x03			X
			Crypto Signing Service	0x12			0x04			Y

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

					Unique EMM			0x2E			0x02			Y
CA2 Improved		Group EMM			0x2E			0x04			Y
					Global EMM			0x2E			0x06			Y
			--------------------------------------------------------------------------------------------------------------------------------------------------
					ECM					0x2F			0x02			Y

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

			
Support 			RSA Sign 0			0x32			0x01			X
Messages	
Improved			Get Random DATA		0x32			0x03			X
			
					Create SKE Key pair	0x32			0x04			Y
			
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

					Unique EMM			0x4E			0x02			Y
CA3					Group EMM			0x4E			0x04			Y
					Global EMM			0x4E			0x06			Y
			Global Sector EMM	0x4E			0x07			Y
			--------------------------------------------------------------------------------------------------------------------------------------
					ECM					0x4F			0x02			Y

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

IUC Feedback		Verify MAC			0x92			0x01			Y
IUC Support			Transform Query		0x91			0x11			Y	

-----------------------------------------------------------------------------------------------------------------------------------------------------------------

CCA 2-WAY 			EXI PRIME QUERY		0x92			0x12			Y
CCA 2-WAY 	SECRECT PRIVATE DATA QUERY	0x92			0x13			Y

--]]


--------------------------------
----Import Header Structure-----
--------------------------------

--MSP TABLE
msp_table = DissectorTable.new("MSP_TABLE", "MSP MESSAGE", FT_STRING)

--PROTOCOL TABLE
local protos = {}


----------------------------
-------- VARIABLE ----------
----------------------------

--CWDK NUMBER FLAG (shan wenbin: this flag is per ecm message, it's not so good to define as a global variable. move to opcodes.lua
--cwdk_double_flag = true

--ECM OPCODE FLAG
cca_ecm_opcode_flag = false

--ECM OPCODE FLAG
ca2_ecm_opcode_flag = false

--ECM OPCODE FLAG
ca3_ecm_opcode_flag = false

--CA3 EMM OPCODE FLAG
ca3_emm_opcode_flag = false

--EMERGENCY FLAG
emergency_flag = false


--------------------------------------------------------------------------------------------------------------------------------------------------------------

do

	function is_primes_info_required(conn_type)
		local conn_type_required_primes_info = {[0x2E] = 1, -- CA2 EMM Improved
												[0x2F] = 1, -- CA2 ECM Improved
												[0x30] = 1, -- IPPV Improved
												[0x32] = 1, -- Support Message Improved
												[0x4E] = 1, -- CA3 EMM
												[0x4F] = 1, -- CA3 ECM
												[0x8e] = 1, -- CCA EMM
												[0x8f]  = 1, -- CCA ECM
												[0x92] = 1, -- CCA Feedback/ CCA-2WAY
												[0x45] = 1 -- Shared Transcribe Command
																			}
		if (conn_type_required_primes_info[conn_type] and conn_type_required_primes_info[conn_type] == 1) then
			if conn_type == 0x8f and msg_type == 0x17 then
			-- 0x8f17 do have primes_info. but it's in old_ecm struct'
				return false
			else
				return true
			end
		else
			return false
		end

	end
	
	--[[

	IUC Group EMM Dessector

	--]]

	local CCA_GROUP_EMM = Proto("CCA_GROUP_EMM", "CCA Group EMM")
	f_msg_group_emm_g_prime = ProtoField.bytes("CCA_GROUP_EMM.GPrime", "Group Transformation Seed Prime", base.HEX)
	CCA_GROUP_EMM.fields = { f_msg_group_emm_g_prime}
	function CCA_GROUP_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		--Protocol Info for Group Address EMM
		pkt.cols.info = "CCA Group EMM"
		-- group emm g prime
		local t = root:add(CCA_GROUP_EMM, buf(0,  16))
		t:add( f_msg_group_emm_g_prime, buf(0, 16))
		
		-- parse emm
		local emm = buf(16, buf:len() - 16):tvb()
		if not emm_table:get_dissector(0x03):call(emm, pkt, t) then
			return false
		end

		return true
    end

	-- register msp protocols table
	msp_table:add(0x8e14, CCA_GROUP_EMM)
	protos = {
		[0x8e] = {
					[0x14] = msp_table:get_dissector(0x8e14)
				}
	}

	--[[

	IUC Global EMM Dissector

	--]]

	local CCA_GLOBAL_EMM = Proto("CCA_GLOBAL_EMM", "CCA Global EMM")
	f_msg_global_emm_gb_prime = ProtoField.bytes("CCA_GLOBAL_EMM.GBPrime", "Global Encryption Key Prime",  base.HEX)	
	CCA_GLOBAL_EMM.fields = { f_msg_global_emm_gb_prime}
	
	function CCA_GLOBAL_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		--Protocol Info for Global Address EMM
		pkt.cols.info = "CCA Global EMM"
		-- global encryption key  prime
		local t = root:add(CCA_GLOBAL_EMM, buf(0,  16))
		t:add( f_msg_global_emm_gb_prime, buf(0, 16))

		-- parse emm
		local emm = buf(16, buf:len() - 16):tvb()
		if not emm_table:get_dissector(0x03):call(emm, pkt, t) then
			return false
		end

		return true
    end


	-- register msp protocols table
	msp_table:add(0x8e13, CCA_GLOBAL_EMM)
	if not protos[0x8e] then protos[0x8e] = {} end
	protos[0x8e][0x13] = msp_table:get_dissector(0x8e13)
	
	
	--[[

	IUC Unique EMM Dessector

	--]]

	local CCA_UNIQUE_EMM = Proto("CCA_UNIQUE_EMM", "CCA Unique EMM")
	f_msg_unique_emm_exi_prime = ProtoField.bytes("CCA_UNIQUE_EMM.EXiPrime", "EXiPrime", base.HEX)
	f_msg_unique_emm_u_prime = ProtoField.bytes("CCA_UNIQUE_EMM.UPrime", "UPrime", base.HEX)
	CCA_UNIQUE_EMM.fields = { f_msg_unique_emm_exi_prime, f_msg_unique_emm_u_prime}
	function CCA_UNIQUE_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 32 then
			return false
		end
		--Protocol Info for Unique Address EMM
		pkt.cols.info = "CCA Unique EMM"
		-- unique emm g exi rime and u prime
		local t = root:add(CCA_UNIQUE_EMM, buf(0,  32))
		t:add( f_msg_unique_emm_exi_prime, buf(0, 16))
		t:add( f_msg_unique_emm_u_prime, buf(16, 16))

		-- parse emm
		local emm = buf(32, buf:len() - 32):tvb()
		if not emm_table:get_dissector(0x03):call(emm, pkt, t) then
			return false
		end

		return true
    end
	msp_table:add(0x8e12, CCA_UNIQUE_EMM)
	if not protos[0x8e] then protos[0x8e] = {} end
	protos[0x8e][0x12] = msp_table:get_dissector(0x8e12)

	--[[
	
	CA3 Unique EMM Dessector
	
	--]]
	
	local CA3_UNIQUE_EMM = Proto("CA3_UNIQUE_EMM", "CA3 Unique EMM")
	f_msg_ca3_unique_emm_xek_prime = ProtoField.bytes("CA3_UNIQUE_EMM.XEK_Prime", "XEK Prime", base.HEX)
	
	CA3_UNIQUE_EMM.fields = {f_msg_ca3_unique_emm_xek_prime}
	
	function CA3_UNIQUE_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 192 then
			return false
		end		
			
		--Protocol Info for CA3 Unique Address EMM
		pkt.cols.info = "CA3 Unique EMM"
		-- unique emm xek prime
		local t = root:add(CA3_UNIQUE_EMM, buf(0,  buf_len))
		t:add( f_msg_ca3_unique_emm_xek_prime, buf(0, 192))	
		-- parse emm
		local emm = buf(192, buf:len() - 192):tvb()
		if not emm_table:get_dissector(0x01):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x4e02, CA3_UNIQUE_EMM)
	if not protos[0x4e] then protos[0x4e] = {} end
	protos[0x4e][0x02] = msp_table:get_dissector(0x4e02)

	
	--[[
	
	CA3 Group EMM Dessector
	
	--]]
	
	local CA3_GROUP_EMM = Proto("CA3_GROUP_EMM", "CA3 Group EMM")
	f_msg_ca3_group_emm_gk_prime = ProtoField.bytes("CA3_GROUP_EMM.GK_Prime", "Group Key Prime",  base.HEX)
	f_msg_ca3_group_emm_tk_prime = ProtoField.bytes("CA3_GROUP_EMM.TK_Prime", "Transformation Key Prime",  base.HEX)
	
	CA3_GROUP_EMM.fields = {f_msg_ca3_group_emm_gk_prime, f_msg_ca3_group_emm_tk_prime}
	
	function CA3_GROUP_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 32 then
			return false
		end		
		
		--Protocol Info for CA3 Group Address EMM
		pkt.cols.info = "CA3 Group EMM"
		-- gk prime & tk prime
		local t = root:add(CA3_GROUP_EMM, buf(0,  buf_len))
		t:add( f_msg_ca3_group_emm_gk_prime, buf(0, 16))	
		t:add(f_msg_ca3_group_emm_tk_prime, buf(16,16))
		
		-- parse emm
		local emm = buf(32, buf:len() - 32):tvb()
		ca3_emm_opcode_flag = true
		if not emm_table:get_dissector(0x01):call(emm, pkt, t) then
		    ca3_emm_opcode_flag = false
			return false
		end
		
		ca3_emm_opcode_flag = false
		return true		
	
	end
	msp_table:add(0x4e04, CA3_GROUP_EMM)
	if not protos[0x4e] then protos[0x4e] = {} end
	protos[0x4e][0x04] = msp_table:get_dissector(0x4e04)
	

	--[[
	
	CA3 Global EMM Dessector
	
	--]]
	
	local CA3_GLOBAL_EMM = Proto("CA3_GLOBAL_EMM", "CA3 Global EMM")
	f_msg_ca3_global_emm_uk_prime = ProtoField.bytes("CA3_GLOBAL_EMM.UK_Prime", "Universal Key Prime",  base.HEX)
	
	CA3_GLOBAL_EMM.fields = {f_msg_ca3_global_emm_uk_prime}
	
	function CA3_GLOBAL_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end		
		
		--Protocol Info for CA3 Global EMM
		pkt.cols.info = "CA3 Global EMM"
		-- global emm uk prime
		local t = root:add(CA3_GLOBAL_EMM, buf(0,  buf_len))
		t:add( f_msg_ca3_global_emm_uk_prime, buf(0, 16))	
		-- parse emm
		local emm = buf(16, buf:len() - 16):tvb()
		if not emm_table:get_dissector(0x01):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x4e06, CA3_GLOBAL_EMM)
	if not protos[0x4e] then protos[0x4e] = {} end
	protos[0x4e][0x06] = msp_table:get_dissector(0x4e06)	
	
	
	--[[
	
	CA3 Global Sector EMM Dessector
	
	--]]
	
	local CA3_GLOBAL_SECTOR_EMM = Proto("CA3_GLOBAL_SECTOR_EMM", "CA3 Global Sector EMM")
	f_msg_ca3_global_sector_emm_mode = ProtoField.uint8("CA3_GLOBAL_SECTOR_EMM.EMM_Mode", "EMM Mode",  base.HEX)
	f_msg_ca3_global_sector_emm_pk_prime = ProtoField.bytes("CA3_GLOBAL_SECTOR_EMM.PK_Prime", "PKey Prime",  base.HEX)
	
	CA3_GLOBAL_SECTOR_EMM.fields = {f_msg_ca3_global_sector_emm_mode, f_msg_ca3_global_sector_emm_pk_prime}
	
	function CA3_GLOBAL_SECTOR_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 9 then
			return false
		end		

		--Protocol Info for CA3 Global Sector EMM
		pkt.cols.info = "CA3 Global Sector EMM"
		-- global sector emm pk prime
		local t = root:add(CA3_GLOBAL_SECTOR_EMM, buf(0,  buf_len))
		
		t:add(f_msg_ca3_global_sector_emm_mode, buf(0,1))
		local pk_indicator = bit:_rshift(buf(0,1) :uint(), 7)
		local size = 1
		if pk_indicator == 0 then	
			t:add( f_msg_ca3_global_sector_emm_pk_prime, buf(1, 16))	
			size = size + 16
		else
			t:add(f_msg_ca3_global_sector_emm_pk_prime, buf(1,8))
			size = size + 8
		end
		-- parse emm
		local emm = buf(size, buf:len() - size):tvb()
		if not emm_table:get_dissector(0x01):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x4e07, CA3_GLOBAL_SECTOR_EMM)
	if not protos[0x4e] then protos[0x4e] = {} end
	protos[0x4e][0x07] = msp_table:get_dissector(0x4e07)	
	

	--[[
	
	CA2 Unique EMM Dessector
	
	--]]
	
	local CA2_UNIQUE_EMM = Proto("CA2_UNIQUE_EMM", "CA2 Unique EMM")
	f_msg_ca2_unique_emm_xi_mode = ProtoField.uint8("CA2_UNIQUE_EMM.Xi_Mode", "Xi Mode", base.HEX)
	f_msg_ca2_unique_emm_exi_prime = ProtoField.bytes("CA2_UNIQUE_EMM.EXi_Prime", "Encryption Key Prime",  base.HEX)
	f_msg_ca2_unique_emm_axi_prime = ProtoField.bytes("CA2_UNIQUE_EMM.AXi_Prime", "Authentication Key Prime",  base.HEX)
	
	CA2_UNIQUE_EMM.fields = {f_msg_ca2_unique_emm_xi_mode, f_msg_ca2_unique_emm_exi_prime, f_msg_ca2_unique_emm_axi_prime}
	
	function CA2_UNIQUE_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 33 then
			return false
		end		

		--Protocol Info for CA2 Unique Address EMM
		pkt.cols.info = "CA2 Unique EMM"
		-- unique emm xek prime
		local t = root:add(CA2_UNIQUE_EMM, buf(0,  buf_len))
		t:add( f_msg_ca2_unique_emm_xi_mode, buf(0, 1))	
		t:add(f_msg_ca2_unique_emm_exi_prime, buf(1,16))
		t:add(f_msg_ca2_unique_emm_axi_prime, buf(17,16))
		-- parse emm
		local emm = buf(33, buf:len() - 33):tvb()
		if not emm_table:get_dissector(0x02):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x2e02, CA2_UNIQUE_EMM)
	if not protos[0x2e] then protos[0x2e] = {} end
	protos[0x2e][0x02] = msp_table:get_dissector(0x2e02)
	
	msp_table:add(0x0e02, CA2_UNIQUE_EMM)
	if not protos[0x0e] then protos[0x0e] = {} end
	protos[0x0e][0x02] = msp_table:get_dissector(0x0e02)

	
	--[[
	
	CA2 Group EMM Dessector
	
	--]]
	
	local CA2_GROUP_EMM = Proto("CA2_GROUP_EMM", "CA2 Group EMM")
	f_msg_ca2_group_emm_gk_prime = ProtoField.bytes("CA2_GROUP_EMM.GK_Prime", "Group Key Prime", base.HEX)
	
	CA2_GROUP_EMM.fields = {f_msg_ca2_group_emm_gk_prime}
	
	function CA2_GROUP_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end		

		--Protocol Info for CA2 Group Address EMM
		pkt.cols.info = "CA2 Group EMM"
		-- gk prime
		local t = root:add(CA2_GROUP_EMM, buf(0,  buf_len))
		t:add( f_msg_ca2_group_emm_gk_prime, buf(0, 16))	
	
		-- parse emm
		local emm = buf(16, buf:len() - 16):tvb()
		if not emm_table:get_dissector(0x02):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x2e04, CA2_GROUP_EMM)
	if not protos[0x2e] then protos[0x2e] = {} end
	protos[0x2e][0x04] = msp_table:get_dissector(0x2e04)
	
	msp_table:add(0x0e04, CA2_GROUP_EMM)
	if not protos[0x0e] then protos[0x0e] = {} end
	protos[0x0e][0x04] = msp_table:get_dissector(0x0e04)
	
	--[[
	
	CA2 Global EMM Dessector
	
	--]]
	
	local CA2_GLOBAL_EMM = Proto("CA2_GLOBAL_EMM", "CA2 Global EMM")
	f_msg_ca2_global_emm_eu_prime = ProtoField.bytes("CA2_GLOBAL_EMM.EU_Prime", "Encryption Key Prime", base.HEX)
	f_msg_ca2_global_emm_au_prime = ProtoField.bytes("CA2_GLOBAL_EMM.AU_Prime", "Authentication Key Prime", base.HEX)
	
	CA2_GLOBAL_EMM.fields = {f_msg_ca2_global_emm_eu_prime, f_msg_ca2_global_emm_au_prime}
	
	function CA2_GLOBAL_EMM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 32 then
			return false
		end		
		
		--Protocol Info for CA2 Global EMM
		pkt.cols.info = "CA2 Global EMM"
		-- global emm uk prime
		local t = root:add(CA2_GLOBAL_EMM, buf(0,  buf_len))
		t:add( f_msg_ca2_global_emm_eu_prime, buf(0, 16))	
		t:add(f_msg_ca2_global_emm_au_prime, buf(16,16))
		-- parse emm
		local emm = buf(32, buf:len() - 32):tvb()
		if not emm_table:get_dissector(0x02):call(emm, pkt, t) then
			return false
		end

		return true		
	
	end
	msp_table:add(0x2e06, CA2_GLOBAL_EMM)
	if not protos[0x2e] then protos[0x2e] = {} end
	protos[0x2e][0x06] = msp_table:get_dissector(0x2e06)	
	
	msp_table:add(0x0e06, CA2_GLOBAL_EMM)
	if not protos[0x0e] then protos[0x0e] = {} end
	protos[0x0e][0x06] = msp_table:get_dissector(0x0e06)

	
	--[[

	Support Message : Crypto Signing Service

	--]]

	local Crypto_Signing_Service = Proto("Crypto_Signing_Service", "Crypto Signing Service")
	f_crypto_signing_service_key_identifier_length = ProtoField.uint8("Crypto_Signing_Service.key_identifier_length", "Key Identifier Length", base.DEC)
	f_crypto_signing_service_key_identifier = ProtoField.bytes("Crypto_Signing_Service.key_identifier", "Key Identifier", base.HEX)
	f_crypto_signing_service_sig_algorithm = ProtoField.uint8("Crypto_Signing_Service.sig_algorithm", "Sig Algorithm", base.HEX)
	f_crypto_signing_service_hash_algorithm = ProtoField.uint8("Crypto_Signing_Service.hash_algorithm", "Hash Algorithm", base.HEX)
	f_crypto_signing_service_message = ProtoField.bytes("Crypto_Signing_Service.message", "Message", base.HEX)
	f_crypto_signing_service_payload = ProtoField.bytes("Crypto_Signing_Service.payload", "Payload", base.HEX)
	f_crypto_signing_service_signature = ProtoField.bytes("Crypto_Signing_Service.signature", "Signature", base.HEX)

	Crypto_Signing_Service.fields = {f_crypto_signing_service_key_identifier_length, f_crypto_signing_service_key_identifier, f_crypto_signing_service_sig_algorithm,
									f_crypto_signing_service_hash_algorithm, f_crypto_signing_service_message, f_crypto_signing_service_payload, f_crypto_signing_service_signature}

	function Crypto_Signing_Service.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		--Protocol Info for Support Messages Legacy : Crypto Signing Service
		pkt.cols.info = "Crypto Signing Service"
		local t = root:add(Crypto_Signing_Service, buf(0,  buf_len))
		local kil = buf(0,1) :uint() -- SCAME-0-S-RSA-1024
		if kil ~= 18  then
			t:add(f_crypto_signing_service_signature, buf(1,buf_len-1))
			return false
		 end
		t:add(f_crypto_signing_service_key_identifier_length, buf(0,1))
		t:add(f_crypto_signing_service_key_identifier, buf(1, kil))
		t:add(f_crypto_signing_service_sig_algorithm, buf(1+kil, 1))
		t:add(f_crypto_signing_service_hash_algorithm, buf(1+kil+1, 1))
		t:add(f_crypto_signing_service_message, buf(1+kil+1+1, 4))

		--parse emm
		local payload = buf(1+kil+1+1+4, buf_len - 7- kil) :tvb()
		if not ccp_table:get_dissector(0xFFFF):call(payload, pkt, t) then
			return false
		end

		return true
	end

	msp_table:add(0x1204, Crypto_Signing_Service)
	if not protos[0x12] then protos[0x12] = {} end
	protos[0x12][0x04] = msp_table:get_dissector(0x1204)

	--[[
	
	Create SKE Key pair (SCA)
	
	--]]
	
	local Create_SKEKey_pair = Proto("Create_SKEKey_pair", "create ske key pair")
	f_create_ske_key_type = ProtoField.uint8("Create_SKEKey_pair.keytype", "SKE Key Type", base.DEC)
	f_create_ske_length = ProtoField.uint16("Create_SKEKey_pair.length", "Length", base.DEC)
	f_create_ske_rfu = ProtoField.uint8("Create_SKEKey_pair.rfu", "Reserved", base.DEC)	
	f_create_ske_skepk_primaryseedname_length = ProtoField.uint8("Create_SKEKey_pair.skepk_primaryseedname_length", "skepk primaryseedname length", base.DEC)
	f_create_ske_skepk_primaryseedname_byte = ProtoField.bytes("Create_SKEKey_pair.skepk_primaryseedname_byte", "skepk primaryseedname byte", base.HEX)
	Create_SKEKey_pair.fields = {f_create_ske_key_type, f_create_ske_length, f_create_ske_rfu, f_create_ske_skepk_primaryseedname_length, f_create_ske_skepk_primaryseedname_byte}
	
	function Create_SKEKey_pair.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		
		pkt.cols.info = "Create SKE Key pair"
		local t = root:add(Create_SKEKey_pair, buf(0, buf_len))
		t:add(f_create_ske_key_type, buf(0,1))
		t:add(f_create_ske_length, buf(1,2))
		t:add(f_create_ske_rfu, buf(3,1))
		t:add(f_create_ske_skepk_primaryseedname_length, buf(4,1))
		t:add(f_create_ske_skepk_primaryseedname_byte, buf(5,buf_len-5))
	end
	
	msp_table:add(0x3204, Create_SKEKey_pair)
	if not protos[0x32] then protos[0x32] = {} end
	protos[0x32][0x04] = msp_table:get_dissector(0x3204)
	
	
	--[[

	Shared Key Transcribe Command : Shared  Key Transcribe Command

	--]]
	
	local SHARED_KEY_TRANSCRIBE_COMMAND = Proto("SHARED_KEY_TRANSCRIBE_COMMAND", "SHARED_KEY_TRANSCRIBE_COMMAND")
	local NEED_TO_TRANSCRIBE_KEYS       = Proto("NEED_TO_TRANSCRIBE_KEYS", "Need to transcribe keys")
	f_shared_key_transcribe_command_commandid = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.commandid", "Command ID", base.HEX)
	f_shared_key_transcribe_command_length = ProtoField.uint16("SHARED_KEY_TRANSCRIBE_COMMAND.length", "Length", base.DEC)
	f_shared_key_transcribe_command_conversiontype  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.conversiontype", "Conversion Type ", base.HEX, nil, 0x80)
	f_shared_key_transcribe_command_rfu1  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.rfu1", "RFU1", base.HEX, nil, 0x7E)
	f_shared_key_transcribe_command_sharedkey  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.sharedkey", "Shared Key ", base.HEX, nil, 0x1)
	f_shared_key_transcribe_command_rfu2  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.rfu2", "RFU2 ", base.HEX, nil, 0xFE)
	f_shared_key_transcribe_command_privatekey  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.privatekey", "Private Key", base.HEX, nil, 0x1)
	f_shared_key_transcribe_command_numberofkeys  = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.numberofkeys", "Number of Keys", base.DEC)
	f_shared_key_transcribe_command_keylength = ProtoField.uint8("SHARED_KEY_TRANSCRIBE_COMMAND.keylength", "Key Length", base.DEC)
	f_shared_key_transcribe_command_key = ProtoField.bytes("SHARED_KEY_TRANSCRIBE_COMMAND.key", "Key", base.HEX)
	
	SHARED_KEY_TRANSCRIBE_COMMAND.fields = {f_shared_key_transcribe_command_commandid, f_shared_key_transcribe_command_length, 
											f_shared_key_transcribe_command_conversiontype,f_shared_key_transcribe_command_rfu1,
											f_shared_key_transcribe_command_sharedkey,f_shared_key_transcribe_command_rfu2,
											f_shared_key_transcribe_command_privatekey,f_shared_key_transcribe_command_numberofkeys,
											f_shared_key_transcribe_command_keylength,f_shared_key_transcribe_command_key}
	
	function SHARED_KEY_TRANSCRIBE_COMMAND.dissector(buf, pkt, root)
	    local length = buf(1,2) : uint()
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end	
		
		--Protocol Info for IUC Feedback Verify MAC Message
		pkt.cols.info = "Shared Key Transcribe Command"
		local t = root:add(SHARED_KEY_TRANSCRIBE_COMMAND, buf(0, buf_len))
		t:add(f_shared_key_transcribe_command_commandid, buf(0,1))
		t:add(f_shared_key_transcribe_command_length, buf(1,2))
		t:add(f_shared_key_transcribe_command_conversiontype, buf(3, 1))
		t:add(f_shared_key_transcribe_command_rfu1, buf(3, 1) )
		t:add(f_shared_key_transcribe_command_sharedkey, buf(3, 1))
		t:add(f_shared_key_transcribe_command_rfu2, buf(4, 1))
		t:add(f_shared_key_transcribe_command_privatekey, buf(4, 1) )
		t:add(f_shared_key_transcribe_command_numberofkeys, buf(5, 1))
		t:add(f_shared_key_transcribe_command_keylength, buf(6, 1))
		local keysNumber = ( buf_len - 7) / 16
		for i=0, keysNumber-1 do
			local pt= t:add(NEED_TO_TRANSCRIBE_KEYS, buf(7+i*16, 16))
			pt:add(f_shared_key_transcribe_command_key, buf(7+i*16, 16))
		end			
	end

	msp_table:add(0x4501, SHARED_KEY_TRANSCRIBE_COMMAND)
	if not protos[0x45] then 
		protos[0x45] = {} 
	end
	protos[0x45][0x01] = msp_table:get_dissector(0x4501)
	
	--[[

	IUC Feedback : Verify MAC Message

	--]]
	local CCA_VERIFY_MAC = Proto("CCA_VERIFY_MAC", "CCA Verify MAC")
	f_verify_mac_exi = ProtoField.bytes("CCA_VERIFY_MAC.exi", "EXI Key", base.HEX)
	f_verify_mac_u = ProtoField.bytes("CCA_VERIFY_MAC.u", "U Key", base.HEX)
	f_verify_mac_client_tran_data = ProtoField.bytes("CCA_VERIFY_MAC.client_tran_data", "Client Transaction Data", base.HEX)

	CCA_VERIFY_MAC.fields = {f_verify_mac_exi, f_verify_mac_u, f_verify_mac_client_tran_data}

	function CCA_VERIFY_MAC.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		--Protocol Info for IUC Feedback Verify MAC Message
		pkt.cols.info = "CCA Feedback - Verify MAC Message"
		local t = root:add(CCA_VERIFY_MAC, buf(0, buf_len))
		t:add(f_verify_mac_exi, buf(0,16))
		t:add(f_verify_mac_u, buf(16,16))
		t:add(f_verify_mac_client_tran_data, buf(32, buf_len-32))

	end

	msp_table:add(0x9201, CCA_VERIFY_MAC)
	if not protos[0x92] then protos[0x92] = {} end
	protos[0x92][0x01] = msp_table:get_dissector(0x9201)
	
	--[[

	CCA Support : Transform Query

	--]]
	local CCA_TRANSFORM_QUERY = Proto("CCA_TRANSFORM_QUERY", "CCA Transform Query")
	f_cca_tq_cgl = ProtoField.uint8("CCA_TRANSFORM_QUERY.cgl", "CG Element Number", base.DEC)
	f_cca_tq_cg_element = ProtoField.bytes("CCA_TRANSFORM_QUERY.element", "CG Elements", base.HEX)
	f_cca_tq_onl = ProtoField.uint8("CCA_TRANSFORM_QUERY.onl", "Length of Operator Name", base.DEC)
	f_cca_tq_operator_name = ProtoField.bytes("CCA_TRANSFORM_QUERY.on", "Operator Name", base.HEX)

	CCA_TRANSFORM_QUERY.fields = {f_cca_tq_cgl, f_cca_tq_cg_element, f_cca_tq_onl, f_cca_tq_operator_name}

	function CCA_TRANSFORM_QUERY.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		--Protocol Info for CCA Support Transform Query
		pkt.cols.info = "CCA Support - Transform Query"
		local t = root:add(CCA_TRANSFORM_QUERY, buf(0, buf_len))
		t:add(f_cca_tq_cgl, buf(0,1))
		local cgl = buf(0,1):uint()
		t:add(f_cca_tq_cg_element, buf(1,cgl))
		t:add(f_cca_tq_onl, buf(1+cgl, 1))
		local onl = buf(1+cgl, 1):uint()
		t:add(f_cca_tq_operator_name, buf(2+cgl, onl))
		return true
	end

	msp_table:add(0x9111, CCA_TRANSFORM_QUERY)
	if not protos[0x91] then protos[0x91] = {} end
	protos[0x91][0x11] = msp_table:get_dissector(0x9111)
	
	--[[
	
	
	CA2 ECM Header Dessector
	
	--]]
	
	local CA2_ECM_HEADER = Proto("CA2_ECM_HEADER", "CA2 ECM Header")
	f_header_ca2_product_id = ProtoField.uint16("CA2_ECM_HEADER.product_id", "Product ID", base.DEC)
	f_header_ca2_sector_number = ProtoField.uint8("CA2_ECM_HEADER.product_id", "Sector Number", base.DEC, nil, 0xf0)
	f_header_ca2_cypher_selection = ProtoField.uint8("CA2_ECM_HEADER.cypher_selection", "Cypher Selection", base.DEC, nil, 0x08)
	f_header_ca2_cw_encryption_indicator = ProtoField.uint8("CA2_ECM_HEADER.cw_encryption_indicator", "CW Encryption Indicator", base.DEC, nil, 0x04)
	f_header_ca2_must_expire = ProtoField.uint8("CA2_ECM_HEADER.must_expire", "Must Expire", base.DEC, nil, 0x02)
	f_header_ca2_record_product = ProtoField.uint8("CA2_ECM_HEADER.record_product", "Record Product", base.DEC, nil, 0x01)
	f_header_ca2_cci_analogue = ProtoField.uint8("CA2_ECM_HEADER.cci_analogue", "CCI Analogue", base.DEC, nil, 0xc0)
	f_header_ca2_pk_index = ProtoField.uint8("CA2_ECM_HEADER.pk_index", "Product Key Index", base.DEC, nil, 0x3e)
	f_header_ca2_non_share_able_flag = ProtoField.uint8("CA2_ECM_HEADER.non_share_able_flag", "non shareable flag", base.HEX, nil, 0x01)
	f_header_ca2_non_pvr_able_flag = ProtoField.uint8("CA2_ECM_HEADER.non_pvr_able_flag", "Non PVR Able Flag", base.DEC, nil, 0x80)
	f_header_ca2_cci_digital = ProtoField.uint8("CA2_ECM_HEADER.cci_digital", "CCI Digital", base.DEC, nil, 0x60)
	f_header_ca2_record_ecm = ProtoField.uint8("CA2_ECM_HEADER.record_ecm", "Record ECM", base.DEC, nil, 0x10)
	f_header_ca2_pk_version_number = ProtoField.uint8("CA2_ECM_HEADER.pk_version_number", "Product Key Version Number", base.DEC, nil, 0x0e)
	f_header_ca2_ecm_header_version = ProtoField.uint8("CA2_ECM_HEADER.ecm_header_version", "ECM Header Version", base.DEC, nil, 0x01)
	f_header_ca2_payload_length = ProtoField.uint8("CA2_ECM_HEADER.payload_length", "Payload Length", base.DEC)
	
	
	CA2_ECM_HEADER.fields = {f_header_ca2_product_id, f_header_ca2_sector_number, f_header_ca2_cypher_selection, f_header_ca2_cw_encryption_indicator,
													f_header_ca2_must_expire, f_header_ca2_record_product, f_header_ca2_cci_analogue, f_header_ca2_pk_index, f_header_ca2_non_share_able_flag,
													f_header_ca2_non_pvr_able_flag, f_header_ca2_cci_digital, f_header_ca2_record_ecm, f_header_ca2_pk_version_number,
													f_header_ca2_ecm_header_version, f_header_ca2_payload_length}
													
	function CA2_ECM_HEADER.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 6 then
			return false
		end
												

		-- ecm header
		local t = root:add(CA2_ECM_HEADER, buf(0,  buf_len))
		t:add(f_header_ca2_product_id, buf(0,2))
		t:add(f_header_ca2_sector_number, buf(2,1))
		t:add(f_header_ca2_cypher_selection, buf(2,1))
		t:add(f_header_ca2_cw_encryption_indicator, buf(2,1))
		t:add(f_header_ca2_must_expire, buf(2,1))
		t:add(f_header_ca2_record_product, buf(2,1))
		t:add(f_header_ca2_cci_analogue, buf(3,1))
		t:add(f_header_ca2_pk_index, buf(3,1))
		t:add(f_header_ca2_non_share_able_flag, buf(3,1))
		t:add(f_header_ca2_non_pvr_able_flag, buf(4,1))
		t:add(f_header_ca2_cci_digital, buf(4,1))
		t:add(f_header_ca2_record_ecm, buf(4,1))
		t:add(f_header_ca2_pk_version_number, buf(4,1))
		t:add(f_header_ca2_ecm_header_version, buf(4,1))
		t:add(f_header_ca2_payload_length, buf(5,1))


		local ecm = buf(6, buf:len() - 6):tvb()
		local opt = root:add(ECM_OPCODES, buf(6, buf:len() - 6))
		
		-- parse ecm
		if not ccp_table:get_dissector(0xFFFF):call(ecm, pkt, opt) then
			return false
		end
		
		return true
    end		

	msp_table:add(0xFFEC, CA2_ECM_HEADER)	
	
	--[[
	
	CA3 ECM Header Dessector
	
	--]]
	
	local CA3_ECM_HEADER  = Proto("CA3_ECM_HEADER", "CA3 ECM Header")
	f_header_ca3_ipr_enforce = ProtoField.uint8("CA3_ECM_HEADER.iprEnforcement", "IPR Enforcement", base.DEC, nil, 0x80)
	f_header_ca3_ci_security_level = ProtoField.uint8("CA3_ECM_HEADER.ci_security_level", "CI Security Level", base.DEC, nil, 0x70)
	f_header_ca3_reserved1 = ProtoField.uint8("CA3_ECM_HEADER.reserved1", "Reserved", base.HEX, nil, 0x0f)
	f_header_ca3_reserved2 = ProtoField.uint8("CA3_ECM_HEADER.reserved2", "Reserved", base.HEX, nil, 0xff)
	f_header_ca3_super_ecm_flag = ProtoField.uint8("CA3_ECM_HEADER.super_ecm_flag", "Super ECM Flag", base.DEC, nil, 0x80)
	f_header_ca3_sector_number = ProtoField.uint8("CA3_ECM_HEADER.sector_number", "Sector Number", base.DEC, nil, 0x70)
	f_header_ca3_reserved3 = ProtoField.uint8("CA3_ECM_HEADER.reserved3", "Reserved", base.HEX, nil, 0x08)
	f_header_ca3_cw_encryption_flag = ProtoField.uint8("CA3_ECM_HEADER.cw_encryption_flag", "CW Encryption Flag", base.DEC, nil, 0x04)
	f_header_ca3_must_expire = ProtoField.uint8("CA3_ECM_HEADER.must_expire", "Must Expire", base.DEC, nil, 0x02)
	f_header_ca3_reserved4 = ProtoField.uint8("CA3_ECM_HEADER.reserved4", "Reserved", base.HEX, nil, 0x01)
	f_header_ca3_cci_analog = ProtoField.uint8("CA3_ECM_HEADER.cci_analog", "CCI Analog", base.DEC, nil, 0xc0)
	f_header_ca3_pk_index =ProtoField.uint8("CA3_ECM_HEADER.pk_index", "PK Index", base.DEC, nil, 0x3e)
	f_header_ca3_non_share_able_flag = ProtoField.uint8("CA3_ECM_HEADER.non_share_able_flag", "non shareable flag", base.HEX, nil, 0x01)
	f_header_ca3_non_pvr_able_flag = ProtoField.uint8("CA3_ECM_HEADER.non_pvr_able_flag", "Non Pvrable Flag", base.DEC, nil, 0x80)
	f_header_ca3_cci_digital = ProtoField.uint8("CA3_ECM_HEADER.cci_digital", "CCI Digital", base.DEC, nil, 0x60)
	f_header_ca3_record_ecm = ProtoField.uint8("CA3_ECM_HEADER.record_ecm", "Record ECM", base.DEC, nil, 0x10)
	f_header_ca3_reserved6 = ProtoField.uint8("CA3_ECM_HEADER.reserved6", "Reserved", base.HEX, nil, 0x0c)
	f_header_ca3_ccp_version = ProtoField.uint8("CA3_ECM_HEADER.ccp_version", "CCP Version", base.DEC, nil, 0x03)
	f_header_ca3_length = ProtoField.uint8("CA3_ECM_HEADER.length", "Payload Length", base.DEC)
	f_header_ca3_payload = ProtoField.bytes("CA3_ECM_HEADER.payload", "Payload", base.HEX)
	
	CA3_ECM_HEADER.fields = {f_header_ca3_ipr_enforce, f_header_ca3_ci_security_level, f_header_ca3_super_ecm_flag, f_header_ca3_sector_number,
												f_header_ca3_cw_encryption_flag, f_header_ca3_must_expire, f_header_ca3_cci_analog, f_header_ca3_pk_index, f_header_ca3_non_pvr_able_flag,
												f_header_ca3_cci_digital, f_header_ca3_record_ecm, f_header_ca3_ccp_version, f_header_ca3_reserved1, f_header_ca3_length,
												f_header_ca3_payload, f_header_ca3_reserved2, f_header_ca3_reserved3, f_header_ca3_reserved4, f_header_ca3_non_share_able_flag, f_header_ca3_reserved6}

	function CA3_ECM_HEADER.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 6 then
			return false
		end
										

		-- ecm header
		local t = root:add(CA3_ECM_HEADER, buf(0,  buf_len))
		t:add(f_header_ca3_ipr_enforce, buf(0,1))
		t:add(f_header_ca3_ci_security_level, buf(0,1))
		t:add(f_header_ca3_reserved1, buf(0,1))
		t:add(f_header_ca3_reserved2, buf(1,1))
		t:add(f_header_ca3_super_ecm_flag, buf(2,1))
		t:add(f_header_ca3_sector_number, buf(2,1))
		t:add(f_header_ca3_reserved3, buf(2,1))
		t:add(f_header_ca3_cw_encryption_flag, buf(2,1))
		t:add(f_header_ca3_must_expire, buf(2,1))
		t:add(f_header_ca3_reserved4,buf(2,1))
		t:add(f_header_ca3_cci_analog, buf(3,1))
		t:add(f_header_ca3_pk_index, buf(3,1))
		t:add(f_header_ca3_non_share_able_flag, buf(3,1))
		t:add(f_header_ca3_non_pvr_able_flag, buf(4,1))
		t:add(f_header_ca3_cci_digital, buf(4,1))
		t:add(f_header_ca3_record_ecm, buf(4,1))
		t:add(f_header_ca3_reserved6, buf(4,1))
		t:add(f_header_ca3_ccp_version, buf(4,1))
		t:add(f_header_ca3_length, buf(5,1))


		local ecm = buf(6, buf:len() - 6) :tvb()
		local opt = root:add(ECM_OPCODES, buf(6, buf:len() - 6))
		
		-- parse ecm
		if not ccp_table:get_dissector(0xFFFF):call(ecm, pkt, opt) then
			return false
		end
		
		return true
    end		

	msp_table:add(0xFFED, CA3_ECM_HEADER)	
	
	
	--[[
	
	Generic IUC ECM Header Dessector
	
	--]]
	
	local IUC_ECM_HEADER = Proto("IUC_ECM_HEADER", "Cloaked CA ECM Header")

	--0,1
	f_msg_product_id = ProtoField.bytes("IUC_ECM_HEADER.ProductId", "Product ID", base.HEX)
	--2,1 0,1
	f_msg_reserved1 = ProtoField.uint8("IUC_ECM_HEADER.Reserved1", "Reserved", base.HEX, nil, 0x80)
	--2,1 1,3
	f_msg_sector_number = ProtoField.uint8("IUC_ECM_HEADER.SectorNumber", "Sector Numeber", base.DEC, nil, 0x70)
	--2,1 4,1
	f_msg_reserved2 = ProtoField.uint8("IUC_ECM_HEADER.Reserved2","Reserved", base.HEX, nil, 0x08)
	--2,1 5,1
	f_msg_cw_encryption_indicator = ProtoField.uint8("IUC_ECM_HEADER.EncryptionIndicator", "Encryption Indicator", base.DEC, nil, 0x04)
	--2,1 6,2
	f_msg_reserved3 = ProtoField.uint8("IUC_ECM_HEADER.Reserved3", "Reserved", base.HEX, nil, 0x03)
    --3,1 0,2
	f_msg_cci_Analogue = ProtoField.uint8("IUC_ECM_HEADER.CCIAnalogue", "CCI Analogue", base.HEX, nil, 0xc0)
	--3,1 2,5
	f_msg_product_key_index = ProtoField.uint8("IUC_ECM_HEADER.ProductKeyIndex", "Product Key Index", base.DEC, nil, 0x3e)
	--3,1 7,1
	f_msg_non_share_able_flag = ProtoField.uint8("IUC_ECM_HEADER.non_share_able_flag", "non shareable flag", base.HEX, nil, 0x01)
	--4,1 0,1
	f_msg_non_pvr_able_flag = ProtoField.uint8("IUC_ECM_HEADER.NonPvrAbaleFlag", "Non PVR Able Flag", base.DEC, nil, 0x80)
	--4,1 1,2
	f_msg_cci_digital = ProtoField.uint8("IUC_ECM_HEADER.CCIDigital", "CCI Digital", base.HEX, nil, 0x60)
	--4,1 3,3
	f_msg_reserved5 = ProtoField.uint8("IUC_ECM_HEADER.Reserved5", "Reserved", base.HEX, nil, 0x1c)
	--4,1 6,2
	f_msg_ecm_header_version = ProtoField.uint8("IUC_ECM_HEADER.HeaderVersion", "ECM Header Version", base.HEX, nil, 0x03)
	--5,1
	f_msg_ecm_length = ProtoField.uint16("IUC_ECM_HEADER.Length", "ECM Length", base.DEC)
	f_msg_ext_ecm_header_length = ProtoField.bytes("IUC_ECM_HEADER.ExtHeaderLength", "Extend Header Length", base.DEC)
	f_msg_ext_product_id = ProtoField.bytes("IUC_ECM_HEADER.ExtProductID", "Extend Product ID", base.HEX)
	f_msg_ext_header = ProtoField.bytes("IUC_ECM_HEADER.ExtHeader", "Extend Header", base.HEX)
	f_msg_ecm_payload = ProtoField.bytes("IUC_ECM_HEADER.Payload", "ECM Payload", base.HEX)

	IUC_ECM_HEADER.fields = { f_msg_product_id, f_msg_reserved1, f_msg_sector_number, f_msg_reserved2, f_msg_cw_encryption_indicator, f_msg_reserved3, f_msg_cci_Analogue, f_msg_product_key_index, f_msg_non_share_able_flag, f_msg_non_pvr_able_flag, f_msg_cci_digital, f_msg_reserved5, f_msg_ecm_header_version, f_msg_ecm_length, f_msg_ext_ecm_header_length, f_msg_ext_product_id, f_msg_ext_header, f_msg_ecm_payload}
	function IUC_ECM_HEADER.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 6 then
			return false
		end
		-- --Protocol Info for IUC ECM(Generic, Secure Chipset)
		-- pkt.cols.info = "General ECM"
		-- ecm header
		local t = root:add(IUC_ECM_HEADER, buf(0,  buf_len))
		t:add( f_msg_product_id, buf(0, 2))
		t:add( f_msg_reserved1, buf(2,1))
		t:add( f_msg_sector_number, buf(2,1))
		t:add( f_msg_reserved2, buf(2,1))
		t:add( f_msg_cw_encryption_indicator, buf(2,1))
		t:add( f_msg_reserved3, buf(2,1))
		t:add( f_msg_cci_Analogue, buf(3,1))
		t:add( f_msg_product_key_index, buf(3,1))
		t:add( f_msg_non_share_able_flag, buf(3,1))
		t:add( f_msg_non_pvr_able_flag, buf(4,1))
		t:add( f_msg_cci_digital, buf(4,1))
		t:add( f_msg_reserved5, buf(4,1))
		t:add( f_msg_ecm_header_version, buf(4,1))
		t:add( f_msg_ecm_length, buf(5, 1))

		local var = 6
		local productid = buf(0, 2):uint()
		if productid == 0xff48 then
			t:add( f_msg_ext_ecm_header_length, buf(6, 1))
			t:add( f_msg_ext_product_id, buf(7, 2))
			
			local ext_product_id = buf(7,2):uint()
			if ext_product_id == 0xffff then
				emergency_flag = true
			else
				emergency_flag = false
			end
			
			local x = buf(6,1) :uint() +1
			if x-3 > 0 then
				t:add( f_msg_ext_header, buf(9, x-3))
			end
			var = var +x
		end
		
		if buf(5, 1):uint() == 0 then 
			return true
		end
		
		-- after svod for cca is introduced. Not all vod has only 1 cwdk. so this flag will be determined by service key opcode length
		--if productid == 0xff48  then
		-- Update the cwdk flag, then the service key opcode will take 1 cwdk 
		--	cwdk_double_flag = false
		--else
		--	cwdk_double_flag = true
		--end
		t:add( f_msg_ecm_payload, buf(var, buf:len()-var))
		local opt = root:add(ECM_OPCODES, buf(6, buf:len() - 6))
		
		--Opcode in ECM Flag
		cca_ecm_opcode_flag = true
		-- parse ecm
		if not ccp_table:get_dissector(0xFFFF):call(buf(var, buf:len() - var):tvb(), pkt, opt) then
			cca_ecm_opcode_flag = false
			return false
		end
		
		cca_ecm_opcode_flag = false
		return true
    end
	
	msp_table:add(0xFFEE, IUC_ECM_HEADER)
	
	
	--[[

	IUC ECM dessector

	--]]

	local IUC_ECM = Proto("IUC_ECM", "Cloaked CA ECM")
	f_msg_iuc_ecm_pseed_prime = ProtoField.bytes("IUC_ECM.P_Seed", "Product Transformation Seed")
	
	IUC_ECM.fields = {f_msg_iuc_ecm_pseed_prime}

	function IUC_ECM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		--Protocol Info for IUC ECM(Generic, Secure Chipset)
		pkt.cols.info = "Cloaked CA ECM"
		-- ecm header
		local t = root:add(IUC_ECM, buf(0,  buf_len))
		t:add(f_msg_iuc_ecm_pseed_prime, buf(0,16))

		local ecm = buf(16, buf:len() - 16) :tvb()		
		-- parse ecm
		if not msp_table:get_dissector(0xFFEE):call(ecm, pkt, t) then
			return false
		end

		return true
    end

	msp_table:add(0x8f14, IUC_ECM)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x14]  = msp_table:get_dissector(0x8f14)
	
	msp_table:add(0x8f13, IUC_ECM)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x13]  = msp_table:get_dissector(0x8f13)

	msp_table:add(0x8f12, IUC_ECM)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x12]  = msp_table:get_dissector(0x8f12)
	
	
	--[[

	IUC ECM Decryption

	--]]

	local IUC_ECM_DECRYPTION = Proto("IUC_ECM_DECRYPTION", "Clokaed CA ECM Decryption")
	f_msg_iuc_decryption_tg_old = ProtoField.uint8("IUC_ECM_DECRYPTION.tg_old", "Old TG", base.DEC)
	f_msg_iuc_decryption_cwdk_old_version = ProtoField.uint8("IUC_ECM_DECRYPTION.cwdk_old_version", "Old CWDK Version", base.DEC)
	f_msg_iuc_decryption_cwdk = ProtoField.bytes("IUC_ECM_DECRYPTION.cwdk_old", "Old CWDK", base.HEX)
	f_msg_iuc_decryption_pseed_prime = ProtoField.bytes("IUC_ECM_DECRYPTION.p_seed", "Old Product Key")
	f_msg_iuc_decryption_old_ecm = ProtoField.bytes("IUC_ECM_DECRYPTION.old_ecm", "Old ECM section")
	
	IUC_ECM_DECRYPTION.fields = {f_msg_iuc_decryption_tg_old, f_msg_iuc_decryption_cwdk_old_version, f_msg_iuc_decryption_cwdk, f_msg_iuc_decryption_pseed_prime, f_msg_iuc_decryption_old_ecm}

	function IUC_ECM_DECRYPTION.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 34 then
			return false
		end
		--Protocol Info for IUC ECM Decryption Message
		pkt.cols.info = "CCA ECM Decryption"
		-- ecm header
		local t = root:add(IUC_ECM_DECRYPTION, buf(0,  buf_len))
		t:add(f_msg_iuc_decryption_tg_old, buf(0,1))
		t:add(f_msg_iuc_decryption_cwdk_old_version, buf(1,1))
		t:add(f_msg_iuc_decryption_cwdk, buf(2, 16))
		t:add(f_msg_iuc_decryption_pseed_prime, buf(18, 16))
		t:add(f_msg_iuc_decryption_old_ecm, buf(34, buf_Len-34))

		local old_ecm = buf(34, buf:len() - 34) :tvb()
		
		
		-- parse ecm
		if not msp_table:get_dissector(0xFFEE):call(old_ecm, pkt, t) then
			return false
		end

		return true
    end

	msp_table:add(0x8f15, IUC_ECM_DECRYPTION)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x15]  = msp_table:get_dissector(0x8f15)
	
	--[[

	IUC ECM Replacement

	--]]

	local IUC_ECM_REPLACEMENT = Proto("IUC_ECM_REPLACEMENT", "Clokaed CA ECM Replacement")
	f_msg_iuc_replacement_tg_old = ProtoField.uint8("IUC_ECM_REPLACEMENT.tg_old", "Old TG", base.HEX)
	f_msg_iuc_replacement_tg_new = ProtoField.uint8("IUC_ECM_REPLACEMENT.tg_new", "New TG", base.HEX)
	f_msg_iuc_replacement_cwdk_old_version = ProtoField.int8("IUC_ECM_REPLACEMENT.cwdk_old_version", "Old CWDK Version", base.DEC)
	f_msg_iuc_replacement_cwdk_old = ProtoField.bytes("IUC_ECM_REPLACEMENT.cwdk_old", "Old CWDK", base.HEX)
	f_msg_iuc_replacement_cwdk_new_count = ProtoField.uint8("IUC_ECM_REPLACEMENT.cwdk_new_count", "New CWDK Count", base.DEC)
	f_msg_iuc_replacement_cwdk_new_version = ProtoField.int8("IUC_ECM_REPLACEMENT.cwdk_new_version", "New CWDK Version", base.DEC)
	f_msg_iuc_replacement_cwdk_new = ProtoField.bytes("IUC_ECM_REPLACEMENT.cwdk_new", "New CWDK", base.HEX)
	f_msg_iuc_replacement_pseed_prime_old = ProtoField.bytes("IUC_ECM_REPLACEMENT.p_seed_old", "Old Product Key", base.HEX)
	f_msg_iuc_replacement_pseed_prime_new = ProtoField.bytes("IUC_ECM_REPLACEMENT.p_seed_new", "New Product Key", base.HEX)
	f_msg_iuc_replacement_old_ecm = ProtoField.bytes("IUC_ECM_REPLACEMENT.old_ecm", "Old ECM section", base.HEX)
	
	IUC_ECM_REPLACEMENT.fields = {f_msg_iuc_replacement_tg_old, f_msg_iuc_replacement_tg_new, f_msg_iuc_replacement_cwdk_old_version, f_msg_iuc_replacement_cwdk_old,
															f_msg_iuc_replacement_cwdk_new_count, f_msg_iuc_replacement_cwdk_new_version, f_msg_iuc_replacement_cwdk_new, f_msg_iuc_replacement_pseed_prime_old,
															f_msg_iuc_replacement_pseed_prime_new, f_msg_iuc_replacement_old_ecm}

	function IUC_ECM_REPLACEMENT.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		--Protocol Info for IUC ECM Replacement Message
		pkt.cols.info = "CCA ECM Replacement"
		-- ecm header
		local t = root:add(IUC_ECM_REPLACEMENT, buf(0,  buf_len))
		t:add(f_msg_iuc_replacement_tg_old, buf(0,1))
		t:add(f_msg_iuc_replacement_tg_new, buf(1,1))
		t:add(f_msg_iuc_replacement_cwdk_old_version, buf(2, 1))
		t:add(f_msg_iuc_replacement_cwdk_old, buf(3, 16))
		t:add(f_msg_iuc_replacement_cwdk_new_count, buf(19, 1))
		t:add(f_msg_iuc_replacement_cwdk_new_version, buf(20,1))
		
		local i=0
		local cwdk_new_count = buf(19,1):uint()
		while i< cwdk_new_count do
			t:add(f_msg_iuc_replacement_cwdk_new,  buf(21+ i*16, 16))
			i = i + 1
		
		end
		
		t:add(f_msg_iuc_replacement_pseed_prime_old, buf(21+ i*16, 16))
		t:add(f_msg_iuc_replacement_pseed_prime_new, buf(21 + (i+1)*16, 16))
		t:add(f_msg_iuc_replacement_old_ecm, buf(21+(i+2)*16, buf_len- 21- (i+2)*16))

		local old_ecm = buf(21+(i+2)*16, buf_len- 21- (i+2)*16) :tvb()
		
		-- parse ecm
		if not msp_table:get_dissector(0xFFEE):call(old_ecm, pkt, t) then
			return false
		end

		return true
    end

	msp_table:add(0x8f16, IUC_ECM_REPLACEMENT)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x16]  = msp_table:get_dissector(0x8f16)
	
	--[[
	IUC_ECM_REPLACEMENT OLD ECM
	--]]
	
	local IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM = Proto("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM", "Old ECM struct")
	f_msg_iuc_replacement_oldEcm_nr_primes = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.NrPrimes", "NrPrimes", base.DEC)
	f_msg_iuc_replacement_oldEcm_smk_timestamp = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.SMKTimestamp", "SMKTimestamp")
	f_msg_iuc_replacement_oldEcm_key_cipher_mode = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.key_cipher_mode", "Key Cipher Mode", base.DEC)
	f_msg_iuc_replacement_oldEcm_tg_old = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.tg_old", "Old TG", base.HEX)
	f_msg_iuc_replacement_oldEcm_tg_new = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.tg_new", "New TG", base.HEX)
	f_msg_iuc_replacement_oldEcm_cwdk_old_version = ProtoField.int8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.cwdk_old_version", "Old CWDK Version", base.DEC)
	f_msg_iuc_replacement_oldEcm_cwdk_old = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.cwdk_old", "Old CWDK", base.HEX)
	f_msg_iuc_replacement_oldEcm_cwdk_new_count = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.cwdk_new_count", "New CWDK Count", base.DEC)
	f_msg_iuc_replacement_oldEcm_cwdk_new_version = ProtoField.int8("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.cwdk_new_version", "New CWDK Version", base.DEC)
	f_msg_iuc_replacement_oldEcm_cwdk_new = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.cwdk_new", "New CWDK", base.HEX)
	f_msg_iuc_replacement_oldEcm_pseed_prime_old = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.p_seed_old", "Old Product Key", base.HEX)
	f_msg_iuc_replacement_oldEcm_pseed_prime_new = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.p_seed_new", "New Product Key", base.HEX)
	f_msg_iuc_replacement_oldEcm_old_ecm = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.old_ecm", "Old ECM Section", base.HEX)
	f_msg_iuc_replacement_oldEcm_crc32 = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.crc32", "Old ECM CRC32", base.HEX)
	
	IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.fields = {f_msg_iuc_replacement_oldEcm_nr_primes, f_msg_iuc_replacement_oldEcm_smk_timestamp, 
													f_msg_iuc_replacement_oldEcm_key_cipher_mode, f_msg_iuc_replacement_oldEcm_tg_old, 
													f_msg_iuc_replacement_oldEcm_tg_new, f_msg_iuc_replacement_oldEcm_cwdk_old_version, 
													f_msg_iuc_replacement_oldEcm_cwdk_old, f_msg_iuc_replacement_oldEcm_cwdk_new_count, 
													f_msg_iuc_replacement_oldEcm_cwdk_new_version, f_msg_iuc_replacement_oldEcm_cwdk_new, 
													f_msg_iuc_replacement_oldEcm_pseed_prime_old, f_msg_iuc_replacement_oldEcm_pseed_prime_new, 
													f_msg_iuc_replacement_oldEcm_old_ecm, f_msg_iuc_replacement_oldEcm_crc32}

	function IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		local t = root:add(IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM, buf(offset,  buf_len))
		-- primes & timestamps
		local nr_primes = buf(0, 1) : uint()
		local offset = 1 + nr_primes * 4
		if ( buf_len > 1+nr_primes*4) then
			t:add(f_msg_iuc_replacement_oldEcm_nr_primes, buf(0, 1))
			t:add(f_msg_iuc_replacement_oldEcm_smk_timestamp, buf(1, nr_primes * 4))
		else
			return false
		end
		-- ecm header
		t:add(f_msg_iuc_replacement_oldEcm_key_cipher_mode, buf(offset,1))
		t:add(f_msg_iuc_replacement_oldEcm_tg_old, buf(offset + 1,1))
		t:add(f_msg_iuc_replacement_oldEcm_tg_new, buf(offset + 2,1))
		t:add(f_msg_iuc_replacement_oldEcm_cwdk_old_version, buf(offset + 3, 1))
		t:add(f_msg_iuc_replacement_oldEcm_cwdk_old, buf(offset + 4, 16))
		t:add(f_msg_iuc_replacement_oldEcm_cwdk_new_count, buf(offset + 20, 1))
		t:add(f_msg_iuc_replacement_oldEcm_cwdk_new_version, buf(offset + 21,1))
		
		local i=0
		local cwdk_new_count = buf(offset + 20,1):uint()
		while i< cwdk_new_count do
			t:add(f_msg_iuc_replacement_oldEcm_cwdk_new,  buf(offset + 22+ i*16, 16))
			i = i + 1
		end
		
		t:add(f_msg_iuc_replacement_oldEcm_pseed_prime_old, buf(offset + 22+ i*16, 16))
		t:add(f_msg_iuc_replacement_oldEcm_pseed_prime_new, buf(offset + 22 + (i+1)*16, 16))
		st = t:add(f_msg_iuc_replacement_oldEcm_old_ecm, buf(offset + 22+(i+2)*16, buf_len- 22- (i+2)*16 - offset))

		local old_ecm = buf(offset + 22+(i+2)*16, buf_len- 22- (i+2)*16  - offset - 8) :tvb()
		
		-- parse ecm
		msp_table:get_dissector(0xFFEE):call(old_ecm, pkt, st)
		st:add(f_msg_iuc_replacement_oldEcm_crc32, buf(buf_len - 8, 8))

		return true
    end
	
	-- Will only be used in 0x8f17. so a strange key 0x8f1701 is used.
	msp_table:add(0x8f1701, IUC_GENERIC_ECM_REPLACEMENT_OLD_ECM)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x1701]  = msp_table:get_dissector(0x8f1701)
	
	--[[
	
	IUC Generic ECM Replacement
	
	--]]

	local IUC_GENERIC_ECM_REPLACEMENT = Proto("IUC_GENERIC_ECM_REPLACEMENT", "Clokaed CA Generic ECM Replacement")
	f_msg_iuc_generic_replacement_version = ProtoField.uint8("IUC_GENERIC_ECM_REPLACEMENT.version", "Version", base.DEC)
	--f_msg_iuc_generic_replacement_old_ecm = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT.old_ecm", "Old ECM", base.HEX)
	--f_msg_iuc_generic_replacement_new_ecm_header = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT.new_ecm_header", "New ECM header setting", base.HEX)
	--f_msg_iuc_generic_replacement_service_data = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT.service_data", "Service Data", base.HEX)
	--f_msg_iuc_generic_replacement_content_rights = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT.content_rights", "Content Rights", base.HEX)
	--f_msg_iuc_generic_replacement_macrovision_control = ProtoField.bytes("IUC_GENERIC_ECM_REPLACEMENT.macrovision_control", "Macrovision Control", base.HEX)

	
	
	IUC_GENERIC_ECM_REPLACEMENT.fields = {f_msg_iuc_generic_replacement_version}

	function IUC_GENERIC_ECM_REPLACEMENT.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 16 then
			return false
		end
		--Protocol Info for IUC ECM Generic Replacement Message
		pkt.cols.info = "CCA Generic ECM Replacement"
		-- ecm header
		local t = root:add(IUC_GENERIC_ECM_REPLACEMENT, buf(0, buf_len))
		t:add(f_msg_iuc_generic_replacement_version, buf(0, 1))
		
		local i=1
		while i < buf_len do
			local tt = buf(i, 1):uint()
			local ll = buf(i+1, 2):uint()
			if tt == 0x01 then
				msp_table:get_dissector(0x8f1701):call(buf(i+3,ll):tvb(), pkt, t)
			elseif tt == 0x02 then
				msp_table:get_dissector(0xFFEE):call(buf(i+3,ll):tvb(), pkt, t)
			else
				ccp_table:get_dissector(tt):call(buf(i+3,ll):tvb(), pkt, t)
			end
			i = i + 3 + ll
		end
    end

	msp_table:add(0x8f17, IUC_GENERIC_ECM_REPLACEMENT)
	if not protos[0x8f] then protos[0x8f] = {} end
	protos[0x8f][0x17]  = msp_table:get_dissector(0x8f17)

	--[[

	CA3 ECM dessector

	--]]

	local CA3_ECM = Proto("CA3_ECM", "CA3 ECM")
	f_msg_ca3_ecm_ecm_mode = ProtoField.uint8("CA3_ECM.ECM_Mode", "ECM Mode")
	f_msg_ca3_ecm_pk_prime = ProtoField.bytes("CA3_ECM.PK_Prime", "PK Prime")
	
	CA3_ECM.fields = {f_msg_ca3_ecm_ecm_mode, f_msg_ca3_ecm_pk_prime}

	function CA3_ECM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 9 then
			return false
		end
		--Protocol Info for CA3 ECM
		pkt.cols.info = "CA3 ECM"
		-- ecm header
		local t = root:add(CA3_ECM, buf(0,  buf_len))
		t:add(f_msg_ca3_ecm_ecm_mode, buf(0,1))
		
		local pk_indicator = bit:_rshift(buf(0,1):uint(), 7) 
		local size = 1
		if pk_indicator == 0 then
			t:add(f_msg_ca3_ecm_pk_prime, buf(1, 16))
			size = size + 16
		elseif pk_indicator == 1 then
			t:add(f_msg_ca3_ecm_pk_prime, buf(1, 8))
			size = size + 8
		end
		
		local ecm = buf(size, buf:len() - size) :tvb()
		
		ca3_ecm_opcode_flag = true
		-- parse ecm
		if not msp_table:get_dissector(0xFFED):call(ecm, pkt, t) then
		    ca3_ecm_opcode_flag = false
			return false
		end
		ca3_ecm_opcode_flag = false

		return true
    end	
		
	msp_table:add(0x4f02, CA3_ECM)
	if not protos[0x4f] then protos[0x4f] = {} end
	protos[0x4f][0x02]  = msp_table:get_dissector(0x4f02)

	--[[

	CA2 ECM dessector

	--]]

	local CA2_ECM = Proto("CA2_ECM", "CA2 ECM")
	f_msg_ca2_ecm_pk_mode = ProtoField.uint8("CA2_ECM.PK_Mode", "PK Mode")
	f_msg_ca2_ecm_pk_prime = ProtoField.bytes("CA2_ECM.PK_Prime", "PK Prime")
	
	CA2_ECM.fields = {f_msg_ca2_ecm_pk_mode, f_msg_ca2_ecm_pk_prime}

	function CA2_ECM.dissector(buf, pkt, root)
        local buf_len = buf:len()
		if buf_len < 9 then
			return false
		end
		--Protocol Info for CA2 ECM
		pkt.cols.info = "CA2 ECM"
		-- ecm header
		local t = root:add(CA2_ECM, buf(0,  buf_len))
		t:add(f_msg_ca2_ecm_pk_mode, buf(0,1))
		
		local pk_indicator = bit:_rshift(buf(0,1):uint(), 7) 
		local size = 1
		if pk_indicator == 0 then
			t:add(f_msg_ca2_ecm_pk_prime, buf(1, 16))
			size = size + 16
		elseif pk_indicator == 1 then
			t:add(f_msg_ca2_ecm_pk_prime, buf(1, 8))
			size = size + 8
		end
		
		local ecm = buf(size, buf:len() - size) :tvb()
		
		-- parse ecm
		ca2_ecm_opcode_flag = true
		if not msp_table:get_dissector(0xFFEC):call(ecm, pkt, t) then
		    ca2_ecm_opcode_flag = false
			return false
		end

		ca2_ecm_opcode_flag = false
		return true
    end	
		
	msp_table:add(0x2f02, CA2_ECM)
	if not protos[0x2f] then protos[0x2f] = {} end
	protos[0x2f][0x02]  = msp_table:get_dissector(0x2f02)	
	
	msp_table:add(0x0f02, CA2_ECM)
	if not protos[0x0f] then protos[0x0f] = {} end
	protos[0x0f][0x02]  = msp_table:get_dissector(0x0f02)
	
-----------------------------------------------------------

--------------- KEY SERVER STATUS MESSAGE ------------------

--	Key Server status messages are used by KMS to identify 
--	a Key Server and to determine which SMK sets a Key Server 
--	is Armed with.

-------------------------------------------------------------
	
	--[[

	KEY SERVER INFO

	--]]

	local KEY_SERVER_INFO = Proto("KEY_SERVER_INFO", "Key Server Info")
	f_ks_info_id_size = ProtoField.uint8("KEY_SERVER_INFO.id_size", "Key Server ID Size", base.DEC)
	f_ks_info_id = ProtoField.bytes("KEY_SERVER_INFO.id", "Key Server ID", base.HEX)
	f_ks_info_host_version = ProtoField.bytes("KEY_SERVER_INFO.host_version", "Host Version", base.HEX)
	
	KEY_SERVER_INFO.fields = {f_ks_info_id_size, f_ks_info_id, f_ks_info_host_version}

	function KEY_SERVER_INFO.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(KEY_SERVER_INFO, buf(0, buf_len))
		local id_size = buf(0,1):uint()
		t:add(f_ks_info_id_size, buf(0,1))
		t:add(f_ks_info_id, buf(1, id_size))
		t:add(f_ks_info_host_version, buf(1 + id_size, 4))
		return true
	end

	msp_table:add(0x4001, KEY_SERVER_INFO)
	if not protos[0x40] then protos[0x40] = {} end
	protos[0x40][0x01]  = msp_table:get_dissector(0x4001)	


	--[[

	SMK OSVK QUERY

	--]]

	local SMK_OSVK_QUERY = Proto("SMK_OSVK_QUERY", "SMK OSVK Query")
	f_smk_query_sets = ProtoField.uint8("SMK_OSVK_QUERY.smk_sets", "SMK Sets", base.DEC)
	f_smk_query_timestamp = ProtoField.bytes("SMK_OSVK_QUERY.smk_timestamp", "SMK Timestamp", base.HEX)
	f_smk_query_osk_quantity = ProtoField.uint8("SMK_OSVK_QUERY.osk_quantity", "OSK Quantity", base.DEC)
	f_smk_query_osk_sector = ProtoField.uint8("SMK_OSVK_QUERY.osk_sector", "OSK Sector Number", base.DEC)
	f_smk_query_osk_version = ProtoField.uint8("SMK_OSVK_QUERY.PK_Prime", "OSK Version", base.DEC)
	
	SMK_OSVK_QUERY.fields = {f_smk_query_sets, f_smk_query_timestamp, f_smk_query_osk_quantity, f_smk_query_osk_sector, f_smk_query_osk_version}

	function SMK_OSVK_QUERY.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(SMK_OSVK_QUERY, buf(0, buf_len))
		t:add(f_smk_query_sets, buf(0,1))
		local smk_sets = buf(0,1):uint()
		local idx = 0
		for i = 0, smk_sets do
			t:add(f_smk_query_timestamp, buf(1 + idx, 4))
			idx = idx + 4
		end
		t:add(f_smk_query_osk_quantity, buf(1 + idx, 1))
		local oks_q = buf(1+idx,1):uint()
		for i = 0, oks_q do
			t:add(f_smk_query_osk_sector, buf(2+idx, 1))
			t:add(f_smk_query_osk_version, buf(3+idx, 1))
			idx = idx + 2
		end
		
		return true
	end

	msp_table:add(0x4002, SMK_OSVK_QUERY)
	if not protos[0x40] then protos[0x40] = {} end
	protos[0x40][0x02]  = msp_table:get_dissector(0x4002)	


------------------------------------------------

---------------- IPPV MESSAGES -----------------

------------------------------------------------

	--[[

	IPPV GENERATE MAC

	--]]

	local IPPV_GENERATE_MAC = Proto("IPPV_GENERATE_MAC", "IPPV Genarate MAC")
	f_ippv_fk = ProtoField.bytes("IPPV_GENERATE_MAC.fk", "Feedback Session Key Prime", base.HEX)
	f_ippv_data = ProtoField.bytes("IPPV_GENERATE_MAC.data", "Data", base.HEX)
	
	IPPV_GENERATE_MAC.fields = {f_ippv_fk, f_ippv_data}

	function IPPV_GENERATE_MAC.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(IPPV_GENERATE_MAC, buf(0, buf_len))
		t:add(f_ippv_fk, buf(0,16))
		t:add(f_ippv_data, buf(16, buf_len -16))
		return true
	end

	msp_table:add(0x1001, IPPV_GENERATE_MAC)
	if not protos[0x10] then protos[0x10] = {} end
	protos[0x10][0x01]  = msp_table:get_dissector(0x1001)	

	msp_table:add(0x3001, IPPV_GENERATE_MAC)
	if not protos[0x30] then protos[0x30] = {} end
	protos[0x30][0x01]  = msp_table:get_dissector(0x3001)	
	
	--[[

	IPPV Verify MAC

	--]]

	local IPPV_VERIFY_MAC = Proto("IPPV_VERIFY_MAC", "IPPV Verify MAC")
	f_ippv_verify_fk = ProtoField.bytes("IPPV_VERIFY_MAC.fk", "Feedback Session Key Prime", base.HEX)
	f_ippv_verify_data = ProtoField.bytes("IPPV_VERIFY_MAC.data", "Data", base.HEX)
	f_ippv_verify_supplied_mac = ProtoField.bytes("IPPV_VERIFY_MAC.supplied_mac", "Supplied MAC", base.HEX)
	
	IPPV_VERIFY_MAC.fields = {f_ippv_verify_fk, f_ippv_verify_data, f_ippv_verify_supplied_mac}

	function IPPV_VERIFY_MAC.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(IPPV_VERIFY_MAC, buf(0, buf_len))
		t:add(f_ippv_verify_fk, buf(0,16))
		t:add(f_ippv_data, buf(16, buf_len - 8 - 16))
		t:add(f_ippv_verify_supplied_mac, buf(buf_len - 8, 8))
		return true
	end

	msp_table:add(0x1002, IPPV_VERIFY_MAC)
	if not protos[0x10] then protos[0x10] = {} end
	protos[0x10][0x02]  = msp_table:get_dissector(0x1002)	

	msp_table:add(0x3002, IPPV_VERIFY_MAC)
	if not protos[0x30] then protos[0x30] = {} end
	protos[0x30][0x02]  = msp_table:get_dissector(0x3002)	
	
	--[[

	IPPV Encrypt

	--]]

	local IPPV_ENCRYPT = Proto("IPPV_ENCRYPT", "IPPV Encrypt")
	f_ippv_encrypt_fk = ProtoField.bytes("IPPV_ENCRYPT.fk", "Feedback Session Key Prime")
	f_ippv_encrypt_data = ProtoField.bytes("IPPV_ENCRYPT.data", "Encrypt Data")
	
	IPPV_ENCRYPT.fields = {f_ippv_encrypt_fk, f_ippv_encrypt_data}

	function IPPV_ENCRYPT.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(IPPV_ENCRYPT, buf(0, buf_len))
		t:add(f_ippv_encrypt_fk, buf(0,16))
		t:add(f_ippv_encrypt_data, buf(16, buf_len -16))
		
		return true

	end

	msp_table:add(0x1003, IPPV_VERIFY_MAC)
	if not protos[0x10] then protos[0x10] = {} end
	protos[0x10][0x03]  = msp_table:get_dissector(0x1003)	

	msp_table:add(0x3003, IPPV_VERIFY_MAC)
	if not protos[0x30] then protos[0x30] = {} end
	protos[0x30][0x03]  = msp_table:get_dissector(0x3003)


-----------------------------------------------

------------   CCA TWO WAY MESSAGES -----------

-----------------------------------------------

	--[[

	EXI Prime Query

	--]]

	local EXI_PRIME_QUERY = Proto("EXI_PRIME_QUERY", "EXI Prime Query")
	f_epq_da = ProtoField.uint8("EXI_PRIME_QUERY.da", "Derication Algorithm", base.HEX)
	f_epq_cssn = ProtoField.bytes("EXI_PRIME_QUERY.cssn", "CSSN", base.HEX)
	f_epq_pdpl = ProtoField.uint16("EXI_PRIME_QUERY.pdpl", "Private Data Prime Length", base.DEC)
	f_epq_pdp = ProtoField.bytes("EXI_PRIME_QUERY.pdp", "Private Data Prime")
	
	EXI_PRIME_QUERY.fields = {f_epq_da, f_epq_cssn, f_epq_pdpl, f_epq_pdp}

	function EXI_PRIME_QUERY.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(EXI_PRIME_QUERY, buf(0, buf_len))
		t:add(f_epq_da, buf(0,1))
		t:add(f_epq_cssn, buf(1,4))
		t:add(f_epq_pdpl, buf(5,2))
		local pdpl = buf(5,2):uint()
		t:add(f_epq_pdp, buf(7, pdpl))
		return true

	end

	msp_table:add(0x9212, EXI_PRIME_QUERY)
	if not protos[0x92] then protos[0x92] = {} end
	protos[0x92][0x12]  = msp_table:get_dissector(0x9212)
	
	--[[

	Secret Private Data Query

	--]]

	local SECRET_PRIVATE_DATA_QUERY = Proto("SECRET_PRIVATE_DATA_QUERY", "Secret Private Data Query")
	f_spdq_tg = ProtoField.uint8("SECRET_PRIVATE_DATA_QUERY.tg", "Transform Generation", base.HEX)
	f_spdq_variant = ProtoField.uint8("SECRET_PRIVATE_DATA_QUERY.variant", "Variant", base.DEC)
	f_spdq_lock_id = ProtoField.uint16("SECRET_PRIVATE_DATA_QUERY.lock_id", "Lock ID", base.HEX)
	f_spdq_pdpl = ProtoField.uint16("SECRET_PRIVATE_DATA_QUERY.pdpl", "Private Data Prime Length", base.DEC)
	f_spdq_pdp = ProtoField.bytes("SECRET_PRIVATE_DATA_QUERY.pdp", "Private Data Prime", base.HEX)
	
	
	SECRET_PRIVATE_DATA_QUERY.fields = {f_spdq_tg, f_spdq_variant, f_spdq_lock_id, f_spdq_pdpl, f_spdq_pdp}

	function SECRET_PRIVATE_DATA_QUERY.dissector(buf, pkt, root)
        local buf_len = buf:len()
		local t = root:add(SECRET_PRIVATE_DATA_QUERY, buf(0, buf_len))
		t:add(f_spdq_tg, buf(0,1))
		t:add(f_spdq_variant, buf(1,1))
		t:add(f_spdq_lock_id, buf(2,2))
		t:add(f_spdq_pdpl, buf(4,2))
		local pdpl = buf(4,2):uint()
		t:add(f_spdq_pdp, buf(6, pdpl))
		return true
	end

	msp_table:add(0x9213, SECRET_PRIVATE_DATA_QUERY)
	if not protos[0x92] then protos[0x92] = {} end
	protos[0x92][0x13]  = msp_table:get_dissector(0x9213)
	

------------------------------------------------

------------- MSP HEADER DISSECTOR -------------

------------------------------------------------
	
	--[[

	MSP Protocol

	--]]

	local MSPS = Proto("MSPS","MSP Message")

	local f_msp_version = ProtoField.uint8("MSPS.VersionFlag", "Version Flag", base.HEX)
	local f_msp_length = ProtoField.uint16("MSPS.Length", "Length", base.DEC)
	local f_msp_ackownledge_id = ProtoField.uint8("MSPS.AcknowledgeId", "Acknowledge Id", base.HEX)
	local f_msp_connection = ProtoField.uint8("MSPS.Connection", "Connection", base.HEX)
	local f_msp_type = ProtoField.uint8("MSPS.Type", "Type", base.HEX)
	local f_msp_nr_primes = ProtoField.uint8("MSPS.NrPrimes", "NrPrimes", base.DEC)
	local f_msp_smk_timestamp = ProtoField.bytes("MSPS.SMKTimestamp", "SMKTimestamp")
	local f_msp_payload = ProtoField.bytes("MSPS.Payload", "Payload", base.HEX)
	MSPS.fields = {f_msp_version, f_msp_length,f_msp_ackownledge_id, f_msp_connection, f_msp_type, f_msp_nr_primes, f_msp_smk_timestamp,f_msp_payload}


	-- msp dessector function
	function MSPS.dissector(buf, pkt, root)
		-- check buffer length
        local buf_len = buf:len()
        if buf_len < 7 then
            return false
        end

        --[[
        packet list columns
        --]]
        pkt.cols.protocol = "MSP"
        pkt.cols.info = "Irdeto Multichoice Standard Protocol"

		local payload_length = buf(1, 2) : uint()
		local connection_type = buf(4,1) : uint()
		local msg_type = buf(5, 1) : uint()
		local offset = 6

        --[[
        dissection tree in packet details
        --]]
        -- tree root
        local t = root:add(MSPS, buf(0, 3 + payload_length))
        -- child items
        t:add(f_msp_version, buf(0,1))
        t:add(f_msp_length, buf(1,2))
        t:add(f_msp_ackownledge_id, buf(3,1))
		t:add(f_msp_connection, buf(4,1))
		t:add(f_msp_type, buf(5,1))

		if is_primes_info_required(connection_type, msg_type) then
			
			local nr_primes = buf(6, 1) : uint()
			if ( buf:len() >= nr_primes * 4 + 7) then
				t:add(f_msp_nr_primes, buf(6, 1))
				t:add(f_msp_smk_timestamp, buf(7, nr_primes * 4))
				offset = 6 + 1 + nr_primes * 4
			else
				t:add(f_msp_payload, buf(6, buf_len - 6))
				return false
			end
		end


		-- call the following dessector depending on the connection_type
		-- the connection_type includes:
		--

		local dissector = nil
		if protos[connection_type] ~= nil then
			dissector = protos[connection_type][msg_type]
		end
		if  dissector ~= nil then
			local payload = buf(offset, buf:len() - offset):tvb()
			dissector:call(payload, pkt, t)
		else
			t:add(f_msp_payload, buf(6, buf_len - 6))
		end

        return true
	end

	proto_table:add(0x01, MSPS)

end
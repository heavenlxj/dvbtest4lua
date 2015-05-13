--[[

IRD MESSAGE LIBRARAY

--]]

	--[[

	IRD : Text Message

	--]]

	local Text_Message = Proto("Text_Message", "Irdeto IRD EMM Text Message")

	f_ird_text_message_type = ProtoField.uint8("Text_Message.message_type", "Text Message Type", base.DEC, nil, 0xf0)
	f_ird_text_message_spare = ProtoField.uint8("Text_Message.spare", "Spare", base.DEC, nil, 0x0f)

	-- Mail Box   or   Announcement
	f_ird_text_message_class = ProtoField.string("Text_Message.message_class", "Message Class")
	f_ird_text_message_flush_buffer = ProtoField.string("Text_Message.flush_buffer", "Flush Buffer")
	f_ird_text_message_compressed = ProtoField.string("Text_Message.compressed", "Compressed")
	f_ird_text_message_club_message = ProtoField.string("Text_Message.club_message", "Club Message")
	f_ird_text_message_priority = ProtoField.string("Text_Message.message_priority", "Message Priority")

	-- Message Class: 0x01
	f_ird_text_message_year = ProtoField.string("Text_Message.year", "Year")
	f_ird_text_message_month = ProtoField.string("Text_Message.month", "Month")
	f_ird_text_message_day = ProtoField.string("Text_Message.day","Day")
	f_ird_text_message_hour = ProtoField.string("Text_Message.hour", "Hour")
	f_ird_text_message_minute = ProtoField.string("Text_Message.minute", "Minute")


	f_ird_text_message_club_number = ProtoField.bytes("Text_Message.club_number", "Club Number", base.DEC)
	f_ird_text_message_length = ProtoField.uint8("Text_Message.message_length", "Message Length", base.DEC)
	f_ird_text_message_bytes = ProtoField.bytes("Text_Message.message_bytes", "Message Bytes", base.HEX)

	--Club Numbers
	f_ird_text_message_del_club_numbers = ProtoField.string("Text_Message.del_club_numbers", "Del Club Number")
	f_ird_text_message_number_of_clubs = ProtoField.string("Text_Message.number_of_clubs", "Number of Clubs")
	f_ird_text_message_payload = ProtoField.bytes("Text_Message.payload", "Message Payload", base.HEX)
	
	--Spare
	f_ird_text_message_spare_message_body = ProtoField.bytes("Text_Message.sparebody", "Spare Message", base.HEX)


	Text_Message.fields = {f_ird_text_message_type, f_ird_text_message_spare, f_ird_text_message_class, f_ird_text_message_flush_buffer,
						f_ird_text_message_compressed, f_ird_text_message_club_message, f_ird_text_message_priority,
						f_ird_text_message_year, f_ird_text_message_month, f_ird_text_message_day, f_ird_text_message_hour,
						f_ird_text_message_minute, f_ird_text_message_club_number, f_ird_text_message_length, f_ird_text_message_bytes,
						f_ird_text_message_del_club_numbers, f_ird_text_message_number_of_clubs, f_ird_text_message_payload,
						f_ird_text_message_spare_message_body}

	function Text_Message.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local message_type = bit:_rshift(buf(0,1):uint(), 4)
		local spare = bit:_and(buf(0,1) : uint(), 0x0f)
		local payload = buf(1, buf_len -1)
		local t = root:add(Text_Message, buf(0, buf_len))
		t:add(f_ird_text_message_type, buf(0,1))
		t:add(f_ird_text_message_spare, buf(0,1))

		if message_type == 0 or message_type == 1 then
			local message_class = bit:_rshift(buf(1,1) :uint(), 5)
			local flush_buffer = bit:_and(bit:_rshift(buf(1,1): uint(), 4), 0x01)
			local compressed = bit:_and(bit:_rshift(buf(1,1): uint(), 3), 0x01)
			local club_message = bit:_and(bit:_rshift(buf(1,1): uint(), 2), 0x01)
			local message_priority = bit:_and(buf(1,1):uint(), 0x03)
			local index = 0

			t:add(f_ird_text_message_class, message_class)
			t:add(f_ird_text_message_flush_buffer, flush_buffer)
			t:add(f_ird_text_message_compressed, compressed)
			t:add(f_ird_text_message_club_message, club_message)
			t:add(f_ird_text_message_priority, message_priority)

			if message_class == 1 then  --Timed
				local time_info = buf(2,2) :uint()
				local year = bit:_rshift(time_info, 0x09)
				local month = bit:_and(bit:_rshift(time_info, 0x05), 0x000f)
				local day = bit:_and(time_info, 0x001f)
				local hour = bit:_rshift(buf(4,1): uint(), 3)
				local minute = bit:_and(buf(4,1): uint(), 0x07)

				t:add(f_ird_text_message_year, year)
				t:add(f_ird_text_message_month, month)
				t:add(f_ird_text_message_day, day)
				t:add(f_ird_text_message_hour, hour)
				t:add(f_ird_text_message_minute, minute)
				index = index + 3

			end

			if club_message == 1 then
				local club_number = buf(2 + index, 2)

				t:add(f_ird_text_message_club_number, club_number)

				index = index + 2

			end

			local message_length = buf(2+index, 1)
			local message_byte = buf(2+index+1, message_length:uint())

			t:add(f_ird_text_message_length, message_length)
			t:add(f_ird_text_message_bytes, message_byte)



		elseif message_type == 2 then
			local del_club_numbers = bit:_rshift(buf(1,1):uint(), 7)
			local number_of_clubs = bit:_and(buf(1,1):uint(), 0x7f)

			local club_number = buf(2, number_of_clubs)

			t:add(f_ird_text_message_del_club_numbers, del_club_numbers)
			t:add(f_ird_text_message_number_of_clubs, number_of_clubs)
			t:add(f_ird_text_message_club_number, club_number)


		else
			t:add(f_ird_text_message_spare_message_body, payload)

		end

	end

	ird_table:add(0x00,  Text_Message)
	ird_protos = {
		[0x00] = ird_table:get_dissector(0x00)
	}



	--[[

	IRD : Decoder Control Message

	--]]

	local Decoder_Control = Proto("Decoder_Control", "Decoder Control Message")

	f_ird_decoder_control_message_type = ProtoField.string("Decoder_Control.message_type", "Message Type")
	f_ird_decoder_control_spare = ProtoField.string("Decoder_Control.spare", "Spare")
	f_ird_decoder_control_payload = ProtoField.bytes("Decoder_Control.payload", "Payload", base.HEX)

	-- force download
	f_ird_decoder_control_download_allowed = ProtoField.string("Decoder_Control.download_allowed", "Download Allowed")
	f_ird_decoder_control_forced_download = ProtoField.string("Decoder_Control.forced_download", "Forced Download")
	f_ird_decoder_control_profdec_forced_download = ProtoField.string("Decoder_Control.profdec_forced_download", "Profdec Forced Download")

	--callback data
	f_ird_decoder_control_callback_data = ProtoField.bytes("Decoder_Control.callback_data", "Callback Data", base_HEX)

	--monitor data
	f_ird_decoder_control_monitor_data = ProtoField.bytes("Decoder_Control.monitor_data", "Monitor Data", base.HEX)

	--read smart card user data
	f_ird_decore_control_smartcard_data = ProtoField.bytes("Decoder_Control.smartcard_data", "Smartcard Data", base.HEX)
	--pin code
	f_ird_decoder_control_parental_pin_index = ProtoField.uint8("Decoder_Control.pin_index", "Parental Pin Index", base.HEX)
	f_ird_decoder_control_parental_pin_code = ProtoField.uint16("Decoder_Control.pin_code", "Parental Pin Code", base.HEX)

	--recovery data
	f_ird_decoder_control_recovery_type = ProtoField.string("Decoder_Control.recovery_type", "Recovery Type")
	f_ird_decoder_control_bouquet_id = ProtoField.uint16("Decoder_Control.bouquet_id", "Bouquet Id", base.DEC)
	f_ird_decoder_control_original_network_id = ProtoField.uint16("Decoder_Control.original_network_id", "Original Network Id", base.DEC)
	f_ird_decoder_control_transport_stream_id = ProtoField.uint16("Decoder_Control.transport_stream_id", "Transport Stream Id", base.DEC)
	f_ird_decoder_control_service_id = ProtoField.uint16("Decoder_Control.service_id", "Service Id", base.DEC)
	f_ird_decoder_control_installer_pin_code = ProtoField.uint16("Decoder_Control.installer_pin_code", base.HEX)

	--user payload data
	f_ird_decoder_control_user_payload_data = ProtoField.bytes("Decoder_Control.user_payload_data", "User Payload Data", base.HEX)
	
	--Loader Extended Code download
	f_ird_decoder_control_include_new_variant = ProtoField.string("Decoder_Control.include_new_variant", "Include New Variant")
	f_ird_decoder_control_include_new_subvariant = ProtoField.string("Decoder_Control.include_new_sub_variant", "Include New Subvariant")
	f_ird_decoder_control_reserved = ProtoField.string("Decoder_Control.reserved", "Reserved")
	f_ird_decoder_control_new_variant = ProtoField.bytes("Decoder_Control.new_variant", "New Variant", base.HEX)
	f_ird_decoder_control_new_subvariant = ProtoField.bytes("Decoder_Control.new_sub_variant", "New Sub Variant", base.HEX)
	
	Decoder_Control.fields = {f_ird_decoder_control_message_type, f_ird_decoder_control_spare,
	f_ird_decoder_control_download_allowed, f_ird_decoder_control_forced_download, f_ird_decoder_control_profdec_forced_download,
	f_ird_decoder_control_callback_data, f_ird_decoder_control_monitor_data, f_ird_decore_control_smartcard_data, f_ird_decoder_control_parental_pin_index,
	f_ird_decoder_control_parental_pin_code, f_ird_decoder_control_recovery_type, f_ird_decoder_control_bouquet_id ,f_ird_decoder_control_original_network_id,
	f_ird_decoder_control_transport_stream_id, f_ird_decoder_control_service_id ,f_ird_decoder_control_installer_pin_code, f_ird_decoder_control_user_payload_data,
	f_ird_decoder_control_payload, f_ird_decoder_control_include_new_variant, f_ird_decoder_control_include_new_subvariant, f_ird_decoder_control_reserved,
	f_ird_decoder_control_new_variant, f_ird_decoder_control_new_subvariant}

	function Decoder_Control.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local message_type = bit:_rshift(buf(0,1) : uint(), 4)
		local spare = bit:_and(buf(0,1) : uint(), 0x0f)
		local payload = buf(1, buf_len -1)
		local t = root:add(Decoder_Control, buf(0, buf_len))
		t:add(f_ird_decoder_control_message_type, message_type)
		t:add(f_ird_decoder_control_spare, spare)

		if message_type == 0 then
			local download_allowed = bit:_rshift(buf(1, 1) : uint(), 7)
			local forced_download = bit:_and(bit:_rshift(buf(1,1) : uint(), 6), 0x01)
			local profdec_forced_download = bit:_and(bit:_rshift(buf(1,1) :uint(), 5), 0x01)
			local spare = bit:_and(buf(1,1):uint(), 0x1f)

			t:add(f_ird_decoder_control_download_allowed, download_allowed)
			t:add(f_ird_decoder_control_forced_download, forced_download)
			t:add(f_ird_decoder_control_profdec_forced_download, profdec_forced_download)
			t:add(f_ird_decoder_control_spare, spare)

		elseif message_type == 1 then
			t:add(f_ird_decoder_control_callback_data, payload)

		elseif message_type == 2 then
			t:add(f_ird_decoder_control_monitor_data, payload)

		elseif message_type == 3 then
			t:add(f_ird_decore_control_smartcard_data, payload)

		elseif message_type == 4 then
			t:add(f_ird_decoder_control_parental_pin_index, buf(1, 1))
			t:add(f_ird_decoder_control_parental_pin_code, buf(2, 2))

		elseif message_type == 5 then
			local recover_type = bit:_rshift(buf(1, 1) :uint(), 4)
			local spare = bit:_and(buf(1, 1) :uint(), 0x0f)
			t:add(f_ird_decoder_control_recovery_type, recover_type)
			t:add(f_ird_decoder_control_spare, spare)

			if recover_type == 1 then
				t:add(f_ird_decoder_control_bouquet_id, buf(2, 2))

			elseif recover_type == 5 then
				t:add(f_ird_decoder_control_original_network_id, buf(2, 2))
				t:add(f_ird_decoder_control_transport_stream_id, buf(4, 2))
				t:add(f_ird_decoder_control_service_id, buf(6, 2))

			elseif recover_type == 6 then
				t:add(f_ird_decoder_control_installer_pin_code, buf(2, 2))

			end

		elseif message_type == 6 then
			t:add(f_ird_decoder_control_user_payload_data, payload)
			
		elseif message_type == 7 then
			local download_allowed = bit:_rshift(buf(1, 1) : uint(), 7)
			local forced_download = bit:_and(bit:_rshift(buf(1,1) : uint(), 6), 0x01)
			local profdec_forced_download = bit:_and(bit:_rshift(buf(1,1) :uint(), 5), 0x01)
			local spare = bit:_and(buf(1,1):uint(), 0x1f)
			t:add(f_ird_decoder_control_download_allowed, download_allowed)
			t:add(f_ird_decoder_control_forced_download, forced_download)
			t:add(f_ird_decoder_control_profdec_forced_download, profdec_forced_download)
			t:add(f_ird_decoder_control_spare, spare)
			
			t:add(f_ird_decoder_control_include_new_variant, bit:_rshift(buf(2,1):uint(),7))
			t:add(f_ird_decoder_control_include_new_subvariant, bit:_and(bit:_rshift(buf(2,1) : uint(), 6), 0x01))
			t:add(f_ird_decoder_control_reserved, bit:_and(buf(2,1):uint(), 0x3f))
			t:add(f_ird_decoder_control_new_variant, buf(3,2))
			t:add(f_ird_decoder_control_new_subvariant, buf(5,2))

		else
			t:add(f_ird_decoder_control_payload, payload)
		end

	end

	ird_table:add(0x01,  Decoder_Control)
	ird_protos[0x01]  = ird_table:get_dissector(0x01)


	--[[

	IRD : Prof-Dec Messages

	--]]

	local Prof_Dec_Message = Proto("Prof_Dec_Message", "Prof-Dec Message")
	f_prof_dec_message_original_network_id = ProtoField.uint16("Prof_Dec_Message.original_network_id", "Original network", base.DEC)
	f_prof_dec_message_club_number = ProtoField.uint16("Prof_Dec_Message.club_number", "Club Number", base.DEC)
	f_prof_dec_message_minicon_data_service = ProtoField.uint16("Prof_Dec_Message.minicon_data_service", "MiniCon Data Service", base.HEX)
	f_prof_dec_message_information_type = ProtoField.uint8("Prof_Dec_Message.information_type", "Information Type", base.DEC)
	f_prof_dec_message_service_id = ProtoField.uint16("Prof_Dec_Message.service_id", "Service Id", base.DEC)
	f_prof_dec_message_spare = ProtoField.string("Prof_Dec_Message.spare", "Spare")
	f_prof_dec_message_iso_language_code = ProtoField.bytes("Prof_Dec_Message.iso_language_code", "ISO Language Code", base.HEX)
	f_prof_dec_message_audio_type = ProtoField.uint8("Prof_Dec_Message.audio_type", "Audio Type", base.HEX)
	f_prof_dec_message_information = ProtoField.bytes("Prof_Dec_Message.payload", "Payload", base.HEX)

	Prof_Dec_Message.fields = {f_prof_dec_message_original_network_id, f_prof_dec_message_club_number, f_prof_dec_message_minicon_data_service,
							f_prof_dec_message_information_type, f_prof_dec_message_service_id, f_prof_dec_message_spare,
							f_prof_dec_message_iso_language_code, f_prof_dec_message_audio_type, f_prof_dec_message_information}


	function Prof_Dec_Message.dissector(buf, pkt ,root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local original_network_id = buf(0,2)
		local club_number = buf(2,2)
		local minicon_data_service = buf(4,2)
		local t = root:add(Prof_Dec_Message, buf(0, buf_len))
		t:add(f_prof_dec_message_original_network_id, original_network_id)
		t:add(f_prof_dec_message_club_number, club_number)
		t:add(f_prof_dec_message_minicon_data_service, minicon_data_service)

		local information = buf(6, buf_len -6)
		for i=0 , buf_len-6, 5 do
			local information_type = information(i, 1) :uint()
			t:add(f_prof_dec_message_information_type, information_type)
			if information_type == 83 then
				t:add(f_prof_dec_message_service_id, information(i+1, 2))
				t:add(f_prof_dec_message_spare, information(i+3, 2))

			elseif information_type == 65 then
				t:add(f_prof_dec_message_iso_language_code, information(i+1, 3))
				t:add(f_prof_dec_message_audio_type, information(i+4, 1))

			else
				t:add(f_prof_dec_message_information, information(i+1, 4))

			end

		end


	end


	ird_table:add(0x03,  Prof_Dec_Message)
	ird_protos[0x03] = ird_table:get_dissector(0x03)


	--[[

	IRD: Attributed Display Message

	--]]

	local Attributed_Display = Proto("Attributed_Display", "Attributed Display Message")
	f_attributed_display_message_type_normal = ProtoField.uint8("Attributed_Display.message_type_normal", "Message Type Normal", base.HEX)
	f_attributed_display_message_type_forced_text = ProtoField.uint8("Attributed_Display.message_type_forced_text", "Message Type Forced Text", base.HEX)
	f_attributed_display_message_type_finger_print = ProtoField.uint8("Attributed_Display.message_type_finger_print", "Message Type Finger Print", base.HEX)
	f_attributed_display_message_type_enhanced_overt_finger_print_options = ProtoField.uint8("Attributed_Display.message_type_enhanced_overt_finger_print_options", "Message Type Enhanced Overt Finger Print", base.HEX)
	f_attributed_display_duration = ProtoField.uint16("Attributed_Display.duration", "Duration", base.DEC)
	f_attributed_display_display_method = ProtoField.uint8("Attributed_Display.display_method", "Display Method", base.HEX)
	f_attributed_display_finger_print_type = ProtoField.uint8("Attributed_Display.finger_print_type", "Finger Print Type", base.DEC, {[0]='Overt',[1]='Covert'}, 0x80)
	f_attributed_display_reserved = ProtoField.uint8("Attributed_Display.reserved", "Reserved", base.DEC, nil, 0x70)
	f_attributed_display_text_length = ProtoField.uint16("Attributed_Display.text_length", "Text Length", base.DEC, nil, 0xfff)
	f_attributed_display_text_byte = ProtoField.bytes("Attributed_Display.text_byte", "Text Byte", base.HEX)

	--display method forced text & finger print
	f_attributed_display_flashing = ProtoField.uint8("Attributed_Display.flashing", "Flashing", base.DEC, {[0]='Flashing', [1]='Not-Flashing'}, 0x01)
	f_attributed_display_banner = ProtoField.uint8("Attributed_Display.banner", "Banner", base.DEC, {[0]='Banner',[1]='Normal'}, 0x02)
	f_attributed_display_coverage_code = ProtoField.uint8("Attributed_Display.coverage_code", "Coverage Code", base.DEC, nil, 0xfc)

	--enhanced overt finger print options
	f_attributed_display_tag = ProtoField.uint8("Attributed_Display.tag", "Tag", base.HEX)
	f_attributed_display_length = ProtoField.uint8("Attributed_Display.length", "Length", base.DEC)
	f_attributed_display_variable = ProtoField.bytes("Attributed_Display.variable", "Variable", base.HEX)
	f_attributed_display_location_x_factor = ProtoField.uint8("Attributed_Display.location_x_factor", "Location X Factor", base.HEX)
	f_attributed_display_location_y_factor = ProtoField.uint8("Attributed_Display.location_y_factor", "Location Y Factor", base.HEX)
	f_attributed_display_background_transparency_alpha_factor = ProtoField.uint8("Attributed_Display.background_transparency_alpha_factor", "Background Transparency Alpha Factor", base.HEX)
	f_attributed_display_background_color_rgb = ProtoField.bytes("Attributed_Display.background_color_rgb", "Background Color RGB", base.HEX)
	f_attributed_display_font_transparency_alpha_factor = ProtoField.uint8("Attributed_Display.font_transparency_alpha_factor", "Font Transparency Alpha Factor", base.HEX)
	f_attributed_display_font_color_rgb = ProtoField.bytes("Attributed_Display.font_color_rgb", "Font Color RGB", base.HEX)
	f_attributed_display_font_type_index = ProtoField.uint8("Attributed_Display.font_type_index", "Font Type Index", base.HEX)

	Attributed_Display.fields = {f_attributed_display_message_type_normal,f_attributed_display_message_type_forced_text, f_attributed_display_message_type_finger_print,f_attributed_display_message_type_enhanced_overt_finger_print_options  , f_attributed_display_duration, f_attributed_display_display_method, f_attributed_display_finger_print_type,
								f_attributed_display_reserved, f_attributed_display_text_length, f_attributed_display_text_byte, f_attributed_display_flashing,
								f_attributed_display_banner, f_attributed_display_coverage_code, f_attributed_display_tag, f_attributed_display_length,
								f_attributed_display_variable, f_attributed_display_location_x_factor, f_attributed_display_location_y_factor, f_attributed_display_background_transparency_alpha_factor,
								f_attributed_display_background_color_rgb, f_attributed_display_font_transparency_alpha_factor, f_attributed_display_font_color_rgb, f_attributed_display_font_type_index}


	function 	Attributed_Display.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local message_type = buf(0,1) :uint()
		local t = root:add(Attributed_Display, buf(0, buf_len))

		if message_type == 1 then
			t:add(f_attributed_display_message_type_forced_text, buf(0,1))
		elseif message_type == 2 then
			t:add(f_attributed_display_message_type_finger_print, buf(0,1))
		elseif message_type == 3 then
			t:add(f_attributed_display_message_type_enhanced_overt_finger_print_options, buf(0,1))
		else
			t:add(f_attributed_display_message_type_normal, buf(0,1))
		end
		
		t:add(f_attributed_display_duration, buf(1,2))
		if message_type ~= 0 then
			t:add(f_attributed_display_flashing, buf(3,1))
			t:add(f_attributed_display_banner, buf(3,1))
			t:add(f_attributed_display_coverage_code, buf(3,1))
		else
			t:add(f_attributed_display_display_method, buf(3,1))
		end

		local payload = buf(6, buf_len -6)
		t:add(f_attributed_display_finger_print_type, buf(4, 1))
		t:add(f_attributed_display_reserved, buf(4, 1))
		t:add(f_attributed_display_text_length, buf(4, 2))
		
		local text_length = bit:_and(buf(4,2):uint(), 0x0fff)
		
		if message_type == 3 and text_length ~= 0 then
			local tag = payload(0,1)
			if tag:uint() ~= 0 then
				return false
			end
			t:add(f_attributed_display_tag, tag)

			local length = payload(1,1):uint()
			if length ~= 12 then
				return false
			end
			t:add(f_attributed_display_length, length)

			local variable = payload(2, length)
			t:add(f_attributed_display_location_x_factor, variable(0,1))
			t:add(f_attributed_display_location_y_factor, variable(1,1))
			t:add(f_attributed_display_background_transparency_alpha_factor, variable(2,1))
			t:add(f_attributed_display_background_color_rgb, variable(3,3))
			t:add(f_attributed_display_font_transparency_alpha_factor, variable(6,1))
			t:add(f_attributed_display_font_color_rgb, variable(7,3))
			t:add(f_attributed_display_font_type_index, variable(10,1))
			t:add(f_attributed_display_reserved, variable(11,1))
		elseif text_length ~= 0 then
			t:add(f_attributed_display_text_byte, payload)
		end

	end

	ird_table:add(0x04,  Attributed_Display)
	ird_protos[0x04] = ird_table:get_dissector(0x04)



	--[[


	IRD : Open Cable Host Message


	--]]

	local Open_Cable_Host = Proto("Open_Cable_Host", "Open Cable Host Message")
	f_open_cable_host_msg_type = ProtoField.uint8("Open_Cable_Host.msg_type", "Msg Type", base.HEX)
	f_open_cable_host_validated_host_id = ProtoField.bytes("Open_Cable_Host.validated_host_id","Validated Host Id", base.HEX)
	f_open_cable_host_pod_id = ProtoField.bytes("Open_Cable_Host.pod_id", "POD Id", base.HEX)
	f_open_cable_host_validation_result = ProtoField.uint8("Open_Cable_Host.validation_result", "aValidation Result", base.HEX)
	f_open_cable_host_max_key_session_period = ProtoField.uint16("Open_Cable_Host.max_key_session_period","Max Key Session Period", base.DEC)
	f_open_cable_host_text = ProtoField.bytes("Open_Cable_Host.text", "Text", base.HEX)
	f_open_cable_host_payload = ProtoField.bytes("Open_Cable_Host.payload", "Payload", base.HEX)

	Open_Cable_Host.fields = {f_open_cable_host_msg_type, f_open_cable_host_validated_host_id, f_open_cable_host_pod_id, f_open_cable_host_validation_result,
							f_open_cable_host_max_key_session_period, f_open_cable_host_text}


	function Open_Cable_Host.dissector(buf, pkt ,root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local msg_type = buf(0,1) : uint()
		local payload = buf(1, buf_len-1)
		local t = root:add(Open_Cable_Host, buf(0, buf_len))
		t:add(f_open_cable_host_msg_type, buf(0,1))

		if msg_type == 0 then
			t:add(f_open_cable_host_validated_host_id, buf(1,5))
			t:add(f_open_cable_host_pod_id, buf(6,8))
			t:add(f_open_cable_host_validation_result, buf(14,1))
			t:add(f_open_cable_host_max_key_session_period, buf(15, 2))

		elseif msg_type == 1 then
			t:add(f_open_cable_host_text, payload)

		elseif msg_type == 3 then
			t:add(f_open_cable_host_max_key_session_period, buf(1,2))
		else
			t:add(f_open_cable_host_payload, payload)
		end


	end

	ird_table:add(0x05,  Open_Cable_Host)
	ird_protos[0x05] = ird_table:get_dissector(0x05)




	--[[

	IRD : CI+ CAM Message

	--]]

	local CIPlUS_Message = Proto("CIPlUS_Message", "CI Plus CAM Message")
	f_ciplus_message_type = ProtoField.string("CIPlUS_Message.Message_Type", "Message Type")
	f_ciplus_message_spare = ProtoField.string("CIPlUS_Message.Spare", "Spare")
	f_ciplus_trigger_cck_refresh = ProtoField.string("CIPlUS_Message.Trigger_CCK_Refresh", "Trigger CCK Refresh")
	f_ciplus_maximum_cck_lifetime = ProtoField.uint16("CIPlUS_Message.Maximux_CCK_Lifetime", "Maximum CCK Lifetime", base.HEX)
	f_ciplus_switch_detection_rsd_on_off = ProtoField.string("CIPlUS_Message.Switch_Detection_RSD_On_Off", "Switch Detection RSD On or Off")
	f_ciplus_rsd_file = ProtoField.bytes("CIPlUS_Message.Rsd_File", "RSD File")
	f_ciplus_rsm_registration_response_registration_number = ProtoField.bytes("CIPlUS_Message.RSM_Registration_Response_Number", "Response Number", base.HEX)
	f_ciplus_rsm_registration_response_action_code = ProtoField.bytes("CIPlUS_Message.RSM_Registration_Response_Action_Code", "Action Code", base.HEX)
	f_ciplus_rsm_registration_response_cicam_id = ProtoField.bytes("CIPlUS_Message.RSM_Registration_Response_CICAM_Id", "CICAM Id", base.HEX)
	f_ciplus_rsm_registration_response_host_id = ProtoField.bytes("CIPlUS_Message.RSM_Registration_Response_Host_Id", "Host Id", base.HEX)
	f_ciplus_rsm_registration_response_cssn = ProtoField.bytes("CIPlUS_Message.RSM_Registration_Response_CSSN", "CSSN", base.HEX)
	f_ciplus_payload = ProtoField.bytes("CIPlUS_Message.Payload", "CIPlus Payload", base.HEX)

	CIPlUS_Message.fields = {f_ciplus_message_type, f_ciplus_message_spare, f_ciplus_trigger_cck_refresh, f_ciplus_maximum_cck_lifetime,
							f_ciplus_switch_detection_rsd_on_off, f_ciplus_rsd_file, f_ciplus_rsm_registration_response_registration_number,
							f_ciplus_rsm_registration_response_action_code, f_ciplus_rsm_registration_response_cicam_id, f_ciplus_rsm_registration_response_host_id,
							f_ciplus_rsm_registration_response_cssn, f_ciplus_payload}

	function CIPlUS_Message.dissector(buf, pkt, root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end

		local message_type = bit:_rshift(buf(0,1) : uint(), 4)
		local spare = bit:_and(buf(0,1) : uint(), 0x0f)
		local payload = buf(1, buf_len -1)
		local t = root:add(CIPlUS_Message, buf(0, buf_len))
		t:add(f_ciplus_message_type, message_type)
		t:add(f_ciplus_message_spare, spare)

		if message_type == 0 then
			local trigger_cck_refresh = bit:_rshift(buf(1,1) : uint(), 7)
			local spare2 = bit:_and(buf(1,1):uint(), 0x7f)
			t:add(f_ciplus_trigger_cck_refresh, trigger_cck_refresh)
			t:add(f_ciplus_message_spare, spare2)

		elseif message_type == 1 then
			local maximux_cck_liftime = buf(1,2)
			t:add(f_ciplus_maximum_cck_lifetime, maximux_cck_liftime)

		elseif message_type == 2 then
			local switch_detection_rsd_on_off = bit:_rshift(buf(1,1) : uint(), 7)
			local spare3 = bit:_and(buf(1,1):uint(), 0x7f)
			t:add(f_ciplus_switch_detection_rsd_on_off, switch_detection_rsd_on_off)
			t:add(f_ciplus_message_spare, spare3)

		elseif message_type == 3 then  --RSD File
			t:add(f_ciplus_rsd_file, payload)

		elseif message_type == 4 then  -- RSM Registration Response
			local registration_number = buf(1,4)
			local action_code = buf(5,1)
			local cicam_id = buf(6,8)
			local host_id = buf(14,8)
			local cssn = buf(22,4)

			t:add(f_ciplus_rsm_registration_response_registration_number, registration_number)
			t:add(f_ciplus_rsm_registration_response_action_code, action_code)
			t:add(f_ciplus_rsm_registration_response_cicam_id, cicam_id)
			t:add(f_ciplus_rsm_registration_response_host_id, host_id)
			t:add(f_ciplus_rsm_registration_response_cssn, cssn)


		else
			t:add(f_ciplus_payload, payload)
		end

	end

	ird_table:add(0x06,  CIPlUS_Message)
	ird_protos[0x06] = ird_table:get_dissector(0x06)


	--[[
			IRD EMM
	--]]

	local IRD_EMM = Proto("IRD_EMM", "Irdeto IRD EMM")

	f_ird_emm_destination_id = ProtoField.uint8("IRD_EMM.destionation_id", "Destination Id", base.DEC, nil, 0xf0)
	f_ird_emm_message_length = ProtoField.uint16("IRD_EMM.message_length", "Message Length", base.DEC, nil, 0xfff)
	f_ird_emm_payload = ProtoField.bytes("IRD_EMM.payload", "Payload")
	f_ird_emm_crc16 = ProtoField.bytes("IRD_EMM.crc16", "CRC16")

	IRD_EMM.fields = {f_ird_emm_destination_id, f_ird_emm_message_length, f_ird_emm_payload, f_ird_emm_crc16}
	function IRD_EMM.dissector(buf, pkt , root)
		local buf_len = buf:len()
		if buf_len < 1 then
			return false
		end
		
		local ird_page = false
		local destination_id =  bit:_rshift(buf(0,1) :uint(), 4)
		local message_length = bit:_and(buf(0,2) : uint(), 0x0fff)
		if message_length > buf_len then
			message_length = buf_len - 2
			ird_page = true
		elseif message_length == 0 then
			message_length = buf_len - 4 --minus crc16
		end
		
		local t = root:add(IRD_EMM, buf(0, buf_len))
		local payload = buf(2, message_length)

		t:add(f_ird_emm_destination_id, buf(0,1))
		t:add(f_ird_emm_message_length, buf(0,2))

		local dessector = nil
		if ird_protos[destination_id] ~= nil then
			dessector = ird_protos[destination_id]
		end
		if dessector ~= nil then
			dessector:call(payload:tvb(),pkt,t)
		else
			t:add(f_ird_emm_payload, payload)
		end

		if ird_page == false then
			local crc16 = buf(2+message_length, 2)
			t:add(f_ird_emm_crc16, crc16)
		end
	
	end

	ird_table:add(0xFFFF, IRD_EMM)

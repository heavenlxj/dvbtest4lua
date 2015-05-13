-- listen_port
-- A console and a window to add listen port for decoder plugin
--
-- (c) 2012 Liu Xingjie <liu.xingjie@irdeto.com>
--
-- add_listen_port.lua 
-- 
-- Wireshark - Network traffic analyzer
if (gui_enabled())  then
	
	default_table_prefix = {"key_server", "emm", "ecm", "si"}
	default_table_name = {"KEY SERVER CONNECTION", "EMM TCP CONNECTION", "ECM CONNECTION", "SI CONNECTION"}
	default_port_table = {{5014}, {4450}, {4350}, {1239}}
	path_portfile = datafile_path()..'plugins\\lua\\port.lua'
	path_configfile = datafile_path()..'plugins\\lua\\config.lua'
	
	--Config parameter dictonary, need to add new para in the dict when the new para added
	config_para_name_dict = { 	[1] = "ENABLE_IRDETO_CRYPTO_WORKS"
	}
							
	config_para_description_dict = { [1] = "Enable or Disable the dissector for Irdeto Message or CryptoWorks Message"
	}
	
	--List the label for config parameter, need to add new label when the new config parameter added
	label_dissector_uncrypted_message = "ENABLE IRDETO CRYPTO WORKS"
	
	
	--Content to write in the port file
	write_to_port_file = [==[
	-- PORT TABLE
	port_table = {
	-- Reserved For Key Server
	key_server_conn_port_table = {},
	
	--	Reserved For EMM Connection Port
	emm_conn_port_table = {},
	
	-- Reserved For ECM Connection Port
	ecm_conn_port_table = {},
					
	-- Reserved For SI Port
	si_conn_port_table = {}
	
	}
	
	]==]
					
					
	--Content to write in the config file				
	write_to_config_file = [==[--- Configuration File ---
	
]==]

	--Extend the string lib to support split method
	function string:split(sep)
		local sep, fields = sep or "\t", {}
		local pattern = string.format("([^%s]+)", sep)
		self:gsub(pattern, function(c) fields[#fields+1] = c end)
		return fields
	end
	
	--Converse the int value to bool
	function converse_the_config_value(value)
		local config_value = false
		if tonumber(value) == 1 then
			config_value = true
		else
			config_value = false
		end
		return config_value
	end
	
	--Open a new dialog for the configuration, need to add args in the new_dialog function when the new parameter added, match to the label for parater
	function open_config_window()
		new_dialog("Configuration", config_para_value, label_dissector_uncrypted_message)
	end
	
	--NOTE: This callback function is for open_config_window
	--NOTE: The arguments number need to be same as lable number in the open_config_window. 
	--NOTE: e.g. if new_dialog("Configuration", config_para_value, lable1,lable2,lable3),  the function should be like this config_para_value(arg1, arg2, arg3)
	--NOTE: e.g. This should be modified manually when the new config parameter added, both open_config_window() and config_para_value() NEED TO UPDATE
	--NOTE: UPDATE config_para_value() need to add new args in the function defination first, then add these args into array_value list, if have 3 args, array_value = {arg1, arg2, arg3}, also update manually
	function config_para_value(arg1)
		local array_value = {arg1}
		local tempConfig = write_to_config_file
		local need_to_write = ""
		local index = 1
		for key,value in pairs(config_para_name_dict) do
			need_to_write = need_to_write..'--'..config_para_description_dict[index]..'-- \n'
			local converse_value = tostring(converse_the_config_value(array_value[index]))
			need_to_write = need_to_write..value..' = '..converse_value..'\n'
			need_to_write = need_to_write..'\n'
			index = index + 1
		end
		tempConfig = tempConfig..need_to_write
		update_file(path_configfile, tempConfig)
	end
	
	--Open the wiki page for plugin usage
	function wiki_page()
		browser_open_url("http://kmsonline.irdeto.intra/wiki/index.php?title=Wireshark_plugin_lua")
	end
	
	function update_file(path, content)
		local file = io.open(path, "w+")
		assert(file)
		file:write(content)
		file:close()
	end
		
	function concat_table(port_table)
		local con_tab = {}
		local result_line = ''
		if port_table ~= nil then
			for index,subtab in pairs(port_table) do
				if type(subtab) == 'table' and table.getn(subtab) > 1 then
					result_line = tostring(table.concat(subtab, ","))
				else
					result_line = tostring(subtab[1])
				end	
				table.insert(con_tab, result_line)
			end
		end
		return con_tab
	end
	
	function get_description(resultTable)
		local desc = "-----Setting port successfully----- \n"
		desc = desc.."Current captured port filter listed as below: \n"
		local con_table = concat_table(resultTable)
		for i, name in pairs(default_table_name) do
			if con_table[i] ~= nil then
				desc = desc..name..':\n['..con_table[i]..'] \n'
			else
				error('Empty port table')
			end
		end

		return desc
	end
	
	function build_conetent(port_table)
		local tempContent = write_to_port_file
		local line = ""
		if port_table ~= nil then
			for index,subtab in pairs(port_table) do
				if type(subtab) == 'table' and table.getn(subtab) > 1 then
					line = tostring(table.concat(subtab, ","))
				else
					line = tostring(subtab[1])
				end
							
				init_str = default_table_prefix[index].."_conn_port_table = {}"
				replace_str = default_table_prefix[index].."_conn_port_table = {"..line.."}"
				tempContent = string.gsub(tempContent, init_str, replace_str)
					
			end
					
		end
						
		return tempContent
				
	end
	

	
	function show()
		local w = TextWindow.new("Regist Port")
		w:set("You can regist the new listen port as your capture filter by cilcking New button \n")
		w:set("Default port will be supported by clicking Default button")
		w:append("\n")
		w:append("Key Server Connection Port: 5014 \n")
		w:append("EMMG Connection Port: 4450 \n")
		w:append("ECMG Connection Port: 4350 \n")
		w:append("SI Connection Port: 1239 \n")
		
		function default()
			write_content = build_conetent(default_port_table)
			update_file(path_portfile, write_content)
			local desc = get_description(default_port_table)
			w:set(desc)
		end
		
		local function reg_port()
			local label_key_server = "Key Server Connection Port"
			local label_emmg = "EMMG Connection Port"
			local lable_ecmg = "ECMG Connection Port"
			local label_si = "SI Connection Port"

			
			local function print_port(p1,p2,p3, p4)
				local reuslt_table = {}
				local port_group = {p1,p2,p3,p4}
				
				--Remove the blank
				local function remove_blank(tab)
					local tempTable = {}
					table.foreach(tab, function(i,v) if string.find(v, "%s") then 
								str = string.gsub(v, "%s", "")
								table.insert(tempTable, str) 
								else 
								table.insert(tempTable, v) end end)
					return tempTable
				end
		
				local function is_valid_string(str)
					if str ~= nil then
						if string.find(str, "^[+-]?%d+") ~= nil then
							if string.find(str, ",") or string.find(str, "-") then
								str = string.gsub(str, "[,-]", "")
							end
						else 
							return false
						end
						
						if string.find(str, "%a") == nil and string.find(str, "%c") == nil and string.find(str, "%p") == nil then
							return true
						else
							return false
						end
					else
						return false
					end	
				end
				
				--Find the specific character
				local function is_char_exist(str, char)
					if string.find(str, char) ~= nil then
						return true
					else
						return false
					end
			
				end

				--Get the port from range
				local function get_port_from_range(range_table)
					local tempTab = {} 
					if table.getn(range_table) > 2 then
						error('Get port number error!')
					else
						for i=range_table[1], range_table[2] do
							table.insert(tempTab, i)
						end	
					end
			
					return tempTab
				end
			
				-- Split the each port table
				local function split_port_group(port_group)
					local tempGroupTable = {}
				
					for _,group in pairs(port_group) do
						local tempResultTable = {}
						if is_char_exist(group, ',') and is_char_exist(group, '-') then
							commaSplitTable = string.split(group, ',')
							for _,subElement in pairs(commaSplitTable) do
								if is_char_exist(subElement, '-') then
									range_table = string.split(subElement, '-')
									tempReturnTable = get_port_from_range(range_table)
									table.foreach(tempReturnTable, function(i,v) table.insert(tempResultTable, v) end)
								else
									table.insert(tempResultTable, subElement)
								end
							end
					
						elseif is_char_exist(group, ',') then
							commaSplitTable = string.split(group, ',')
							table.foreach(commaSplitTable, function(i,v) table.insert(tempResultTable, v) end)

						elseif is_char_exist(group, '-') then
							range_table = string.split(group, '-')
							tempReturnTable = get_port_from_range(range_table)
							table.foreach(tempReturnTable, function(i,v) table.insert(tempResultTable, v) end)
					
						else
							table.insert(tempResultTable, group)
						end
				
						table.insert(tempGroupTable, tempResultTable)
					
					end
			
					return tempGroupTable

		
				end
						
				local invalid_flag = false
				table.foreach(port_group, function(i,v) if not is_valid_string(v) then invalid_flag = true end end)
				
				if invalid_flag then
					error("Please input the valid port for all the connection")
				else
					port_group = remove_blank(port_group)
					reuslt_table = split_port_group(port_group)
					write_content = build_conetent(reuslt_table)
					update_file(path_portfile, write_content)
					local desc = get_description(reuslt_table)
					w:set(desc)
				end

			end
			
			new_dialog("Apply the port", print_port, label_key_server, label_emmg, lable_ecmg, label_si)
					
		end
		

				
		w:add_button("New",reg_port)
		w:add_button("Default", default)

	end

register_menu("Irdeto Decoder/Add Port", show, 8)
register_menu("Irdeto Decoder/Wiki", wiki_page, 8)
register_menu("Irdeto Decoder/Configuration", open_config_window, 8)
end
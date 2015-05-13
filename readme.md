This plugin is based on the Lua script which supported by Wireshark, it allows decoding of KMS traffic over various interfaces.

The following listed the description of the lua files:

# bitlib.lua & bitop.lua

Provides the bit operation function for dissector function.

# cam.lua

Decode CAM message according to CCP CAM Message system specification

# config.la

The configuration file for the decoder plugin, not used yet. you can add the customized configutation for the plugin.

# descriptors.lua

SI descriptor lib, refer to the DVB_SI_spec_ETSI_EN_300468

# dvb.lua (DVB Simulcrypt)

DVB interface, refer to "DVB Simulcrypt ts_103197v010401p.pdf"

# emmh.lua

EMM Header interface

# err_info.lua

Error Info definition for Error_Status

# filter.lua

Search filter for msp, dvbs, si message.

# gui.lua

Gui interface for port registration and configuration.

# ird.lua

Decodes IRD message according to 705410_CCP IRD Messages desgin

# metadata.lua

Metadata inferface

# msp.lua

MSP interface, refer to key server specification

# opcodes.lua

Decodes parts of CCP opcodes

# port.lua

Registration for port listening

# section.lua

Section Message interface

# si.lua

SI Message Interface

 
# Plugin Usage 

 
     1.  Get the latest version of plugin from TFS: $KMS/Base/Tools/WiresharkPluginLua/
     2.  Exeute the 'load_plugin.bat' and wait for the setup completed, all the files should be copied to your wireshark installation folder, the plugin\lua 	folder should be created. 
     3.  Launch wireshark, regist your listening port following below step: 

          ` Clik menu Tools -> Irdeto Deoder -> Add Port `

          ` Default port will be added in the port file if your connection used, you can click Default button and Re-launch wireshark. `

          ` New port can be added by clicking New button, you should set the each port for your connectin. Multiple port can be splited by comma, if continuous number you can use '-' to `

          ` set a range(e.g. 4350,4351,4352 you can put 4350-4352 in the text box). `

      4.   Re-launch your wireshark when you finish the port registration.

 

# Supported Feature 

There are lots of update and new protocol dissector function added in this version, listed as below.

    Fix the DVB version support bug
    Refactor DVB dissector function make the plugin more stable
    Add bit mask display in the filed length less than 1 byte
    Add EMM Header dissector function
    Add Section Message dissector function
    Add Metadata dissector function
    Add SI descriptor dissector funtion
    Update new MSP interface
    Update new Opcode
    Add super ecm expression parser in the expression filter opcode
    Fix many minor bug 


# Search Filter 

The search filter always could be set to the protocol name definition:

Filter_Name                            Protocol

msps                                     MSP Request

dvbs                                      DVB Messages

si                                          SI Message


If you want to filter the message by smartcard type:

Filter_Name                           Message Type

emm_ca2                                 CA2 EMM

emm_ca3                                 CA3 EMM

emm_cca                                 CCA EMM

ca2_ecm                                  CA2 ECM

ca3_ecm                                  CA3 ECM

cca_ecm                                  CCA ECM

ird_emm                                   IRD EMM

cam_emm                                 CAM EMM


Or filter the message by the address type:

Filter_Name                                  Message Type

ca2_golbal_emm                          CA2 GLOBAL EMM

cca_group_emm                           CCA GROUP EMM

ca3_unique_emm                          CA3 UNIQUE EMM

......

......

Even you can set the filter to the opcode name, this will retun the message which contain the matched opcode:

Filter_Name      

ccp_par_ca3_preview_control

ccp_par_sc_service_key

ccp_par_sc_expression_filer

ccp_par_....


# Extend Plugin

Lua is a powerful, fast, lightweight, embeddable scripting language designed for extending application. We can extend the plugin easily to support our protocol decoder.

    How Lua fits into Wireshark 

   - A file called init.lua will be called first

   - Scripts passed with the -x lua_script:file.lua will be called after init.lua

   - All scripts will be run before packets are read, at the end of the dissector registration process

 

    Checking your version of Wireshark 

    Help -> About

    In the description of wireshark, the application should support with Lua

 

    Example: Adding my simple protocol 

     1.   Proto

```
-- Create a new protocol in Wireshark


proto.dissector: a function you define

proto.fields: a list of fields

proto.init: the initialization routine

proto.prefs: the preferences

proto.name: the name given


-- Create a new dissector

MyProto = Proto("MyProto", "My Simple Protocol")
```

      2.  Proto.dissector

```
– This is the function doing the dissecting
– Takes three arguments: buffer, pinfo and tree

-- The dissector function

function MyProto.dissector(buf, pkt, root)

	<do something>

end
```

    3 . ProtoField
```
-- To be used when adding items to the tree
-- Integer types:
	ProtoField.{type}(abbr,[name],[desc],[base],[valuestring],[mask])
	
	uint8, uint16, uint24, uint32, uint64, frameenum

-- Other types
	ProtoField.{type}(abbr,[name],[desc])
	
	float, double, string, stringZ, bytes, bool, ipv4, ipv6, ether, oid, guid


-- Contains a list of all ProtoFields defined

-- Create the protocol fields

f_para1 = ProtoField.uint8("MyProto.para1", "Parameter 1", base.DEC)
f_para2 = ProtoField.bytes("MyProto.para2", "Parameter 2", base.HEX)
f_para3 = ProtoField.string("MyProto.para3", "Parameter 3")

MyProto.fields = {f_para1, f_para2, f_para3}
```

         4.  Tvb/TvbRange
```
-- The buffer passed to the dissector is represented by a tvb(Testy Virtual Buffer)

-- Data is fetched by creating a TvbRange 
   Tvb([offset], [length])

-- The tvbrange can be converted to correct
datatypes with this function
uint, le_uint, float, le_float, ipv4, le_ipv4, ether, string, bytes
```
        5.  TreeItem  
```
-- Used to add a new entry to the packet details, both protocol and field entry

-- Adding a new element returning a child
 treeitem:add([field | proto], [tvbrange], [label])

-- Modifying an element
 treeitem:set_text(text)
 treeitem:append_text(text)


-- The dissector function

function MyProto.dissector (buf, pkt, root)

-- Adding fields to the tree
local sub_tree = root:add(MyProto, buf())

local offset = 0
local msgid = buf(offset, 4)
sub_tree:add(f_para1, msgid)

offset = offset + 4
sub_tree:add(f_para2, buf(offset, 2))

end
```
 

    6. Extend opcodes decoder  
```
-- Just extend the opcodes.lua, no need to modify other file

-- Adding new opcode dissector 

-- code segment
 
-- Register New Opcode
local CCP_PAR_NEW_OPCODE = Proto("CCP_PAR_NEW_OPCODE", "New Opcode")


-- Define opcode field
f_new_opcode = ProtoField.uint8("CCP_PAR_NEW_OPCODE.opcode", "Opcode", base.HEX)
f_new_opcode_length = ProtoField.uint16("CCP_PAR_NEW_OPCODE.length", "Length", base.DEC)
f_new_opcode_field = ProtoField.bytes("CCP_PAR_NEW_OPCODE.expression", "Expression", base.HEX)

--Add the opcode field into ProtoFields
CCP_PAR_NEW_OPCODE.fields = {f_new_opcode, f_new_opcode_length, f_new_opcode_field}

--Add new dissector function to decode the opcode

function CCP_PAR_NEW_OPCODE.dissector(buf, pkt, root)

 local opcode = buf(0, 1):uint() 
 if opcode ~= 0xff then -- Check Opcode Tag
 return false
 end


 local length = buf(1, 1) : uint()
 local buf_len = buf:len()
 if buf_len < length + 1 then
 return false
 end 



 -- Add new entry for opcode packet details
 local t = root:add(CCP_PAR_NEW_OPCODE, buf(0, 2 + length))
 
 -- Add field item on the sub tree
 t:add(f_new_opcode, buf(0,1))
 t:add(f_new_opcode_length, buf(1,1)) 
 t:add(f_new_opcode_field, buf(2, 4))


 --If Emm takes many opcodes, continue to decode the rest opcodes
 if ( buf_len - 2 - length > 0) then
 local next_buf = buf( 2 + length, buf_len - 2 - length)
 return ccp_table:get_dissector(0xFFFF):call( next_buf:tvb(), pkt, root)
 end



 return true 

end



--Important, Register the new opcode into the Disector Table, table:add([opcode_tag], [Opcode_Protocol_Name])
ccp_table:add(0x00ff, CCP_PAR_NEW_OPCODE)



-- register ccp opcodes table
ccp_opcodes_protos[0x00ff] = {
["dis"] = ccp_table:get_dissector(0x00ff),
["version"] = 1 -- version 1 got 1 byte length para, version 2 got 2
} 
```
<span id="fck_dom_range_temp_1309319840015_536" />



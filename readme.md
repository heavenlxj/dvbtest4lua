WireShark plugin for Irdeto internal Test

This is the initial version for wireshark, it is based on Lua script developed by BDC Head-End Test Team. 
This plug-in includes the parser for MSP, DVB Simulcrypt protocol and CCP function.

================================================================
Usage:
================================================================

1. Get the latest version of plugin from TFS: $KMS/Base/Tools/WiresharkPluginLua/ 
2. Exeute the 'load_plugin.bat' and wait for the setup completed, all the files should be copied to your wireshark installation folder, the plugin\lua folder should be created.  
3. Launch wireshark, regist your listening port following below step: 
    -- Clik menu Tools -> Irdeto Deoder -> Add Port 

    -- Default port will be added in the port file if your connection used, you can click Default button and Re-launch wireshark. 

    -- New port can be added by clicking New button, you should set the each port for your connectin. Multiple port can be splited by comma, if continuous number you can use '-' to 

    -- set a range(e.g. 4350,4351,4352 you can put 4350-4352 in the text box). 

4.   Re-launch your wireshark when you finish the port registration.


================================================================
Useful link for lua learning:
================================================================
wireshark wiki  ---  http://wiki.wireshark.org/Lua
A classic pdf book ----  http://sharkfest.wireshark.org/sharkfest.09/DT06_Bjorlykke_Lua%20Scripting%20in%20Wireshark.pdf
KMS wiki ---  http://kmsonline.irdeto.intra/wiki/index.php?title=Wireshark_plugin_lua




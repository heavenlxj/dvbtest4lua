#Get the powershell installation path from registry
$Current_Execution_Path = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Plugin_Script = Get-ChildItem -Path $Current_Execution_Path -Filter "*.lua" -Recurse
$Overwrite_Content = ""
#Do not change the file loading order, some dependecy exists, this should be fixed
$Load_File_Array = "ac.lua", "bitlib.lua", "bitop.lua", "descriptors.lua", "err_info.lua", "config.lua", "port.lua", "filter.lua", "gui.lua", "emmh.lua", "section.lua", "metadata.lua", "msp.lua", "opcodes.lua", "dvb.lua", "cam.lua", "ird.lua", "si.lua", "ice_section.lua"
$Exclude_Filter = "init.lua", "console.lua", "dtd_gen.lua"

try
{
	$Wireshark_Registry_Key_Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wireshark.exe"
	$Error_Message = "Error in find the wireshark registry path, please make sure you have installed wireshark successfully"
	$Wireshark_Install_Path = [Microsoft.win32.registry]::GetValue($Wireshark_Registry_Key_Path, "Path", $Error_Message)

    if ($Wireshark_Install_Path -eq $null)
    {
        Write-Host "Can not find wireshark in your system, please make sure you have installed wireshark!"
        exit 1
    }
}
catch
{
Write-Host "Failed to Retrieve the value from Registry"
}

$Plugin_Path = $Wireshark_Install_Path + "\plugins\lua"
$Filter1 = $Wireshark_Install_Path + "\*.lua"
$Filter2 = $Plugin_Path + "\*.*"
$Wireshark_Init_File_Path = $Wireshark_Install_Path + "\init.lua"
$Set_Plugin_Folder_Init = "PLUGIN_DIR = datafile_path()..'plugins\\lua\\'"
$Add_System_File = "console.lua", "dtd_gen.lua"
$Do_File_Init_Plugin = "dofile(PLUGIN_DIR..`"{0}`")"
$DO_File_Init_Data = "dofile(DATA_DIR..`"{0}`")"
$Search_DoFile_Result = Select-String -Path $Wireshark_Init_File_Path -Pattern "dofile(" -SimpleMatch
$Search_Plugin_Result = Select-String -Path $Wireshark_Init_File_Path -Pattern "PLUGIN_DIR" -SimpleMatch

if ($Search_DoFile_Result -ne $null)
{
    if ($Search_Plugin_Result -ne $null)
    {
      #Remove current line and index
      $Current_Number = $Search_Plugin_Result[0].lineNumber - 2
      $Overwrite_Content = (Get-Content -Path $Wireshark_Init_File_Path)[0..$Current_Number] | Out-String 
    }
    else
    {
      #Remove current line and index
      $Current_Number = $Search_DoFile_Result[0].lineNumber - 2
      $Overwrite_Content = (Get-Content -Path $Wireshark_Init_File_Path)[0..$Current_Number] | Out-String
  }
}
elseif ($Search_Plugin_Result -ne $null)
{
  #Remove current line and index
  $Current_Number = $Search_Plugin_Result[0].lineNumber - 2
  $Overwrite_Content = (Get-Content -Path $Wireshark_Init_File_Path)[0..$Current_Number] | Out-String
}
else
{
  $Overwrite_Content = (Get-Content -Path $Wireshark_Init_File_Path) | Out-String
}

#Change the disable_lua = false to enable the plugin
if ($Overwrite_Content.ToLower().Contains("disable_lua = true") -or $Overwrite_Content.ToLower().Contains("disable_lua = true; do return end;"))
{
  $Overwrite_Content = $Overwrite_Content.Replace("disable_lua = true", "disable_lua = false")
}

#Remove Plugin folder if existed
if (Test-Path $Plugin_Path)
{
    Remove-Item $Plugin_Path -Recurse -Force
}


#Remove all the old files under installation path if existed
Remove-Item $Filter1 -Exclude $Exclude_Filter -Force

#Create the .\plugin\lua folder 
New-Item -Path $Plugin_Path -ItemType Directory -Force

#Copy the plugin file into the plugin folder
foreach ($file in $Plugin_Script)
{
	Copy-Item -Path $file.FullName -Destination $Plugin_Path -Force
}

#Remove the Read-Only Attribute for the files
attrib -r $Filter2

#Overwrite the Init file
Set-Content -Path $Wireshark_Init_File_Path -Value $Overwrite_Content

#Set the relative path for the plugin
Add-Content -Path $Wireshark_Init_File_Path -Value $Set_Plugin_Folder_Init

foreach ($file in $Add_System_File)
{
 	$value = [String]::Format($DO_File_Init_Data, $file) 
 	Add-Content -Path $Wireshark_Init_File_Path -Value $value
}


#Load the plugin file
foreach ($file in $Load_File_Array)
{
 	$value = [String]::Format($Do_File_Init_Plugin, $file)
 	Add-Content -Path $Wireshark_Init_File_Path -Value $value
}

Write-Host ""
write-Host "------------------------------------------"
Write-Host "  !!Load Wireshark Plugin Successfully!!  "
Write-Host "------------------------------------------"
Write-Host ""

Trap [Exception] {
	[Console]::WriteLine("Error during plugin loading!!")
    [Console]::Error.WriteLine($_.Exception.Message)	
	[Console]::Error.WriteLine($_.Exception.InnerException.StackTrace)	
	
	if ($p -ne $null) 
	{
		$p.StandardInput.WriteLine("End")
		$p.StandardInput.Flush()
		$p.WaitForExit()
	}

	exit 1
	}
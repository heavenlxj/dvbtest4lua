@echo off

@echo Enable the powershell script execution policy... 

@REM Enable execution script in powershell x32
%windir%\System32\WindowsPowerShell\v1.0\powershell.exe Set-ExecutionPolicy Unrestricted

@REM Enable execution script in powershell x64
%windir%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Set-ExecutionPolicy Unrestricted


@echo Start to load the plugin, wait for a moment...

powershell .\load_plugin.ps1

pause
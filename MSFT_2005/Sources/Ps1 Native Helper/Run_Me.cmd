@echo off
@cls

cd /d "%~dp0"
powershell -nop -f .\PidKeyData-Direct.ps1 -BinkFile .\Bink.bin -KeyFile .\KeyData.bin
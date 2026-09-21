@cls
@echo off
>nul chcp 437
setlocal enabledelayedexpansion
goto :Job

Group ID    : 3311
Serial      : 1
Security ID : 7792597778124621
HWID        : -7066209111506718658

Msft ** Dll Call results : 001038673622913089434770947177629465325380236491500529507856881
Msft C# Dll Call results : 001038673622913089434770947177629465325380236491500529507856881
Pidgen  Dll Call results : 001038673622913089434770947177629465325380236491500529507856881

--- Native DLL Decoded Successfully ---

Group ID    : 3311
Serial      : 1
Security ID : 242306893
HWID        : -7066209111506718658

--- .Net C# Decoded Successfully ---

Group ID    : 3311
Serial      : 1
Security ID : 242306893
HWID        : -7066209111506718658

:Job
cd /d "%~dp0"
where python >nul 2>nul || goto :eof

set "Group=3311"
set "Serial=1"
set "Last=T83GX"

set   "SecurityIn=7792597778124621"
set  "SecurityDec=0x1BAF538E714F4D"
set "SecurityBits=0x1baf???e714f4d"

set "HWID=-7066209111506718658"
Set "IID=001038673622913089434770947177629465325380236491500529507856881"

set "Encode=!Group! !Serial! !SecurityIn! !HWID!"
set "Decode=!IID!"

echo.
echo "Encode Value : !Encode!"
echo "Decode Value : !Decode!"

echo.
python iid2009.py encode !Encode!

echo.
python iid2009.py decode !Decode!

echo.
python iid2009.py recover !Decode! !Last!

goto :eof
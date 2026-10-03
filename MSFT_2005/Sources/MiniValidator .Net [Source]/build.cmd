@echo off
rem Builds PKeyValidator.exe as a 32-bit app with the compiler that ships with Windows.
rem Keep PidKeyData.dll (the x86 one) in this folder; it gets embedded into the exe.
"%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" /nologo /platform:x86 /optimize+ ^
  /out:PKeyValidator.exe /resource:PidKeyData.dll,PidKeyData.dll Program.cs

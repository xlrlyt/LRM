@echo off

set fwd = %~dp0

@if "x%1" EQU "x" (goto help) else (goto sign)
:help
@echo Usage: xsign.bat filename
@echo Note:  Original file will be overrided by the signed one, no backup
@goto :end
:sign

@echo Sign File %1
set message=%DATE%
date 2015/05/01
CSignTool.exe sign /r sys /f %1 /ac
CsignTool verify /r sys /f %1 /kp
cmd /c wsx bash xbase64.sh
date %message%
:end

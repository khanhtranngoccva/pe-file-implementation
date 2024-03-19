echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set target=%~f1
set cwd=%cd%

cd %location%/payload
%location%/cmake-build-debug/pefile-oep-stager.exe %target%
cl.exe /c /FA /GS- payload.cpp
ml64.exe payload.asm /link /entry:AlignRSP
cd %cwd%
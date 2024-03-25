@echo off
echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set cwd=%cd%

call vcvarsall.bat x64
mkdir %location%\payload\dist
cd %location%/payload/dist
cl.exe /c /Fapayload64 /GS- ../src/payload.cpp
node.exe %location%/src/asm-fix.js --input payload64.asm --output output64.asm --architecture x64
ml64.exe output64.asm /link /entry:AlignRSP
cd %cwd%
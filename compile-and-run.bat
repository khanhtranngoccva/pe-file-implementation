@echo off
cmd /c compile-payload.bat %~f1 %~f2
payload\dist\molware.exe

echo Process exited with error %ERRORLEVEL%
@echo off
rem DroidBridge launcher - no console window. Use this if .vbs is blocked.
setlocal
set "PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
if not exist "%PY%" set "PY=pythonw"
start "" "%PY%" "%~dp0droidbridge.py"
endlocal

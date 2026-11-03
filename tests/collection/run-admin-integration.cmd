@echo off
setlocal
cd /d "%~dp0..\.."
where cl >nul 2>nul
if errorlevel 1 (
    echo Run from an unelevated Visual Studio Developer Command Prompt.
    exit /b 1
)
if not exist build\tests\x64 mkdir build\tests\x64
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\collection\admin-integration.cpp src\collection\*.cpp src\process\*.cpp src\access\*.cpp src\enumerators\*-enumerator.cpp src\native\object-directory.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\admin-integration.exe
if errorlevel 1 exit /b 1
build\tests\x64\admin-integration.exe
exit /b %errorlevel%

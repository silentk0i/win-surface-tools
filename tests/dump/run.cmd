@echo off
setlocal
cd /d "%~dp0..\.."
where cl >nul 2>nul
if errorlevel 1 (
    echo Run from an x64 Visual Studio Developer Command Prompt.
    exit /b 1
)
if not exist build\tests\dump mkdir build\tests\dump
cl /nologo /std:c++20 /EHsc /W4 /DNOMINMAX /Isrc tests\dump\pe-rebuild-tests.cpp src\dump\pe\pe-rebuild.cpp /Fo:build\tests\dump\ /Fe:build\tests\dump\pe-rebuild-tests.exe
if errorlevel 1 exit /b 1
build\tests\dump\pe-rebuild-tests.exe
exit /b %errorlevel%

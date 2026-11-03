@echo off
setlocal
cd /d "%~dp0.."
where cl >nul 2>nul
if errorlevel 1 (
    echo Run this script from a Visual Studio Developer Command Prompt.
    exit /b 1
)
if not exist build\tests\x64 mkdir build\tests\x64
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\discovery-smoke.cpp src\enumerators\*-enumerator.cpp src\native\object-directory.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\discovery-smoke.exe
if errorlevel 1 exit /b 1
build\tests\x64\discovery-smoke.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\access\access-smoke.cpp src\access\*.cpp src\cli\access-output.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\access-smoke.exe
if errorlevel 1 exit /b 1
build\tests\x64\access-smoke.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\report\report-smoke.cpp src\report\report-output.cpp src\cli\access-output.cpp src\access\access-tests.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\report-smoke.exe
if errorlevel 1 exit /b 1
build\tests\x64\report-smoke.exe
if errorlevel 1 exit /b 1
where node >nul 2>nul
if errorlevel 1 (
    echo Node.js is required for the report UI tests.
    exit /b 1
)
node tests\report\report-ui.test.js
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\process\process-smoke.cpp src\process\*.cpp src\access\access-context.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\process-smoke.exe
if errorlevel 1 exit /b 1
build\tests\x64\process-smoke.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /Isrc tests\collection\collection-smoke.cpp src\collection\collector-data.cpp /Fo:build\tests\x64\ /Fe:build\tests\x64\collection-smoke.exe
if errorlevel 1 exit /b 1
build\tests\x64\collection-smoke.exe
if errorlevel 1 exit /b 1
call tests\dump\run.cmd
exit /b %errorlevel%

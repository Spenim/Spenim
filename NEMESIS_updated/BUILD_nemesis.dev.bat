@echo off
setlocal EnableExtensions
chcp 65001 >nul
title Nemesis.dev - One Click Build

cd /d "%~dp0"
echo ============================================
echo          Nemesis.dev - AUTOMATIC BUILD
echo ============================================
echo.

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [ERROR] Visual Studio Installer was not found.
  echo Install Visual Studio 2022 with Desktop development with C++.
  goto :fail
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
  echo [ERROR] MSVC x64 C++ tools were not found.
  goto :fail
)

set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo [ERROR] vcvars64.bat was not found.
  goto :fail
)
call "%VCVARS%" >nul
if errorlevel 1 (
  echo [ERROR] Could not initialize the x64 compiler environment.
  goto :fail
)

where cmake >nul 2>nul
if errorlevel 1 (
  set "VSCMAKE=%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
  if exist "%VSCMAKE%\cmake.exe" set "PATH=%VSCMAKE%;%PATH%"
)
where cmake >nul 2>nul
if errorlevel 1 (
  echo [ERROR] CMake was not found. Install CMake or add it to PATH.
  goto :fail
)

echo.
echo [1/3] Checking CMake...
cmake --version
if errorlevel 1 goto :fail

echo.
echo [2/3] Configuring x64 Release build...
if exist build rmdir /s /q build
cmake -S . -B build -A x64
if errorlevel 1 goto :fail

echo.
echo [3/3] Compiling...
cmake --build build --config Release --parallel
if errorlevel 1 goto :fail

if not exist "build\Release\nemesis.dev.exe" (
  echo [ERROR] Build finished but nemesis.dev.exe was not found.
  goto :fail
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo CLIENT: %CD%\build\Release\nemesis.dev.exe
if exist "%CD%\build\Release\nemesis.dev(DeveloperAccess).exe" echo DEV:    %CD%\build\Release\nemesis.dev(DeveloperAccess).exe
echo SERVER: %CD%\build\Release\nemesis_server.exe
echo ============================================
start "" explorer.exe /select,"%CD%\build\Release\nemesis.dev.exe"
echo.
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Read the error messages above.
echo Check that Visual Studio C++ workload and CMake are installed.
echo.
pause
exit /b 1
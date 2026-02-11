@echo off
REM ============================================================================
REM  SAPology - Build standalone Windows executable
REM
REM  Prerequisites: Python 3.8+ installed on this Windows machine
REM  This script installs dependencies and builds a single .exe file.
REM
REM  Usage: Double-click this file or run from Command Prompt.
REM         The resulting SAPology.exe will be in the "dist" folder.
REM ============================================================================

echo.
echo  ============================================================
echo   SAPology - Windows Build Script
echo  ============================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] Python is not installed or not in PATH.
    echo [-] Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo [*] Installing build dependencies ...
pip install pyinstaller requests rich
if errorlevel 1 (
    echo [-] Failed to install dependencies. Check pip output above.
    pause
    exit /b 1
)

echo.
echo [*] Building standalone executable ...
echo [*] This may take a minute ...
echo.

pyinstaller --onefile --clean --name SAPology --console --noconfirm ^
    --collect-all "rich" ^
    SAPology.py

echo.
if exist "dist\SAPology.exe" (
    echo  ============================================================
    echo   [+] Build successful!
    echo   [+] Executable: dist\SAPology.exe
    echo   [+] Copy SAPology.exe anywhere and run without Python.
    echo  ============================================================
    echo.
    echo  Example usage:
    echo    SAPology.exe -t 192.168.1.0/24
    echo    SAPology.exe -t 10.0.0.1 -v --url-scan
    echo    SAPology.exe -t targets.txt -o report.html
) else (
    echo  [-] Build failed. Check the output above for errors.
)
echo.
pause

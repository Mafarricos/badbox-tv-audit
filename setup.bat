@echo off
setlocal enabledelayedexpansion
title BadBox TV Audit - Prerequisites Setup (Windows)

echo ================================================================================
echo             BadBox TV Audit - Automated Environment Setup                       
echo ================================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python was not found on your system.
    echo [*] Attempting to install Python 3 via winget...
    winget install -e --id Python.Python.3.11 --scope currentuser --accept-package-agreements --accept-source-agreements
    if %ERRORLEVEL% NEQ 0 (
        echo [X] Failed to install Python automatically.
        echo     Please install Python manually from: https://www.python.org/downloads/
        echo     (Be sure to check 'Add python.exe to PATH' during installation)
        pause
        exit /b 1
    )
    echo [v] Python installed successfully! Restart your terminal if python is not yet recognized.
) else (
    for /f "tokens=*" %%i in ('python --version') do echo [v] %%i detected.
)

:: 2. Create or activate Virtual Environment
if not exist "venv" (
    echo [*] Creating isolated virtual environment (venv)...
    python -m venv venv
)

if exist "venv\Scripts\activate.bat" (
    echo [*] Activating venv virtual environment...
    call venv\Scripts\activate.bat
)

:: 3. Upgrade pip and install Python dependencies
echo [*] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

echo [*] Installing Python dependencies (adb-shell, rsa, pyasn1)...
pip install -r requirements.txt

:: 4. Check Android Toolchain (Optional - Only required if compiling APK from source)
echo.
echo ================================================================================
echo           Android Toolchain Verification (Building from source)                 
echo ================================================================================
echo [*] Note: The repository already includes a precompiled APK at:
echo     tools\xcpe-scanner-tv.apk
echo.
set /p INSTALL_SDK="Do you also want to set up JDK 17 and Android SDK to compile APKs from scratch? [y/N]: "
if /i not "!INSTALL_SDK!"=="y" if /i not "!INSTALL_SDK!"=="yes" (
    goto :done
)

:: Check Java JDK 17+
javac -version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Java JDK not found. Installing Microsoft OpenJDK 17 via winget...
    winget install -e --id Microsoft.OpenJDK.17 --accept-package-agreements --accept-source-agreements
    if %ERRORLEVEL% NEQ 0 (
        echo [X] Could not install OpenJDK automatically.
    ) else (
        echo [v] OpenJDK 17 installed.
    )
) else (
    for /f "tokens=*" %%i in ('javac -version 2^>^&1') do echo [v] Java Compiler: %%i
)

:: Check Android SDK commandlinetools
if "%ANDROID_HOME%"=="" if "%ANDROID_SDK_ROOT%"=="" (
    set "DEFAULT_SDK=%LOCALAPPDATA%\Android\Sdk"
    if exist "!DEFAULT_SDK!" (
        echo [v] Android SDK located at: !DEFAULT_SDK!
        set "ANDROID_HOME=!DEFAULT_SDK!"
    ) else (
        echo [*] Android SDK not detected. Running automated toolchain setup...
        python tools\setup_env.py
    )
) else (
    echo [v] ANDROID_HOME configured.
)

:done
echo.
echo ================================================================================
echo [v] Environment ready! You can now audit your Android TV boxes:
echo.
echo     1. Fast 5-layer read-only audit:
echo        python tools\audit_security.py ^<TV_IP^> --quick-scan
echo.
echo     2. Full automated pipeline (Sentinel VPN + APK + scoring):
echo        python tools\audit_security.py ^<TV_IP^> --auto-pipeline
echo.
echo     3. Discover Android TVs across subnet:
echo        python tools\audit_security.py --scan-subnet 192.168.1.0/24
echo.
echo     4. Infection stage forensic classifier:
echo        python tools\detect_infection_stage.py ^<TV_IP^>
echo.
echo     Para a versao em Portugues, execute: setup.pt.bat
echo ================================================================================
pause

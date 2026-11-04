@echo off
setlocal enabledelayedexpansion
title BadBox TV Audit - Instalador Completo de Pre-Requisitos (Windows)

echo ================================================================================
echo             BadBox TV Audit - Configuracao Automatica de Ambiente               
echo ================================================================================
echo.

:: 1. Verificar se o Python esta instalado
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python nao foi encontrado no sistema.
    echo [*] A tentar instalar Python 3 via winget...
    winget install -e --id Python.Python.3.11 --scope currentuser --accept-package-agreements --accept-source-agreements
    if %ERRORLEVEL% NEQ 0 (
        echo [X] Erro ao instalar Python automaticamente.
        echo     Por favor instale manualmente a partir de: https://www.python.org/downloads/
        echo     (Certifique-se de marcar 'Add python.exe to PATH' durante a instalacao)
        pause
        exit /b 1
    )
    echo [v] Python instalado! Reinicie a janela do terminal se o comando python ainda nao for reconhecido.
) else (
    for /f "tokens=*" %%i in ('python --version') do echo [v] %%i detetado.
)

:: 2. Criar ou ativar Virtual Environment
if not exist "venv" (
    echo [*] A criar ambiente virtual isolado (venv)...
    python -m venv venv
)

if exist "venv\Scripts\activate.bat" (
    echo [*] A ativar ambiente virtual venv...
    call venv\Scripts\activate.bat
)

:: 3. Atualizar pip e instalar dependencias Python
echo [*] A atualizar pip...
python -m pip install --upgrade pip >nul 2>&1

echo [*] A instalar dependencias Python (adb-shell, rsa, pyasn1)...
pip install -r requirements.txt

:: 4. Verificar Toolchain Android (Opcional - Necessario apenas se quiser compilar o APK de raiz)
echo.
echo ================================================================================
echo           Verificacao da Toolchain Android (Compilacao de raiz)                 
echo ================================================================================
echo [*] O repositorio ja inclui o APK pre-compilado em tools\xcpe-scanner-tv.apk.
echo     Deseja tambem instalar o JDK 17 e Android SDK para compilar de raiz? (S/N)
set /p INSTALL_SDK="Escolha [S/N] (por omissao N): "

if /i "%INSTALL_SDK%"=="S" (
    echo.
    echo [*] A verificar Java JDK 17...
    javac -version >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [*] A instalar Eclipse Adoptium Temurin 17 JDK via winget...
        winget install -e --id EclipseAdoptium.Temurin.17.JDK --accept-package-agreements --accept-source-agreements
        echo [v] JDK 17 instalado.
    ) else (
        echo [v] Java Compiler detetado.
    )

    if not defined ANDROID_HOME (
        if exist "C:\AndroidSDK" (
            set "ANDROID_HOME=C:\AndroidSDK"
            echo [v] ANDROID_HOME detetado em C:\AndroidSDK
        ) else if exist "%LOCALAPPDATA%\Android\Sdk" (
            set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
            echo [v] ANDROID_HOME detetado em %LOCALAPPDATA%\Android\Sdk
        ) else (
            echo [*] A criar C:\AndroidSDK...
            mkdir "C:\AndroidSDK" >nul 2>&1
            set "ANDROID_HOME=C:\AndroidSDK"
        )
    )

    if not exist "app\local.properties" (
        set "ESCAPED_SDK=!ANDROID_HOME:\=\\!"
        echo sdk.dir=!ESCAPED_SDK!> app\local.properties
        echo [v] app\local.properties configurado com: !ANDROID_HOME!
    )
)

echo.
echo ================================================================================
echo [v] Configuracao concluida com SUCESSO!
echo ================================================================================
echo.
echo Para iniciar a suite forense:
echo   1. Ligue a Depuracao ADB na sua TV (Definicoes -^> Opcoes do Programador)
echo   2. Execute o pipeline automatizado:
echo        python tools\audit_security.py ^<IP_DA_TV^> --auto-pipeline
echo      ou o menu interativo:
echo        python tools\audit_security.py
echo.
pause

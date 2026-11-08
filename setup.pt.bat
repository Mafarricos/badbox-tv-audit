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
echo [*] Nota: O repositorio ja inclui o APK universal pre-compilado em:
echo     tools\xcpe-scanner-tv.apk
echo.
set /p INSTALL_SDK="Deseja tambem configurar o JDK 17 e Android SDK para compilar de raiz? [s/N]: "
if /i not "!INSTALL_SDK!"=="s" if /i not "!INSTALL_SDK!"=="sim" (
    goto :done
)

:: Verificar Java JDK 17+
javac -version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Java JDK nao encontrado. A instalar Microsoft OpenJDK 17 via winget...
    winget install -e --id Microsoft.OpenJDK.17 --accept-package-agreements --accept-source-agreements
    if %ERRORLEVEL% NEQ 0 (
        echo [X] Nao foi possivel instalar o OpenJDK automaticamente.
    ) else (
        echo [v] OpenJDK 17 instalado com sucesso.
    )
) else (
    for /f "tokens=*" %%i in ('javac -version 2^>^&1') do echo [v] Compilador Java: %%i
)

:: Verificar Android SDK commandlinetools
if "%ANDROID_HOME%"=="" if "%ANDROID_SDK_ROOT%"=="" (
    set "DEFAULT_SDK=%LOCALAPPDATA%\Android\Sdk"
    if exist "!DEFAULT_SDK!" (
        echo [v] Android SDK localizado em: !DEFAULT_SDK!
        set "ANDROID_HOME=!DEFAULT_SDK!"
    ) else (
        echo [*] Android SDK nao detetado. A correr assistente de configuracao da toolchain...
        python tools\setup_env.py
    )
) else (
    echo [v] ANDROID_HOME configurado.
)

:done
echo.
echo ================================================================================
echo [v] Ambiente pronto! Pode agora auditar as suas boxes Android TV:
echo.
echo     1. Auditoria rapida de 6 camadas via ADB:
echo        python tools\audit_security.py ^<IP_DA_TV^> --quick-scan
echo.
echo     2. Pipeline completo (Sentinela VPN + APK nativo + pontuacao):
echo        python tools\audit_security.py ^<IP_DA_TV^> --auto-pipeline
echo.
echo     3. Descobrir Android TVs na rede local:
echo        python tools\audit_security.py --scan-subnet 192.168.1.0/24
echo.
echo     4. Classificador forense de estagio de infecao:
echo        python tools\detect_infection_stage.py ^<IP_DA_TV^>
echo.
echo     For the English version, run: setup.bat
echo ================================================================================
pause

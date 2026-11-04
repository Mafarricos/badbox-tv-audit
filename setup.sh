#!/usr/bin/env bash
set -e

echo "================================================================================"
echo "             BadBox TV Audit - Configuração Automática de Ambiente              "
echo "================================================================================"
echo ""

# 1. Verificar Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 não foi encontrado."
    echo "[*] A tentar instalar Python 3..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
    elif command -v brew &> /dev/null; then
        brew install python3
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3 python3-pip
    else
        echo "[X] Gestor de pacotes não suportado. Instale o Python 3 manualmente."
        exit 1
    fi
fi

PYTHON_VER=$(python3 --version)
echo "[✓] $PYTHON_VER detetado."

# 2. Criar e Ativar venv
if [ ! -d "venv" ]; then
    echo "[*] A criar ambiente virtual isolado (venv)..."
    python3 -m venv venv
fi

echo "[*] A ativar venv..."
source venv/bin/activate

# 3. Instalar dependências Python
echo "[*] A instalar pacotes do requirements.txt..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

# 4. Toolchain Android (Opcional)
echo ""
echo "================================================================================"
echo "           Verificação da Toolchain Android (Compilação de raiz)                "
echo "================================================================================"
echo "[*] O repositório já inclui o APK pré-compilado em tools/xcpe-scanner-tv.apk."
read -p "Deseja também configurar JDK 17 e Android SDK para compilar de raiz? [s/N]: " INSTALL_SDK
INSTALL_SDK=${INSTALL_SDK:-N}

if [[ "$INSTALL_SDK" =~ ^[sSyY]$ ]]; then
    if ! command -v javac &> /dev/null; then
        echo "[*] A instalar OpenJDK 17..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y openjdk-17-jdk
        elif command -v brew &> /dev/null; then
            brew install openjdk@17
        fi
    else
        echo "[✓] Java Compiler detetado."
    fi

    SDK_DIR="${ANDROID_HOME:-$HOME/Android/Sdk}"
    if [ ! -f "app/local.properties" ]; then
        echo "sdk.dir=$SDK_DIR" > app/local.properties
        echo "[✓] app/local.properties configurado com: $SDK_DIR"
    fi
fi

echo ""
echo "================================================================================"
echo "[✓] Configuração concluída com SUCESSO!"
echo "================================================================================"
echo ""
echo "Para iniciar a suite forense:"
echo "  1. Ligue a Depuração ADB na sua TV (Definições -> Opções do Programador)"
echo "  2. Execute:"
echo "       source venv/bin/activate"
echo "       python tools/audit_security.py <IP_DA_TV> --auto-pipeline"
echo "     ou o menu interativo:"
echo "       python tools/audit_security.py"
echo ""

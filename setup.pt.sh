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
echo "[*] Nota: O repositório já inclui o APK pré-compilado em:"
echo "    tools/xcpe-scanner-tv.apk"
echo ""
read -p "Deseja também configurar JDK 17 e Android SDK para compilar de raiz? [s/N]: " INSTALL_SDK
INSTALL_SDK=${INSTALL_SDK:-N}

if [[ "$INSTALL_SDK" =~ ^[Ss]$ ]]; then
    # Java JDK 17
    if ! command -v javac &> /dev/null; then
        echo "[*] Java JDK não encontrado. A instalar OpenJDK 17..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y openjdk-17-jdk
        elif command -v brew &> /dev/null; then
            brew install openjdk@17
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y java-17-openjdk-devel
        fi
    else
        echo "[✓] $(javac -version 2>&1) detetado."
    fi

    # Android SDK
    if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
        echo "[*] ANDROID_HOME não definido. A correr assistente de configuração..."
        python3 tools/setup_env.py
    else
        echo "[✓] Android SDK configurado em: ${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
    fi
fi

echo ""
echo "================================================================================"
echo "[✓] Ambiente pronto! Pode agora auditar os seus dispositivos Android TV:"
echo ""
echo "    1. Auditoria rápida de 5 camadas via ADB:"
echo "       python3 tools/audit_security.py <IP_DA_TV> --quick-scan"
echo ""
echo "    2. Pipeline completo (Sentinela VPN + APK nativo + pontuação):"
echo "       python3 tools/audit_security.py <IP_DA_TV> --auto-pipeline"
echo ""
echo "    3. Descobrir Android TVs na sub-rede:"
echo "       python3 tools/audit_security.py --scan-subnet 192.168.1.0/24"
echo ""
echo "    4. Classificador forense de estágio de infeção:"
echo "       python3 tools/detect_infection_stage.py <IP_DA_TV>"
echo ""
echo "    For the English version, run: bash setup.sh"
echo "================================================================================"

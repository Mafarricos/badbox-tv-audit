#!/usr/bin/env bash
set -e

echo "================================================================================"
echo "             BadBox TV Audit - Automated Environment Setup                      "
echo "================================================================================"
echo ""

# 1. Verify Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 was not found."
    echo "[*] Attempting to install Python 3..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
    elif command -v brew &> /dev/null; then
        brew install python3
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3 python3-pip
    else
        echo "[X] Unsupported package manager. Please install Python 3 manually."
        exit 1
    fi
fi

PYTHON_VER=$(python3 --version)
echo "[✓] $PYTHON_VER detected."

# 2. Create and Activate venv
if [ ! -d "venv" ]; then
    echo "[*] Creating isolated virtual environment (venv)..."
    python3 -m venv venv
fi

echo "[*] Activating venv..."
source venv/bin/activate

# 3. Install Python dependencies
echo "[*] Installing dependencies from requirements.txt..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

# 4. Android Toolchain (Optional)
echo ""
echo "================================================================================"
echo "           Android Toolchain Verification (Building from source)                "
echo "================================================================================"
echo "[*] Note: The repository already includes a precompiled APK at:"
echo "    tools/xcpe-scanner-tv.apk"
echo ""
read -p "Do you also want to set up JDK 17 and Android SDK to compile from source? [y/N]: " INSTALL_SDK
INSTALL_SDK=${INSTALL_SDK:-N}

if [[ "$INSTALL_SDK" =~ ^[Yy]$ ]]; then
    # Java JDK 17
    if ! command -v javac &> /dev/null; then
        echo "[*] Java JDK not found. Installing OpenJDK 17..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y openjdk-17-jdk
        elif command -v brew &> /dev/null; then
            brew install openjdk@17
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y java-17-openjdk-devel
        fi
    else
        echo "[✓] $(javac -version 2>&1) detected."
    fi

    # Android SDK
    if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
        echo "[*] ANDROID_HOME not set. Running toolchain setup wizard..."
        python3 tools/setup_env.py
    else
        echo "[✓] Android SDK configured at: ${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
    fi
fi

echo ""
echo "================================================================================"
echo "[✓] Setup complete! You can now audit your Android TV devices:"
echo ""
echo "    1. Fast 6-layer read-only audit:"
echo "       python3 tools/audit_security.py <TV_IP> --quick-scan"
echo ""
echo "    2. Full automated pipeline (VPN sentinel + native APK + scoring):"
echo "       python3 tools/audit_security.py <TV_IP> --auto-pipeline"
echo ""
echo "    3. Discover Android TVs across subnet:"
echo "       python3 tools/audit_security.py --scan-subnet 192.168.1.0/24"
echo ""
echo "    4. Forensic infection stage classifier:"
echo "       python3 tools/detect_infection_stage.py <TV_IP>"
echo ""
echo "    Para a versão em Português, execute: bash setup.pt.sh"
echo "================================================================================"

# -*- coding: utf-8 -*-
"""
Ferramenta Integrada de Instalação e Configuração de Pré-Requisitos
Permite a qualquer pessoa ou agente instalar facilmente as dependências necessárias
(Python, Pacotes ADB, Java JDK 17 e Android SDK) com um menu simples.
"""

import sys
import os
import subprocess
import shutil

# Configurar stdout/stderr UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_PROJECT_DIR = os.path.join(PROJECT_ROOT, "app")


def check_python_deps():
    print("\n[*] A verificar pacotes Python necessários (adb-shell, rsa, pyasn1)...")
    req_file = os.path.join(PROJECT_ROOT, "requirements.txt")
    cmd = [sys.executable, "-m", "pip", "install", "-r", req_file]
    res = subprocess.run(cmd)
    if res.returncode == 0:
        print("    [✓] Dependências Python instaladas e atualizadas com sucesso!")
        return True
    else:
        print("    [!] Erro ao instalar dependências Python.")
        return False


def check_and_install_jdk():
    print("\n[*] A verificar Java JDK 17 (Necessário apenas para compilar de raiz)...")
    javac_found = False
    try:
        res = subprocess.run(["javac", "-version"], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"    [✓] Java detetado: {res.stdout.strip() or res.stderr.strip()}")
            javac_found = True
    except FileNotFoundError:
        pass

    if not javac_found and sys.platform == "win32":
        default_jdk = r"C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
        if os.path.exists(default_jdk):
            os.environ["JAVA_HOME"] = default_jdk
            os.environ["PATH"] = os.path.join(default_jdk, "bin") + os.pathsep + os.environ["PATH"]
            print(f"    [✓] JDK 17 encontrado em: {default_jdk}")
            return True

        print("    [*] A descarregar e instalar Eclipse Adoptium Temurin 17 JDK via winget...")
        cmd = ["winget", "install", "-e", "--id", "EclipseAdoptium.Temurin.17.JDK", "--accept-package-agreements", "--accept-source-agreements"]
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print("    [✓] JDK 17 instalado com sucesso!")
            return True
        else:
            print("    [!] Falha na instalação automática do JDK. Pode descarregar em: https://adoptium.net/")
            return False
    elif not javac_found:
        print("    [*] A instalar OpenJDK 17 via gestor de pacotes do sistema...")
        if shutil.which("apt-get"):
            subprocess.run(["sudo", "apt-get", "update"])
            subprocess.run(["sudo", "apt-get", "install", "-y", "openjdk-17-jdk"])
            return True
        elif shutil.which("brew"):
            subprocess.run(["brew", "install", "openjdk@17"])
            return True
    return javac_found


def check_and_configure_sdk():
    print("\n[*] A verificar configuração do Android SDK...")
    android_home = os.environ.get("ANDROID_HOME")
    candidates = [
        r"C:\AndroidSDK",
        os.path.expanduser("~/Android/Sdk"),
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")
    ]
    if not android_home:
        for c in candidates:
            if os.path.exists(c):
                android_home = c
                break

    if not android_home:
        # Sugerir pasta padrão
        default_dir = r"C:\AndroidSDK" if sys.platform == "win32" else os.path.expanduser("~/Android/Sdk")
        print(f"    [!] Android SDK não encontrado. A inicializar diretoria em: {default_dir}")
        os.makedirs(default_dir, exist_ok=True)
        android_home = default_dir

    local_prop = os.path.join(APP_PROJECT_DIR, "local.properties")
    escaped = android_home.replace("\\", "\\\\") if sys.platform == "win32" else android_home
    with open(local_prop, "w", encoding="utf-8") as f:
        f.write(f"sdk.dir={escaped}\n")
    print(f"    [✓] app/local.properties configurado com: {android_home}")
    return True


def interactive_installer_menu():
    while True:
        print("\n================================================================================")
        print("       CONFIGURADOR DE PRÉ-REQUISITOS - BADBOX TV AUDIT                         ")
        print("================================================================================")
        print("  1. Instalar Pré-Requisitos Padrão (Python + Dependências ADB - Rápido)")
        print("     -> Permite usar o APK universal pré-compilado sem precisar de Java/SDK.")
        print("")
        print("  2. Instalar Toolchain Completa (JDK 17 + Android SDK - Para Compilação de Raiz)")
        print("     -> Permite recompilar o APK à medida para SoCs específicos em tempo real.")
        print("")
        print("  3. Instalar TUDO (Modo Completo)")
        print("  0. Voltar / Sair")
        print("================================================================================")
        choice = input("Escolha uma opção [0-3]: ").strip()

        if choice == "1":
            check_python_deps()
            input("\nPrima ENTER para continuar...")
        elif choice == "2":
            check_and_install_jdk()
            check_and_configure_sdk()
            input("\nPrima ENTER para continuar...")
        elif choice == "3":
            check_python_deps()
            check_and_install_jdk()
            check_and_configure_sdk()
            print("\n[✓] Todos os componentes e toolchains estão prontos!")
            input("\nPrima ENTER para continuar...")
        elif choice == "0":
            break


if __name__ == "__main__":
    interactive_installer_menu()

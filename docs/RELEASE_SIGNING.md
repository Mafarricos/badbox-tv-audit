# Procedimento de Assinatura e Gestão de Chaves de Release

> **Aviso Crítico de Segurança:**  
> A chave de release anterior (`badbox-release`), cujo keystore esteve versionado no repositório, está **definitivamente comprometida** e foi revogada. Qualquer utilizador com a versão legada instalada na Android TV deve **desinstalar a aplicação** antes de instalar lançamentos oficiais posteriores à versão 2.0.0.

---

## 1. Geração de Nova Chave de Release (Executado Fora do Repositório)

O mantenedor deve gerar a chave criptográfica numa máquina isolada e segura, fora do diretório do repositório:

```bash
keytool -genkeypair \
  -v \
  -keystore release.keystore \
  -alias badbox-release \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -deststoretype JKS
```

Guarde a palavra-passe do keystore e a palavra-passe do alias num gestor de palavras-passe seguro. **Nunca copie o ficheiro `.keystore` ou `.jks` para dentro de diretórios controlados pelo Git.**

---

## 2. Configuração de Segredos no GitHub Actions

No repositório do GitHub, navegue até **Settings** -> **Secrets and variables** -> **Actions** e crie os seguintes segredos:

1. `ANDROID_KEYSTORE_BASE64`: Conteúdo do ficheiro `release.keystore` codificado em base64 (`base64 -w 0 release.keystore` ou no PowerShell `[Convert]::ToBase64String([IO.File]::ReadAllBytes("release.keystore"))`).
2. `ANDROID_KEYSTORE_PASSWORD`: Palavra-passe do keystore.
3. `ANDROID_KEY_ALIAS`: Nome do alias configurado (`badbox-release`).
4. `ANDROID_KEY_PASSWORD`: Palavra-passe da chave do alias.

---

## 3. Publicação de Release Oficial

1. Criar uma nova tag semântica:
   ```bash
   git tag -a v2.0.0 -m "Release v2.0.0"
   git push origin v2.0.0
   ```
2. O workflow de CI/CD em `.github/workflows/release.yml` decodifica a keystore em memória efémera, compila o APK (`assembleRelease`), assina-o e gera o fingerprint:
   ```bash
   apksigner verify --print-certs app-release.apk
   ```
3. O workflow publica o APK, o ficheiro `.sha256` e a impressão digital pública nas notas da Release do GitHub.
4. O mantenedor atualiza o ficheiro `tools/apk_pin.json` com o `cert_sha256` oficial verificado.

---

## 4. Atualização de Dispositivos e Histórico Git

* **Desinstalação Obrigatória:** Dispositivos com versões anteriores assinadas pela chave vazada rejeitarão a atualização oficial (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`). O utilizador deve desinstalar a versão legada via comando `pm uninstall com.scanner.tv` ou através da interface de definições da TV.
* **Histórico Git:** Caso o mantenedor decida purgar o ficheiro comprometido do histórico histórico do repositório, pode ser executado o utilitário `git-filter-repo`. Note-se, contudo, que reescrever commits passados não anula o facto de a chave ter sido exposta publicamente, razão pela qual a revogação e migração de chave é a única medida de segurança válida.

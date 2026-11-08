# Política de Segurança (Security Policy)

## Notificação de Chave Comprometida (Revogação de Chave v1.0)

A chave de assinatura privada anteriormente utilizada no projeto esteve inadvertidamente exposta no repositório. Por conseguinte, a seguinte impressão digital SHA-256 está **OFICIALMENTE DECLARADA COMPROMETIDA E REVOGADA**:

```text
70:BA:AC:0D:7E:C8:74:C1:C6:9E:FA:A5:FC:66:40:EA:F9:71:7F:A5:02:9A:BD:E4:8E:50:88:6F:2A:EB:53:14
```

Qualquer pacote APK assinado por este certificado não deve ser considerado autêntico. Se possui uma versão antiga instalada na sua Android TV, **desinstale-a de imediato** através de:
```bash
adb shell pm uninstall com.scanner.tv
```

---

## Verificação de Autenticidade dos Lançamentos Oficiais (v2.0.0+)

Os binários oficiais disponibilizados nas Releases do GitHub são compilados via GitHub Actions a partir de segredos isolados. Para verificar a autenticidade de um APK antes de o instalar na sua TV:

```bash
apksigner verify --print-certs tools/xcpe-scanner-tv.apk
```

Compare a impressão digital obtida com o valor oficial publicado no ficheiro `tools/apk_pin.json` e nas notas de lançamento oficiais.

---

## Reporte Responsável de Vulnerabilidades

Agradecemos o reporte responsável de quaisquer falhas de segurança encontradas neste projeto:

1. **Canal de Contacto:** Envie detalhes técnicos para o e-mail: `mafastudios@gmail.com`.
2. **Encriptação:** Se desejar partilhar dados sensíveis ou provas de conceito de exploração, solicite a chave PGP do mantenedor pelo e-mail acima.
3. **Prazos:** Comprometemo-nos a responder no prazo de 48 horas e a disponibilizar correções em ambiente de teste no prazo máximo de 14 dias para vulnerabilidades de gravidade crítica/alta.

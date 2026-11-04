package com.scanner.tv;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 0x0F;

    private TextView tvVerdictBadge;
    private TextView tvScore;
    private TextView tvSubStatus;
    private TextView tvLogOutput;
    private TextView tvDeviceStats;
    private Button btnScan;
    private Button btnVpnMonitor;
    private Button btnRemediate;
    private ScrollView scrollLogs;

    private boolean isVpnRunning = false;
    private int criticalThreatsCount = 0;
    private int anomalyThreatsCount = 0;
    private ScanResult lastResult = null;
    private final List<String> detectedMaliciousPackages = new ArrayList<>();

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        AuditLogger.init(getApplicationContext());

        tvVerdictBadge = findViewById(R.id.tvVerdictBadge);
        tvScore = findViewById(R.id.tvScore);
        tvSubStatus = findViewById(R.id.tvSubStatus);
        tvLogOutput = findViewById(R.id.tvLogOutput);
        tvDeviceStats = findViewById(R.id.tvDeviceStats);
        btnScan = findViewById(R.id.btnScan);
        btnVpnMonitor = findViewById(R.id.btnVpnMonitor);
        btnRemediate = findViewById(R.id.btnRemediate);
        scrollLogs = findViewById(R.id.scrollLogs);

        btnScan.setOnClickListener(v -> startAudit());
        btnVpnMonitor.setOnClickListener(v -> toggleVpnMonitor());
        btnRemediate.setOnClickListener(v -> triggerOnScreenRemediation());

        PacketMonitorVpnService.setPacketListener(this::handlePacketEvent);

        btnScan.requestFocus();
    }

    private void appendColoredLog(String text, int color) {
        mainHandler.post(() -> {
            SpannableString ss = new SpannableString(text + "\n");
            ss.setSpan(new ForegroundColorSpan(color), 0, ss.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            tvLogOutput.append(ss);
            scrollLogs.post(() -> scrollLogs.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void handlePacketEvent(String level, String logMessage) {
        if ("CRITICO".equals(level)) {
            criticalThreatsCount++;
            appendColoredLog("[!] " + logMessage, Color.parseColor("#EF4444"));
            mainHandler.post(() -> {
                tvVerdictBadge.setText("PERIGO [C2 ATIVO]");
                tvVerdictBadge.setBackgroundColor(Color.parseColor("#B91C1C"));
                tvVerdictBadge.setTextColor(Color.WHITE);
                btnRemediate.setVisibility(View.VISIBLE);
                btnVpnMonitor.setNextFocusDownId(R.id.btnRemediate);
            });
        } else if ("ANOMALIA".equals(level)) {
            anomalyThreatsCount++;
            appendColoredLog("[?] " + logMessage, Color.parseColor("#F59E0B"));
        } else {
            appendColoredLog(logMessage, Color.WHITE);
        }
    }

    private void startAudit() {
        tvVerdictBadge.setText("ANALISANDO...");
        tvVerdictBadge.setBackgroundColor(Color.parseColor("#1E293B"));
        tvVerdictBadge.setTextColor(Color.WHITE);
        tvLogOutput.setText("");
        detectedMaliciousPackages.clear();

        appendColoredLog("=================================================", Color.WHITE);
        appendColoredLog("       A INICIAR AUDITORIA FORENSE NA TV         ", Color.WHITE);
        appendColoredLog("=================================================", Color.WHITE);

        executor.execute(() -> {
            ScanResult result = CoreScanner.executeScan(getApplicationContext(), msg -> {
                appendColoredLog(msg, Color.parseColor("#93C5FD"));
            });

            lastResult = result;

            mainHandler.post(() -> {
                tvDeviceStats.setText(result.deviceDetails);
                tvScore.setText(result.findings.size() + " Ameaça(s)");

                appendColoredLog("\n=================================================", Color.WHITE);
                appendColoredLog("               RELATÓRIO CONCLUÍDO               ", Color.WHITE);
                appendColoredLog("=================================================", Color.WHITE);
                appendColoredLog("Veredito: " + result.overallStatus.name(), Color.WHITE);
                appendColoredLog("Pontuação de Risco: " + result.riskScore, Color.WHITE);
                appendColoredLog("Play Protect: " + result.playProtectStatus, Color.WHITE);
                appendColoredLog("APKs OEM analisados: " + result.scannedApks.size(), Color.WHITE);

                for (String f : result.findings) {
                    if (f.contains("[CRÍTICO]")) {
                        appendColoredLog("  * " + f, Color.parseColor("#EF4444"));
                        if (f.contains("Pacote com assinatura")) {
                            String pkg = f.substring(f.lastIndexOf(":") + 1).trim();
                            if (!pkg.isEmpty()) detectedMaliciousPackages.add(pkg);
                        }
                    } else if (f.contains("[AVISO INFORMATIVO]")) {
                        appendColoredLog("  * " + f, Color.parseColor("#38BDF8"));
                    } else {
                        appendColoredLog("  * " + f, Color.parseColor("#F59E0B"));
                    }
                }

                switch (result.overallStatus) {
                    case LIMPO:
                        tvVerdictBadge.setText("DISPOSITIVO LIMPO");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#15803D"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Nenhum sinal de malware ou botnet.");
                        btnRemediate.setVisibility(View.GONE);
                        break;
                    case SUSPEITO:
                        tvVerdictBadge.setText("ALERTA [SUSPEITO]");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B45309"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Detectadas anomalias estruturais.");
                        btnRemediate.setVisibility(View.VISIBLE);
                        btnVpnMonitor.setNextFocusDownId(R.id.btnRemediate);
                        break;
                    case INFETADO_CRITICO:
                        tvVerdictBadge.setText("PERIGO [INFETADO]");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B91C1C"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Assinatura de XCPE / BadBox detectada!");
                        btnRemediate.setVisibility(View.VISIBLE);
                        btnVpnMonitor.setNextFocusDownId(R.id.btnRemediate);
                        btnRemediate.requestFocus();
                        break;
                }
            });
        });
    }

    /**
     * Remediação Nativa no ecrã da TV:
     * 1. Desinstalação com confirmação D-Pad para cada app maliciosa detetada
     * 2. Atalho para ativar Google Play Protect
     * 3. Atalho para configurar Private DNS seguro
     */
    private void triggerOnScreenRemediation() {
        appendColoredLog("\n=================================================", Color.parseColor("#F59E0B"));
        appendColoredLog("      A INICIAR REMEDIAÇÃO NATIVA NA TV          ", Color.parseColor("#F59E0B"));
        appendColoredLog("=================================================", Color.parseColor("#F59E0B"));

        if (!detectedMaliciousPackages.isEmpty()) {
            appendColoredLog("[*] A abrir desinstalação guiada das apps da botnet...", Color.WHITE);
            for (String pkg : detectedMaliciousPackages) {
                appendColoredLog("   -> A solicitar remoção de: " + pkg, Color.parseColor("#EF4444"));
                Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
                uninstallIntent.setData(Uri.parse("package:" + pkg));
                uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
                try {
                    startActivity(uninstallIntent);
                } catch (Exception e) {
                    appendColoredLog("   [!] App do sistema (necessita de congelamento via ADB): " + pkg, Color.parseColor("#F59E0B"));
                }
            }
        } else {
            appendColoredLog("[✓] Não foram encontrados pacotes de terceiros na partição de utilizador.", Color.WHITE);
        }

        appendColoredLog("\n[*] A abrir Definições de Segurança / Play Protect na TV...", Color.WHITE);
        appendColoredLog("    Por favor confirme que a 'Verificação de apps' está ATIVA.", Color.parseColor("#38BDF8"));
        
        try {
            Intent secIntent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
            startActivity(secIntent);
        } catch (Exception ignored) {
            try {
                Intent setIntent = new Intent(Settings.ACTION_SETTINGS);
                startActivity(setIntent);
            } catch (Exception e) {
                appendColoredLog("[!] Não foi possível abrir definições automaticamente.", Color.parseColor("#EF4444"));
            }
        }

        appendColoredLog("\n[✓] Passos de remediação aplicados!", Color.parseColor("#22C55E"));
        appendColoredLog(">>> Prima novamente 'ANALISAR BOX' para comprovar a eficácia da limpeza!\n", Color.parseColor("#38BDF8"));
        btnScan.requestFocus();
    }

    private void toggleVpnMonitor() {
        if (!isVpnRunning) {
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST_CODE);
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
            }
        } else {
            Intent intent = new Intent(this, PacketMonitorVpnService.class);
            intent.setAction("STOP");
            startService(intent);
            isVpnRunning = false;
            btnVpnMonitor.setText("MONITORIZAR REDE (VPN)");
            btnVpnMonitor.setBackgroundResource(R.drawable.btn_green_focused);
            btnVpnMonitor.requestFocus();
            appendColoredLog("\n[i] Monitor de rede VPN parado.", Color.WHITE);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, PacketMonitorVpnService.class);
            startService(intent);
            isVpnRunning = true;
            btnVpnMonitor.setText("PARAR MONITOR VPN");
            btnVpnMonitor.setBackgroundResource(R.drawable.btn_red_focused);
            btnVpnMonitor.requestFocus();
            appendColoredLog("\n[✓] Modo Sentinela Global Ativo!", Color.parseColor("#22C55E"));
            appendColoredLog("Filtro Ativo: Tráfego C2/Botnet a VERMELHO | Portas não habituais a AMARELO\n", Color.WHITE);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}

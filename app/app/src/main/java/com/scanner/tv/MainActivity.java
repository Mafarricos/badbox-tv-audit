package com.scanner.tv;

import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

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
    private ScrollView scrollLogs;

    private boolean isVpnRunning = false;
    private int criticalThreatsCount = 0;
    private int anomalyThreatsCount = 0;

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
        scrollLogs = findViewById(R.id.scrollLogs);

        btnScan.setOnClickListener(v -> startAudit());
        btnVpnMonitor.setOnClickListener(v -> toggleVpnMonitor());

        // Callback em tempo real com distinção por cores (Vermelho vs Amarelo)
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
        mainHandler.post(() -> {
            if ("CRITICO".equals(level)) {
                criticalThreatsCount++;
                appendColoredLog(logMessage, Color.parseColor("#EF4444")); // Vermelho vivo
                tvVerdictBadge.setText("PERIGO [C2 / BOTNET]");
                tvVerdictBadge.setBackgroundColor(Color.parseColor("#B91C1C"));
                tvVerdictBadge.setTextColor(Color.WHITE);
            } else {
                anomalyThreatsCount++;
                appendColoredLog(logMessage, Color.parseColor("#F59E0B")); // Amarelo/Laranja
                if (criticalThreatsCount == 0) {
                    tvVerdictBadge.setText("ALERTA [ANOMALIA REDE]");
                    tvVerdictBadge.setBackgroundColor(Color.parseColor("#B45309"));
                    tvVerdictBadge.setTextColor(Color.WHITE);
                }
            }
            tvScore.setText((criticalThreatsCount + anomalyThreatsCount) + " Alerta(s)");
            tvSubStatus.setText(criticalThreatsCount + " Críticos | " + anomalyThreatsCount + " Anomalias");
        });
    }

    private void startAudit() {
        btnScan.setEnabled(false);
        btnScan.setText("A AUDITAR...");
        tvLogOutput.setText("");
        tvVerdictBadge.setText("SCAN EM CURSO...");
        tvVerdictBadge.setBackgroundColor(Color.parseColor("#334155"));
        tvVerdictBadge.setTextColor(Color.parseColor("#94A3B8"));
        tvScore.setText("0");
        tvSubStatus.setText("A analisar 5 camadas de segurança...");

        executor.execute(() -> {
            appendColoredLog("=================================================", Color.WHITE);
            appendColoredLog("    INÍCIO DA AUDITORIA FORENSE NATIVA DA BOX   ", Color.WHITE);
            appendColoredLog("=================================================\n", Color.WHITE);

            ScanResult result = CoreScanner.executeScan(getApplicationContext(), msg -> appendColoredLog(msg, Color.parseColor("#94A3B8")));

            mainHandler.post(() -> {
                btnScan.setEnabled(true);
                btnScan.setText("REPETIR ANÁLISE");
                btnScan.requestFocus();
                tvDeviceStats.setText(result.deviceDetails);
                tvScore.setText(result.findings.size() + " Ameaça(s)");

                appendColoredLog("\n=================================================", Color.WHITE);
                appendColoredLog("               RELATÓRIO CONCLUÍDO               ", Color.WHITE);
                appendColoredLog("=================================================", Color.WHITE);
                appendColoredLog("Veredito: " + result.overallStatus.name(), Color.WHITE);
                appendColoredLog("Pontuação de Risco: " + result.riskScore, Color.WHITE);
                appendColoredLog("Play Protect: " + result.playProtectStatus, Color.WHITE);
                appendColoredLog("APKs OEM analisados: " + result.scannedApks.size(), Color.WHITE);

                if (result.findings.isEmpty()) {
                    appendColoredLog("\n[✓] A box está LIMPA. Nenhum IoC de botnet detectado.", Color.parseColor("#22C55E"));
                } else {
                    appendColoredLog("\nDETALHE DOS ACHADOS:", Color.WHITE);
                    for (String f : result.findings) {
                        int c = f.contains("CRÍTICO") ? Color.parseColor("#EF4444") : Color.parseColor("#F59E0B");
                        appendColoredLog(" * " + f, c);
                    }
                }
                appendColoredLog("\nLog gravado em: last_scan.json e audit_events.log\n", Color.WHITE);

                switch (result.overallStatus) {
                    case LIMPO:
                        tvVerdictBadge.setText("BOX LIMPA [SEGURO]");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#15803D"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Nenhum sinal de malware ou botnet.");
                        break;
                    case SUSPEITO:
                        tvVerdictBadge.setText("ALERTA [SUSPEITO]");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B45309"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Detectadas anomalias estruturais.");
                        break;
                    case INFETADO_CRITICO:
                        tvVerdictBadge.setText("PERIGO [INFETADO]");
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B91C1C"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText("Assinatura de XCPE / BadBox detectada!");
                        break;
                }
            });
        });
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

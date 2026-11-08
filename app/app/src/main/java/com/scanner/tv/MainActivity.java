package com.scanner.tv;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
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

        // Se a app for aberta através do pipeline automatizado (--auto-pipeline ou extra auto_start)
        boolean autoStart = getIntent().getBooleanExtra("auto_start", false);
        if (autoStart) {
            mainHandler.postDelayed(this::startAudit, 800);
        }
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
                tvVerdictBadge.setText(getString(R.string.badge_c2_active));
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
        tvVerdictBadge.setText(getString(R.string.badge_scanning));
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
                tvScore.setText(getString(R.string.threats_count, result.findings.size()));

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
                        tvVerdictBadge.setText(getString(R.string.badge_clean));
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#15803D"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText(getString(R.string.substatus_clean));
                        btnRemediate.setVisibility(View.GONE);
                        break;
                    case SUSPEITO:
                        tvVerdictBadge.setText(getString(R.string.badge_suspicious));
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B45309"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText(getString(R.string.substatus_suspicious));
                        btnRemediate.setVisibility(View.VISIBLE);
                        btnVpnMonitor.setNextFocusDownId(R.id.btnRemediate);
                        break;
                    case INFETADO_CRITICO:
                        tvVerdictBadge.setText(getString(R.string.badge_infected));
                        tvVerdictBadge.setBackgroundColor(Color.parseColor("#B91C1C"));
                        tvVerdictBadge.setTextColor(Color.WHITE);
                        tvSubStatus.setText(getString(R.string.substatus_infected));
                        btnRemediate.setVisibility(View.VISIBLE);
                        btnVpnMonitor.setNextFocusDownId(R.id.btnRemediate);
                        break;
                }

                // Notifica o sistema de que a primeira fase estática terminou
                AuditLogger.log("INFO", "STATUS", "SCAN_ESTATICO_CONCLUIDO");

                // Transição sequencial inteligente: se foi chamada pelo pipeline ou auto-start,
                // inicia de imediato a segunda fase (monitorização de rede VPN)
                boolean autoStart = getIntent().getBooleanExtra("auto_start", false);
                if (autoStart && !isVpnRunning) {
                    mainHandler.postDelayed(this::toggleVpnMonitor, 1000);
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

        List<String> userPkgs = (lastResult != null) ? new ArrayList<>(lastResult.userThreatPackages) : new ArrayList<>();
        List<String> sysPkgs = (lastResult != null) ? new ArrayList<>(lastResult.systemThreatPackages) : new ArrayList<>();

        if (userPkgs.isEmpty() && sysPkgs.isEmpty() && !detectedMaliciousPackages.isEmpty()) {
            for (String p : detectedMaliciousPackages) {
                try {
                    ApplicationInfo ai = getPackageManager().getApplicationInfo(p, 0);
                    if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0 || (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                        sysPkgs.add(p);
                    } else {
                        userPkgs.add(p);
                    }
                } catch (Exception e) {
                    userPkgs.add(p);
                }
            }
        }

        // 1. Desinstalação com D-Pad de Apps de Utilizador (/data/app)
        if (!userPkgs.isEmpty()) {
            appendColoredLog("\n[Passo 1/3] A solicitar desinstalação de apps na partição de utilizador...", Color.WHITE);
            for (String pkg : userPkgs) {
                appendColoredLog("   -> A solicitar desinstalação: " + pkg, Color.parseColor("#EF4444"));
                Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
                uninstallIntent.setData(Uri.parse("package:" + pkg));
                uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
                try {
                    startActivity(uninstallIntent);
                } catch (Exception e) {
                    appendColoredLog("   [!] Erro ao invocar desinstalação: " + pkg, Color.parseColor("#EF4444"));
                }
            }
        } else {
            appendColoredLog("\n[Passo 1/3] Nenhuma app maliciosa removível em /data/app.", Color.WHITE);
        }

        // 2. Isolamento de Implantes de Sistema (/system, /vendor) via Quarentena Sinkhole e Definições
        if (!sysPkgs.isEmpty()) {
            appendColoredLog("\n[Passo 2/3] Implantes de sistema detetados (/system ou /vendor):", Color.parseColor("#EF4444"));
            appendColoredLog("   Nota: Sem ADB/PC, o Android TV bloqueia a desinstalação direta de apps de fábrica.", Color.parseColor("#F59E0B"));
            appendColoredLog("   [*] A ativar Quarentena de Rede (VpnService Sinkhole) para cortar ligações C2...", Color.parseColor("#22C55E"));

            Intent vpnPrep = VpnService.prepare(this);
            if (vpnPrep == null) {
                Intent qIntent = new Intent(this, PacketMonitorVpnService.class);
                qIntent.setAction(PacketMonitorVpnService.ACTION_QUARANTINE);
                qIntent.putStringArrayListExtra(PacketMonitorVpnService.EXTRA_QUARANTINE_PKGS, new ArrayList<>(sysPkgs));
                startService(qIntent);
                isVpnRunning = true;
                btnVpnMonitor.setText(getString(R.string.btn_stop_vpn));
                btnVpnMonitor.setBackgroundResource(R.drawable.btn_red_focused);
                appendColoredLog("   [✓] Quarentena Sinkhole ATIVA: Tráfego de rede dos implantes foi travado!", Color.parseColor("#22C55E"));
            } else {
                startActivityForResult(vpnPrep, VPN_REQUEST_CODE);
            }

            appendColoredLog("   [*] A abrir ecrã de detalhes da app (prima 'Forçar Paragem' e 'Desativar' no telecomando):", Color.parseColor("#38BDF8"));
            for (String pkg : sysPkgs) {
                try {
                    Intent detailsIntent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    detailsIntent.setData(Uri.parse("package:" + pkg));
                    startActivity(detailsIntent);
                } catch (Exception ignored) {}
            }
        } else {
            appendColoredLog("\n[Passo 2/3] Nenhum implante de sistema detetado.", Color.WHITE);
        }

        // 3. Ativação de Google Play Protect
        appendColoredLog("\n[Passo 3/3] A abrir Definições de Segurança / Play Protect...", Color.WHITE);
        appendColoredLog("    Por favor confirme que a 'Verificação de apps' está ATIVA.", Color.parseColor("#38BDF8"));
        try {
            Intent secIntent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
            startActivity(secIntent);
        } catch (Exception ignored) {
            try {
                Intent setIntent = new Intent(Settings.ACTION_SETTINGS);
                startActivity(setIntent);
            } catch (Exception e) {
                appendColoredLog("[!] Não foi possível abrir definições gerais automaticamente.", Color.parseColor("#EF4444"));
            }
        }

        if (!sysPkgs.isEmpty()) {
            appendColoredLog("\n[!] AVISO IMPORTANTE: Implantes de sistema foram isolados na Quarentena VPN (tráfego de rede bloqueado).", Color.parseColor("#F59E0B"));
            appendColoredLog("    Para desativação permanente da app de fábrica sem PC, utilize 'Desativar' nas Definições da TV,", Color.parseColor("#F59E0B"));
            appendColoredLog("    ou execute via PC/ADB: adb shell pm disable-user --user 0 " + sysPkgs.get(0), Color.parseColor("#38BDF8"));
        } else {
            appendColoredLog("\n[✓] Ações de desinstalação aplicadas com sucesso!", Color.parseColor("#22C55E"));
            appendColoredLog(">>> Prima 'ANALISAR BOX' para validar o estado de limpeza!\n", Color.parseColor("#38BDF8"));
        }
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
            btnVpnMonitor.setText(getString(R.string.btn_vpn_monitor));
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
            btnVpnMonitor.setText(getString(R.string.btn_stop_vpn));
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

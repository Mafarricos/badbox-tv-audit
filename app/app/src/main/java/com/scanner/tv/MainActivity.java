package com.scanner.tv;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
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
    private static final int REQUEST_UNINSTALL_PACKAGE = 0x10;

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
    private final List<String> mPendingUninstalls = new ArrayList<>();
    private final List<String> mPendingSysPackages = new ArrayList<>();
    private final List<String> mEligibleQuarantinePkgs = new ArrayList<>();

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
        } else if ("SUSPICIOUS".equals(level) || "ANOMALIA".equals(level)) {
            anomalyThreatsCount++;
            appendColoredLog("[?] " + logMessage, Color.parseColor("#F59E0B"));
        } else if ("QUARANTINE_ABORTED".equals(level)) {
            appendColoredLog("[!] " + logMessage, Color.parseColor("#F59E0B"));
            mainHandler.post(() -> {
                isVpnRunning = false;
                btnVpnMonitor.setText(getString(R.string.btn_vpn_monitor));
                btnVpnMonitor.setBackgroundResource(R.drawable.btn_green_focused);
            });
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
                int threats = result.getThreatCount();
                tvScore.setText(getString(R.string.threats_count, threats));

                appendColoredLog("\n=================================================", Color.WHITE);
                appendColoredLog("               RELATÓRIO CONCLUÍDO               ", Color.WHITE);
                appendColoredLog("=================================================", Color.WHITE);
                appendColoredLog("Veredito: " + result.overallStatus.name(), Color.WHITE);
                appendColoredLog("Pontuação de Risco: " + result.riskScore, Color.WHITE);
                appendColoredLog("Ameaças Reais: " + threats, Color.WHITE);
                appendColoredLog("Play Protect: " + result.playProtectStatus, Color.WHITE);
                appendColoredLog("APKs OEM analisados: " + result.scannedApks.size(), Color.WHITE);

                for (String f : result.findings) {
                    if (f.contains("[CRÍTICO")) {
                        appendColoredLog("  * " + f, Color.parseColor("#EF4444"));
                    } else if (f.contains("[DESATIVADO]")) {
                        appendColoredLog("  * " + f, Color.parseColor("#34D399"));
                    } else if (f.contains("[INFO]") || f.contains("[AVISO INFORMATIVO]")) {
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

                AuditLogger.log("INFO", "STATUS", "SCAN_ESTATICO_CONCLUIDO");

                boolean autoStart = getIntent().getBooleanExtra("auto_start", false);
                if (autoStart && !isVpnRunning) {
                    mainHandler.postDelayed(this::toggleVpnMonitor, 1000);
                }
            });
        });
    }

    private void triggerOnScreenRemediation() {
        appendColoredLog("\n=================================================", Color.parseColor("#F59E0B"));
        appendColoredLog("      A INICIAR REMEDIAÇÃO NATIVA NA TV          ", Color.parseColor("#F59E0B"));
        appendColoredLog("=================================================", Color.parseColor("#F59E0B"));

        mPendingUninstalls.clear();
        mPendingSysPackages.clear();
        mEligibleQuarantinePkgs.clear();

        if (lastResult != null) {
            mPendingUninstalls.addAll(lastResult.userThreatPackages);
            mPendingSysPackages.addAll(lastResult.systemThreatPackages);
        }

        // Inicia fluxo sequencial de desinstalação para evitar colisões de UI
        processNextUninstall();
    }

    private void processNextUninstall() {
        if (!mPendingUninstalls.isEmpty()) {
            String pkg = mPendingUninstalls.remove(0);
            appendColoredLog("\n[Passo 1/3] A solicitar desinstalação: " + pkg, Color.parseColor("#EF4444"));
            Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
            uninstallIntent.setData(Uri.parse("package:" + pkg));
            uninstallIntent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
            try {
                startActivityForResult(uninstallIntent, REQUEST_UNINSTALL_PACKAGE);
            } catch (Exception e) {
                appendColoredLog("   [!] Erro ao invocar desinstalação: " + pkg, Color.parseColor("#EF4444"));
                processNextUninstall(); // Prossegue com o próximo
            }
        } else {
            // Concluído o passo 1 (apps de utilizador), passa ao passo 2 e 3
            finishRemediationSteps();
        }
    }

    private void finishRemediationSteps() {
        // 2. Isolamento de Implantes de Sistema (/system, /vendor)
        if (!mPendingSysPackages.isEmpty()) {
            appendColoredLog("\n[Passo 2/3] Implantes de sistema detetados (/system ou /vendor):", Color.parseColor("#EF4444"));
            appendColoredLog("   Nota: Sem ADB/PC, o Android TV bloqueia a desinstalação/desativação direta de apps de fábrica.", Color.parseColor("#F59E0B"));

            PackageManager pm = getPackageManager();
            mEligibleQuarantinePkgs.clear();
            List<String> uid1000Pkgs = new ArrayList<>();

            for (String pkg : mPendingSysPackages) {
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                    if (ai.uid == 1000) {
                        uid1000Pkgs.add(pkg);
                    } else {
                        mEligibleQuarantinePkgs.add(pkg);
                    }
                } catch (Exception ignored) {}
            }

            if (!uid1000Pkgs.isEmpty()) {
                for (String sPkg : uid1000Pkgs) {
                    appendColoredLog("   [!] O pacote '" + sPkg + "' partilha o UID 1000 (android.uid.system).", Color.parseColor("#F59E0B"));
                    appendColoredLog("       -> A quarentena VPN não é aplicável a UID 1000 (bloquearia toda a rede do Android).", Color.parseColor("#F59E0B"));
                    appendColoredLog("       -> Para desativá-lo em segurança, execute num PC via ADB:", Color.parseColor("#38BDF8"));
                    appendColoredLog("          adb shell pm disable-user --user 0 " + sPkg, Color.parseColor("#38BDF8"));
                }
            }

            if (!mEligibleQuarantinePkgs.isEmpty()) {
                appendColoredLog("   [*] A ativar Quarentena de Rede (VpnService Sinkhole) para " + mEligibleQuarantinePkgs.size() + " pacote(s) elegível(is)...", Color.parseColor("#22C55E"));
                Intent vpnPrep = VpnService.prepare(this);
                if (vpnPrep == null) {
                    Intent qIntent = new Intent(this, PacketMonitorVpnService.class);
                    qIntent.setAction(PacketMonitorVpnService.ACTION_QUARANTINE);
                    qIntent.putStringArrayListExtra(PacketMonitorVpnService.EXTRA_QUARANTINE_PKGS, new ArrayList<>(mEligibleQuarantinePkgs));
                    startService(qIntent);
                    isVpnRunning = true;
                    btnVpnMonitor.setText(getString(R.string.btn_stop_vpn));
                    btnVpnMonitor.setBackgroundResource(R.drawable.btn_red_focused);
                    appendColoredLog("   [✓] Quarentena Sinkhole ATIVA para: " + mEligibleQuarantinePkgs, Color.parseColor("#22C55E"));
                } else {
                    startActivityForResult(vpnPrep, VPN_REQUEST_CODE);
                }
            } else {
                appendColoredLog("   [i] Nenhum pacote elegível para isolamento via VPN (0 pacotes associados). A rede geral da box mantém-se intacta.", Color.WHITE);
            }

            appendColoredLog("   [*] A abrir ecrã de informações da app (Nota: o Android TV bloqueia o botão 'Desativar' em apps de sistema; use 'Forçar Paragem' ou ADB):", Color.parseColor("#38BDF8"));
            for (String pkg : mPendingSysPackages) {
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

        if (!mPendingSysPackages.isEmpty()) {
            appendColoredLog("\n[!] NOTA TÉCNICA: O Android TV bloqueia nativamente o botão 'Desativar' para apps assinadas pela plataforma ('canDisable=false').", Color.parseColor("#F59E0B"));
            appendColoredLog("    Para congelamento definitivo de implantes da ROM, utilize o script PC/ADB: python tools/audit_security.py <IP> --remediate", Color.parseColor("#38BDF8"));
        } else {
            appendColoredLog("\n[✓] Ações de remediação de pacotes de utilizador concluídas!", Color.parseColor("#22C55E"));
        }
        appendColoredLog(">>> Prima 'ANALISAR BOX' para validar o estado atual!\n", Color.parseColor("#38BDF8"));
        btnScan.requestFocus();
    }

    private void toggleVpnMonitor() {
        if (!isVpnRunning) {
            mEligibleQuarantinePkgs.clear();
            appendColoredLog("\n[!] AVISO DE REDE: Durante a monitorização VPN Sentinel, apenas o DNS é reencaminhado; o restante tráfego TCP/UDP é intercetado e retido (a box fica temporariamente sem navegação aberta enquanto o teste corre).", Color.parseColor("#F59E0B"));
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
            appendColoredLog("\n[i] Monitor de rede VPN parado. Ligação normal à Internet restabelecida.", Color.WHITE);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_UNINSTALL_PACKAGE) {
            processNextUninstall();
        } else if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, PacketMonitorVpnService.class);
            if (!mEligibleQuarantinePkgs.isEmpty()) {
                intent.setAction(PacketMonitorVpnService.ACTION_QUARANTINE);
                intent.putStringArrayListExtra(PacketMonitorVpnService.EXTRA_QUARANTINE_PKGS, new ArrayList<>(mEligibleQuarantinePkgs));
            }
            startService(intent);
            isVpnRunning = true;
            btnVpnMonitor.setText(getString(R.string.btn_stop_vpn));
            btnVpnMonitor.setBackgroundResource(R.drawable.btn_red_focused);
            btnVpnMonitor.requestFocus();
            appendColoredLog("\n[✓] Modo VPN Ativo!", Color.parseColor("#22C55E"));
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}

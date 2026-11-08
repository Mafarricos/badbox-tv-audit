package com.scanner.tv;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PacketMonitorVpnService extends VpnService implements Runnable {

    private static final String TAG = "VpnPacketMonitor";
    public static final String ACTION_STOP = "STOP";
    public static final String ACTION_START_SENTINEL = "START_SENTINEL";
    public static final String ACTION_QUARANTINE = "QUARANTINE";
    public static final String EXTRA_QUARANTINE_PKGS = "quarantine_pkgs";

    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    private boolean isRunning = false;
    private boolean isQuarantineMode = false;
    private final Set<String> mQuarantinePackages = new HashSet<>();

    // 1. Portas CRÍTICAS de C2, Proxies e PCDN conhecidos (XCPE, Videostrong, Airship, Linkfog, TitanNet) -> VERMELHO
    private static final Set<Integer> CRITICAL_MALWARE_PORTS = new HashSet<>(Arrays.asList(
            3885, 3886, 3887,       // Portas MQTT C2 do XCPE / szbboys
            1080, 8080, 9050, 4145, // Proxies SOCKS5 comuns em bots residenciais
            8888, 7777, 9999, 6667, // Botnets / IRC / Troianos
            22345,                  // Airship PCDN Overseer controller (121.4.8.146 / painet.work)
            16000,                  // APSolo Proxy relay (bmw.bestipip.com)
            12000,                  // Jaguar cleartext controller
            9992, 9994,             // Linkfog agent deployment channels (bkdomain.cn)
            2375,                   // VS/SOFT backup router (router.anyevonline.com)
            2095, 2082,             // UOTA updater endpoints (uota.club / uota.xyz)
            2222, 7000              // Portas SSH Reverso / FRP do XCPE (Plume Whitepaper)
    ));

    private static final Set<String> CRITICAL_C2_IPS = new HashSet<>(Arrays.asList(
            "219.134.163.210",
            "121.4.8.146",
            "38.145.197.135",
            "38.145.197.30",
            "23.94.49.57"
    ));

    // 2. Portas Legítimas Habituais de uma Android TV em Repouso -> IGNORADAS
    private static final Set<Integer> STANDARD_PORTS = new HashSet<>(Arrays.asList(
            80, 443,                 // Web / HTTPS padrão
            53,                      // DNS padrão
            853,                     // DNS over TLS (DoT - Google Private DNS / Cloudflare)
            123,                     // NTP (Acerto de relógio do sistema)
            5228, 5229, 5230,        // Google Play Services / MTalk Push notifications
            8008, 8009,              // Google Cast / Chromecast local
            5353,                    // mDNS local
            1900                     // SSDP / UPnP local
    ));

    public interface PacketListener {
        void onPacketEvent(String level, String logMessage);
    }

    private static PacketListener sListener;

    public static void setPacketListener(PacketListener listener) {
        sListener = listener;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            if (ACTION_STOP.equals(intent.getAction())) {
                stopVpn();
                return START_NOT_STICKY;
            }
            if (ACTION_QUARANTINE.equals(intent.getAction())) {
                ArrayList<String> pkgs = intent.getStringArrayListExtra(EXTRA_QUARANTINE_PKGS);
                if (pkgs != null && !pkgs.isEmpty()) {
                    mQuarantinePackages.clear();
                    mQuarantinePackages.addAll(pkgs);
                    isQuarantineMode = true;
                }
            }
        }

        if (mThread == null || !mThread.isAlive()) {
            AuditLogger.log("INFO", "VPN", isQuarantineMode ? "Interface de Quarentena Sinkhole iniciada." : "Interface de monitorização VPN iniciada.");
            mThread = new Thread(this, "VpnMonitorThread");
            isRunning = true;
            mThread.start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private void stopVpn() {
        isRunning = false;
        if (mThread != null) {
            mThread.interrupt();
            mThread = null;
        }
        if (mInterface != null) {
            try {
                mInterface.close();
            } catch (IOException ignored) {}
            mInterface = null;
        }
        AuditLogger.log("INFO", "VPN", "Interface de monitorização VPN encerrada.");
    }

    @Override
    public void run() {
        try {
            Builder builder = new Builder();
            if (isQuarantineMode && !mQuarantinePackages.isEmpty()) {
                builder.setSession("XCPE Quarantine Sinkhole");
                builder.addAddress("10.99.99.2", 32);
                builder.addRoute("0.0.0.0", 0);
                builder.addDnsServer("127.0.0.1");
                for (String pkg : mQuarantinePackages) {
                    try {
                        builder.addAllowedApplication(pkg);
                        AuditLogger.log("INFO", "QUARANTINE", "Pacote isolado via Sinkhole: " + pkg);
                    } catch (Exception e) {
                        Log.w(TAG, "Impossível associar pacote à quarentena: " + pkg, e);
                    }
                }
            } else {
                builder.setSession("XCPE Sentinel VPN");
                builder.addAddress("10.10.10.2", 32);
                builder.addRoute("0.0.0.0", 0);
                builder.addDnsServer("8.8.8.8");
            }

            mInterface = builder.establish();
            if (mInterface == null) {
                Log.e(TAG, "Falha ao estabelecer interface VPN.");
                return;
            }

            FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());
            byte[] packet = new byte[32767];

            while (isRunning && !Thread.currentThread().isInterrupted()) {
                int length = in.read(packet);
                if (length > 0) {
                    inspectPacket(packet, length);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro no loop da VPN: " + e.getMessage());
        } finally {
            stopVpn();
        }
    }

    private void inspectPacket(byte[] data, int length) {
        if (length < 20) return;

        int version = (data[0] >> 4) & 0x0F;
        if (version != 4) return; // Foco em IPv4

        int headerLength = (data[0] & 0x0F) * 4;
        int protocol = data[9] & 0xFF;

        String srcIp = (data[12] & 0xFF) + "." + (data[13] & 0xFF) + "." + (data[14] & 0xFF) + "." + (data[15] & 0xFF);
        String destIp = (data[16] & 0xFF) + "." + (data[17] & 0xFF) + "." + (data[18] & 0xFF) + "." + (data[19] & 0xFF);

        int srcPort = 0;
        int destPort = 0;
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "PROTO-" + protocol;

        if (protocol == 6 || protocol == 17) {
            if (length >= headerLength + 4) {
                srcPort = ((data[headerLength] & 0xFF) << 8) | (data[headerLength + 1] & 0xFF);
                destPort = ((data[headerLength + 2] & 0xFF) << 8) | (data[headerLength + 3] & 0xFF);
            }
        }

        // Se estiver em modo Quarentena Sinkhole, todo o tráfego dos pacotes isolados é bloqueado
        if (isQuarantineMode) {
            String msg = "QUARENTENA [SINKHOLE BLOQUEADO]: Tráfego de implante de sistema bloqueado: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("CRITICO", msg);
            return;
        }

        // Tenta atribuição de UID/Pacote no Android 10+ (API 29+)
        String attribution = "";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && (protocol == 6 || protocol == 17) && destPort > 0) {
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    InetSocketAddress local = new InetSocketAddress(srcIp, srcPort);
                    InetSocketAddress remote = new InetSocketAddress(destIp, destPort);
                    int uid = cm.getConnectionOwnerUid(protocol, local, remote);
                    if (uid > 0) {
                        String[] pkgs = getPackageManager().getPackagesForUid(uid);
                        if (pkgs != null && pkgs.length > 0) {
                            attribution = " [App: " + pkgs[0] + "]";
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        // === CASO A: AMEAÇAS CRÍTICAS DE BOTNET / C2 (VERMELHO) ===

        // 1. Conexão direta a IP de C2 conhecido
        if (CRITICAL_C2_IPS.contains(destIp)) {
            String msg = "PERIGO [CRÍTICO]: Ligação direta a IP C2 da Botnet: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
            notifyEvent("CRITICO", msg);
            return;
        }

        // 2. Conexão a portas de C2 / Proxies conhecidos
        if (CRITICAL_MALWARE_PORTS.contains(destPort)) {
            String msg = "PERIGO [CRÍTICO]: Conexão a Porta de Botnet/Proxy: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
            notifyEvent("CRITICO", msg);
            return;
        }

        // 3. Inspeção de DNS (Porta 53 UDP) para domínios de C2 e Proxy SDKs
        if (destPort == 53 && protocol == 17 && length > headerLength + 12) {
            String payload = new String(data, headerLength + 8, length - (headerLength + 8), StandardCharsets.ISO_8859_1).toLowerCase();
            
            if (payload.contains("szbboys") || payload.contains("anyevonline") || payload.contains("nexus")
                    || payload.contains("titannet") || payload.contains("painet") || payload.contains("paigod")
                    || payload.contains("getgrass") || payload.contains("traffmonetizer") || payload.contains("linkfog")
                    || payload.contains("yokatv") || payload.contains("uota") || payload.contains("amhib")
                    || payload.contains("creapslpinut") || payload.contains("gapslpinch") || payload.contains("bestipip")) {
                String msg = "PERIGO [CRÍTICO DNS]: Pedido de resolução para domínio malicioso de C2/Botnet!" + attribution;
                notifyEvent("CRITICO", msg);
                return;
            }
        }

        // === FILTRAGEM DE TRÁFEGO LEGÍTIMO (IGNORADO SILENCIOSAMENTE) ===
        boolean isLocalOrInternal = destIp.startsWith("192.168.") || destIp.startsWith("10.") || destIp.startsWith("172.16.")
                || destIp.startsWith("172.17.") || destIp.startsWith("172.18.") || destIp.startsWith("172.19.")
                || destIp.startsWith("172.2") || destIp.startsWith("172.3")
                || destIp.startsWith("224.") || destIp.startsWith("239.") || destIp.equals("255.255.255.255")
                || destIp.startsWith("127.") || destIp.startsWith("169.254.");

        if (isLocalOrInternal) {
            return;
        }

        boolean isGoogleInfra = destIp.equals("8.8.8.8") || destIp.equals("8.8.4.4")
                || destIp.startsWith("142.250.") || destIp.startsWith("172.217.")
                || destIp.startsWith("216.58.") || destIp.startsWith("74.125.");

        if (isGoogleInfra) {
            return;
        }

        if (STANDARD_PORTS.contains(destPort)) {
            return;
        }

        // === CASO B: ANOMALIA SUSPEITA REAL ===
        String msg = "ALERTA [ANOMALIA]: Tráfego externo não habitual: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
        notifyEvent("ANOMALIA", msg);
    }

    private void notifyEvent(String level, String msg) {
        Log.w(TAG, "[" + level + "] " + msg);
        AuditLogger.log(level, "SENTINELA_VPN", msg);
        if (sListener != null) {
            sListener.onPacketEvent(level, msg);
        }
    }
}

package com.scanner.tv;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PacketMonitorVpnService extends VpnService implements Runnable {

    private static final String TAG = "VpnPacketMonitor";
    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    private boolean isRunning = false;

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
            2095, 2082              // UOTA updater endpoints (uota.club / uota.xyz)
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
            53,                      // DNS
            123,                     // NTP (Acerto de relógio do sistema)
            5228, 5229, 5230,        // Google Play Services / MTalk Push notifications
            8008, 8009,              // Google Cast / Chromecast local
            5353                     // mDNS local
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
        if ("STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        if (mThread == null || !mThread.isAlive()) {
            AuditLogger.log("INFO", "VPN", "Interface de monitorização VPN iniciada.");
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
            builder.setSession("XCPE Sentinel VPN");
            builder.addAddress("10.10.10.2", 32);
            builder.addRoute("0.0.0.0", 0);
            builder.addDnsServer("8.8.8.8");

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

        String destIp = (data[16] & 0xFF) + "." + (data[17] & 0xFF) + "." + (data[18] & 0xFF) + "." + (data[19] & 0xFF);

        int destPort = 0;
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "PROTO-" + protocol;

        if (protocol == 6 || protocol == 17) {
            if (length >= headerLength + 4) {
                destPort = ((data[headerLength + 2] & 0xFF) << 8) | (data[headerLength + 3] & 0xFF);
            }
        }

        // === CASO A: AMEAÇAS CRÍTICAS DE BOTNET / C2 (VERMELHO) ===

        // 1. Conexão direta a IP de C2 conhecido
        if (CRITICAL_C2_IPS.contains(destIp)) {
            String msg = "PERIGO [CRÍTICO]: Tentativa de ligação direta a IP C2 da Botnet: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("CRITICO", msg);
            return;
        }

        // 2. Conexão a portas de C2 / Proxies conhecidos
        if (CRITICAL_MALWARE_PORTS.contains(destPort)) {
            String msg = "PERIGO [CRÍTICO]: Tentativa de conexão a Porta de Botnet/Proxy: " + destIp + ":" + destPort + " (" + protoStr + ")";
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
                String msg = "PERIGO [CRÍTICO DNS]: Pedido de resolução para domínio malicioso de C2/Botnet!";
                notifyEvent("CRITICO", msg);
                return;
            }
        }

        // === CASO B: ANOMALIAS DE REDE / PORTAS NÃO HABITUAIS (AMARELO) ===
        if (!STANDARD_PORTS.contains(destPort)) {
            String msg = "ALERTA [ANOMALIA]: Tráfego em porta não habitual em repouso: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("ANOMALIA", msg);
        }
    }

    private void notifyEvent(String level, String msg) {
        Log.w(TAG, "[" + level + "] " + msg);
        AuditLogger.log(level, "SENTINELA_VPN", msg);
        if (sListener != null) {
            sListener.onPacketEvent(level, msg);
        }
    }
}

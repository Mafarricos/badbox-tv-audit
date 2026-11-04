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

    // 1. Portas CRÍTICAS de Malware Conhecido (XCPE, BadBox, SOCKS5 Proxies, Botnets) -> VERMELHO
    private static final Set<Integer> CRITICAL_MALWARE_PORTS = new HashSet<>(Arrays.asList(
            3885, 3886, 3887,       // Portas MQTT C2 do XCPE / szbboys
            1080, 8080, 9050, 4145, // Proxies SOCKS5 comuns em bots residenciais
            8888, 7777, 9999, 6667  // Botnets / IRC / Troianos
    ));

    private static final String CRITICAL_C2_IP = "219.134.163.210";

    // 2. Portas Legítimas Habituaiss de uma Android TV em Repouso -> IGNORADAS
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
        try {
            if (mInterface != null) {
                mInterface.close();
                mInterface = null;
            }
        } catch (IOException ignored) {}
        AuditLogger.log("INFO", "VPN", "Interface de monitorização VPN terminada.");
    }

    @Override
    public void run() {
        try {
            Builder builder = new Builder();
            builder.setSession("Sentinela Global TV");
            builder.addAddress("10.0.0.2", 24);
            builder.addRoute("0.0.0.0", 0);

            mInterface = builder.establish();
            if (mInterface == null) {
                Log.e(TAG, "Falha ao estabelecer TUN.");
                return;
            }

            FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());
            byte[] packet = new byte[32767];

            while (isRunning) {
                int length = in.read(packet);
                if (length > 0) {
                    inspectPacket(packet, length);
                    out.write(packet, 0, length);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro na VPN: " + e.getMessage());
        } finally {
            stopVpn();
        }
    }

    private void inspectPacket(byte[] data, int length) {
        if (length < 20) return;
        int version = (data[0] >> 4) & 0x0F;
        if (version != 4) return;

        int protocol = data[9] & 0xFF; // 6 = TCP, 17 = UDP
        int destIpOffset = 16;
        String destIp = String.format("%d.%d.%d.%d",
                data[destIpOffset] & 0xFF,
                data[destIpOffset + 1] & 0xFF,
                data[destIpOffset + 2] & 0xFF,
                data[destIpOffset + 3] & 0xFF);

        int destPort = 0;
        int headerLength = (data[0] & 0x0F) * 4;

        if (protocol == 6 || protocol == 17) {
            if (length >= headerLength + 4) {
                destPort = ((data[headerLength + 2] & 0xFF) << 8) | (data[headerLength + 3] & 0xFF);
            }
        }

        // Ignorar tráfego local da LAN (192.168.x.x, 10.x.x.x, 127.0.0.1, 224.0.0.x multicast)
        if (destIp.startsWith("192.168.") || destIp.startsWith("10.") || destIp.startsWith("127.") || destIp.startsWith("224.") || destIp.startsWith("239.")) {
            return;
        }

        String protoStr = (protocol == 6) ? "TCP" : "UDP";

        // === CASO A: AMEAÇAS CRÍTICAS CONHECIDAS (VERMELHO) ===
        if (CRITICAL_C2_IP.equals(destIp)) {
            String msg = "PERIGO [CRÍTICO]: Conexão direta ao IP C2 BadBox: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("CRITICO", msg);
            return;
        }

        if (CRITICAL_MALWARE_PORTS.contains(destPort)) {
            String msg = "PERIGO [CRÍTICO]: Tentativa de conexão a Porta de Botnet/Proxy: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("CRITICO", msg);
            return;
        }

        // Inspeção de DNS (Porta 53 UDP) para domínios C2 conhecidos
        if (destPort == 53 && protocol == 17 && length > headerLength + 12) {
            String payload = new String(data, headerLength + 8, length - (headerLength + 8), StandardCharsets.ISO_8859_1);
            if (payload.contains("szbboys") || payload.contains("anyevonline") || payload.contains("nexus")) {
                String msg = "PERIGO [CRÍTICO DNS]: Pedido de resolução para domínio C2 malicioso: " + destIp;
                notifyEvent("CRITICO", msg);
                return;
            }
        }

        // === CASO B: ANOMALIAS DE REDE / PORTAS NÃO HABITUAIS (AMARELO) ===
        // Se não for uma das portas padrão e legítimas de TV em repouso
        if (!STANDARD_PORTS.contains(destPort)) {
            String msg = "ALERTA [ANOMALIA]: Tráfego em porta não habitual: " + destIp + ":" + destPort + " (" + protoStr + ")";
            notifyEvent("ANOMALIA", msg);
        }
    }

    private void notifyEvent(String level, String msg) {
        Log.w(TAG, "[" + level + "] " + msg);
        // Grava no log permanente da box que depois é extraído pelo script
        AuditLogger.log(level, "SENTINELA_VPN", msg);
        if (sListener != null) {
            sListener.onPacketEvent(level, msg);
        }
    }
}

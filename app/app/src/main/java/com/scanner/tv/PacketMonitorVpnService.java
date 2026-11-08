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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
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

    // 1. Portas CRÍTICAS de C2 e Proxies conhecidos (XCPE, Videostrong, Airship, Linkfog, TitanNet) -> VERMELHO
    // NOTA: 8080, 8888 e 9999 foram removidas para evitar falsos positivos com servidores web / IPTV legítimos.
    private static final Set<Integer> CRITICAL_MALWARE_PORTS = new HashSet<>(Arrays.asList(
            3885, 3886, 3887,       // Portas MQTT C2 do XCPE / szbboys
            1080, 9050, 4145,       // Proxies SOCKS5 comuns em bots residenciais
            7777, 6667,             // Botnets / IRC
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

    // Domínios de C2 e Proxy SDKs verificados com parser de QNAME
    private static final Set<String> KNOWN_C2_DOMAINS = new HashSet<>(Arrays.asList(
            "szbboys.com", "anyevonline.com", "bestipip.com", "uota.club", "uota.xyz",
            "titannet.io", "getgrass.io", "traffmonetizer.com", "painet.work", "paigod.com",
            "linkfog.com", "yokatvonline.com", "yokatv.com", "amhib.com", "creapslpinut.com",
            "gapslpinch.com", "dgjm.online", "zorapslwsnic.com", "cloudbrokerapi.xyz",
            "floporin.com", "ipmoyu.com", "catmore88.com", "file.long.tv"
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
            1900,                    // SSDP / UPnP local
            7000,                    // AirPlay / RTSP local
            2222                     // SSH de desenvolvimento / local
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
                    inspectAndProcessPacket(packet, length, out);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Erro no loop da VPN: " + e.getMessage());
        } finally {
            stopVpn();
        }
    }

    private void inspectAndProcessPacket(byte[] data, int length, FileOutputStream out) {
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

        // Se estiver em modo Quarentena Sinkhole: bloqueia integralmente qualquer pacote
        if (isQuarantineMode) {
            String msg = "QUARENTENA [SINKHOLE BLOQUEADO]: Tráfego de implante de sistema travado: " + destIp + ":" + destPort + " (" + protoStr + ")";
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

        // === CASO A: CONEXÃO A IP DE C2 CONHECIDO ===
        if (CRITICAL_C2_IPS.contains(destIp)) {
            String msg = "PERIGO [CRÍTICO]: Ligação direta a IP C2 da Botnet: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
            notifyEvent("CRITICO", msg);
            return;
        }

        // === CASO B: CONEXÃO A PORTAS DE C2 / PROXIES CONHECIDOS ===
        if (CRITICAL_MALWARE_PORTS.contains(destPort)) {
            String msg = "PERIGO [CRÍTICO]: Conexão a Porta de Botnet/Proxy: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
            notifyEvent("CRITICO", msg);
            return;
        }

        // === CASO C: INSPEÇÃO DE DNS (Porta 53 UDP) COM PARSER DE QNAME E REENCAMINHAMENTO ===
        if (destPort == 53 && protocol == 17 && length > headerLength + 12) {
            String qname = parseDnsQName(data, headerLength + 8, length - (headerLength + 8));
            if (isMaliciousDomain(qname)) {
                String msg = "PERIGO [CRÍTICO DNS]: Resolução para domínio malicioso C2: " + qname + attribution;
                notifyEvent("CRITICO", msg);
            }

            // REENCAMINHAMENTO DNS NO MODO SENTINELA:
            // Permite que o pedido DNS receba resposta real de modo a que a app maliciosa tente a ligação TCP subsequente
            forwardDnsQuery(data, headerLength, length, srcIp, srcPort, destIp, destPort, out);
            return;
        }

        // === FILTRAGEM DE TRÁFEGO LEGÍTIMO ===
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

        // === CASO D: ANOMALIA SUSPEITA REAL ===
        String msg = "ALERTA [ANOMALIA]: Tráfego externo não habitual: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
        notifyEvent("ANOMALIA", msg);
    }

    private String parseDnsQName(byte[] data, int dnsOffset, int dnsLen) {
        if (dnsLen < 12) return "";
        int qOffset = dnsOffset + 12; // Salta cabeçalho de 12 bytes do DNS
        StringBuilder sb = new StringBuilder();
        while (qOffset < dnsOffset + dnsLen) {
            int labelLen = data[qOffset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63 || qOffset + 1 + labelLen > dnsOffset + dnsLen) return "";
            if (sb.length() > 0) sb.append(".");
            sb.append(new String(data, qOffset + 1, labelLen, StandardCharsets.UTF_8));
            qOffset += 1 + labelLen;
        }
        return sb.toString().toLowerCase();
    }

    private boolean isMaliciousDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        for (String c2 : KNOWN_C2_DOMAINS) {
            if (domain.equals(c2) || domain.endsWith("." + c2)) {
                return true;
            }
        }
        if (domain.contains("x.cpe") || domain.contains("szbboys") || domain.contains("anyevonline") || domain.contains("bestipip")) {
            return true;
        }
        return false;
    }

    private void forwardDnsQuery(byte[] data, int headerLength, int length, String srcIp, int srcPort, String destIp, int destPort, FileOutputStream out) {
        int dnsOffset = headerLength + 8;
        int dnsLen = length - dnsOffset;
        if (dnsLen <= 0) return;

        new Thread(() -> {
            DatagramSocket socket = null;
            try {
                socket = new DatagramSocket();
                protect(socket); // Protege o socket para não entrar em loop na VPN
                socket.setSoTimeout(3000);
                InetAddress dnsServer = InetAddress.getByName(destIp.equals("127.0.0.1") || destIp.startsWith("10.10.") ? "8.8.8.8" : destIp);
                DatagramPacket queryPacket = new DatagramPacket(data, dnsOffset, dnsLen, dnsServer, 53);
                socket.send(queryPacket);

                byte[] respBuf = new byte[1500];
                DatagramPacket respPacket = new DatagramPacket(respBuf, respBuf.length);
                socket.receive(respPacket);
                int respDnsLen = respPacket.getLength();

                int totalLen = 20 + 8 + respDnsLen;
                byte[] respData = new byte[totalLen];

                // Cabeçalho IPv4 (20 bytes)
                respData[0] = 0x45;
                respData[2] = (byte) ((totalLen >> 8) & 0xFF);
                respData[3] = (byte) (totalLen & 0xFF);
                respData[6] = 0x40; // Don't fragment
                respData[8] = 64;   // TTL
                respData[9] = 17;   // UDP
                // IP Origem (Servidor DNS)
                respData[12] = data[16]; respData[13] = data[17]; respData[14] = data[18]; respData[15] = data[19];
                // IP Destino (Cliente)
                respData[16] = data[12]; respData[17] = data[13]; respData[18] = data[14]; respData[19] = data[15];

                int checksum = computeIpChecksum(respData, 20);
                respData[10] = (byte) ((checksum >> 8) & 0xFF);
                respData[11] = (byte) (checksum & 0xFF);

                // Cabeçalho UDP (8 bytes)
                int udpLen = 8 + respDnsLen;
                respData[20] = (byte) ((destPort >> 8) & 0xFF);
                respData[21] = (byte) (destPort & 0xFF);
                respData[22] = (byte) ((srcPort >> 8) & 0xFF);
                respData[23] = (byte) (srcPort & 0xFF);
                respData[24] = (byte) ((udpLen >> 8) & 0xFF);
                respData[25] = (byte) (udpLen & 0xFF);

                System.arraycopy(respBuf, 0, respData, 28, respDnsLen);

                synchronized (out) {
                    out.write(respData, 0, totalLen);
                    out.flush();
                }
            } catch (Exception ignored) {
            } finally {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            }
        }).start();
    }

    private static int computeIpChecksum(byte[] buf, int length) {
        int sum = 0;
        for (int i = 0; i < length; i += 2) {
            if (i == 10) continue;
            int word = ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
            sum += word;
            if ((sum & 0xFFFF0000) != 0) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        return ~sum & 0xFFFF;
    }

    private void notifyEvent(String level, String msg) {
        Log.w(TAG, "[" + level + "] " + msg);
        AuditLogger.log(level, "SENTINELA_VPN", msg);
        if (sListener != null) {
            sListener.onPacketEvent(level, msg);
        }
    }
}

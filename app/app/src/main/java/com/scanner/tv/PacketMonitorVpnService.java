package com.scanner.tv;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
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

    private static final String PREFS_NAME = "quarantine_prefs";
    private static final String KEY_ACTIVE = "active";
    private static final String KEY_PACKAGES = "packages";

    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    private boolean isRunning = false;
    private boolean isQuarantineMode = false;
    private final Set<String> mQuarantinePackages = new HashSet<>();
    private final FlowTracker mFlowTracker = new FlowTracker();

    // 1. Portas CRÍTICAS de C2 e Proxies conhecidos (XCPE, Videostrong, Airship, Linkfog, TitanNet)
    private static final Set<Integer> CRITICAL_MALWARE_PORTS = new HashSet<>(Arrays.asList(
            3885, 3886, 3887,       // Portas MQTT C2 do XCPE / szbboys
            1080, 9050, 4145,       // Proxies SOCKS5 comuns em bots residenciais
            7777, 6667,             // Botnets / IRC
            22345,                  // Airship PCDN Overseer controller (121.4.8.146 / painet.work)
            16000,                  // APSolo Proxy relay (bmw.bestipip.com)
            12000,                  // Jaguar cleartext controller
            9992, 9994,             // Linkfog agent deployment channels (bkdomain.cn)
            2375                    // VS/SOFT backup router (router.anyevonline.com)
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
            123,                     // NTP
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
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        if (intent != null) {
            String action = intent.getAction();
            if (ACTION_STOP.equals(action)) {
                prefs.edit().putBoolean(KEY_ACTIVE, false).apply();
                stopVpn();
                return START_NOT_STICKY;
            }
            if (ACTION_QUARANTINE.equals(action)) {
                ArrayList<String> pkgs = intent.getStringArrayListExtra(EXTRA_QUARANTINE_PKGS);
                if (pkgs != null && !pkgs.isEmpty()) {
                    mQuarantinePackages.clear();
                    mQuarantinePackages.addAll(pkgs);
                    isQuarantineMode = true;
                    prefs.edit()
                            .putBoolean(KEY_ACTIVE, true)
                            .putStringSet(KEY_PACKAGES, new HashSet<>(pkgs))
                            .apply();
                }
            }
        } else {
            // Reinício automático pelo sistema ou arranque sem Intent
            boolean savedActive = prefs.getBoolean(KEY_ACTIVE, false);
            if (savedActive) {
                Set<String> savedPkgs = prefs.getStringSet(KEY_PACKAGES, null);
                if (savedPkgs != null && !savedPkgs.isEmpty()) {
                    mQuarantinePackages.clear();
                    mQuarantinePackages.addAll(savedPkgs);
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
                android.content.pm.PackageManager pm = getPackageManager();
                for (String pkg : mQuarantinePackages) {
                    try {
                        android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                        if (ai.uid == 1000) {
                            AuditLogger.log("AVISO", "QUARANTINE", "Pacote " + pkg + " utiliza UID 1000 (sistema). Quarentena de rede requer 'pm disable-user --user 0' para não afetar o sistema.");
                            continue;
                        }
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
        IpPacketParser.ParsedPacket pkt = IpPacketParser.parse(data, length);
        if (pkt == null) return;

        String srcIp = pkt.srcIp;
        String destIp = pkt.dstIp;
        int srcPort = pkt.srcPort;
        int destPort = pkt.dstPort;
        String protoStr = pkt.protocol;
        int headerLength = (data[0] & 0x0F) * 4;
        int protocol = "TCP".equals(protoStr) ? 6 : "UDP".equals(protoStr) ? 17 : 0;

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
        if (destPort == 53 && "UDP".equals(protoStr) && length > headerLength + 12) {
            String qname = DnsPacketParser.parseQName(data, headerLength + 8);
            if (DnsPacketParser.isMatch(qname, KNOWN_C2_DOMAINS)) {
                String msg = "PERIGO [CRÍTICO DNS]: Resolução para domínio malicioso C2: " + qname + attribution;
                notifyEvent("CRITICO", msg);
            }

            // REENCAMINHAMENTO DNS NO MODO SENTINELA
            forwardDnsQuery(data, headerLength, length, srcIp, srcPort, destIp, destPort, out);
            return;
        }

        // === FILTRAGEM DE TRÁFEGO LEGÍTIMO COM IpClassifier ===
        if (IpClassifier.isInternalOrLocal(destIp)) {
            return;
        }

        if (IpClassifier.isGoogleInfrastructure(destIp)) {
            return;
        }

        if (STANDARD_PORTS.contains(destPort)) {
            return;
        }

        // Filtro de repetição via FlowTracker
        if (mFlowTracker.shouldAlert(srcIp, destIp, destPort, protoStr)) {
            String msg = "ALERTA [ANOMALIA]: Tráfego externo não habitual: " + destIp + ":" + destPort + " (" + protoStr + ")" + attribution;
            notifyEvent("ANOMALIA", msg);
        }
    }

    private void forwardDnsQuery(byte[] data, int headerLength, int length, String srcIp, int srcPort, String destIp, int destPort, FileOutputStream out) {
        int dnsOffset = headerLength + 8;
        int dnsLen = length - dnsOffset;
        if (dnsLen <= 0) return;

        // Evita race condition no buffer: cópia isolada antes de enviar para a thread
        byte[] queryData = Arrays.copyOfRange(data, dnsOffset, dnsOffset + dnsLen);

        new Thread(() -> {
            DatagramSocket socket = null;
            try {
                socket = new DatagramSocket();
                protect(socket);
                socket.setSoTimeout(3000);
                InetAddress dnsServer = InetAddress.getByName(destIp.equals("127.0.0.1") || destIp.startsWith("10.10.") ? "8.8.8.8" : destIp);
                DatagramPacket queryPacket = new DatagramPacket(queryData, queryData.length, dnsServer, 53);
                socket.send(queryPacket);

                byte[] respBuf = new byte[1500];
                DatagramPacket respPacket = new DatagramPacket(respBuf, respBuf.length);
                socket.receive(respPacket);
                int respDnsLen = respPacket.getLength();

                byte[] respData = DnsDispatcher.buildDnsResponsePacket(destIp, srcIp, destPort, srcPort, respBuf, respDnsLen);

                synchronized (out) {
                    out.write(respData, 0, respData.length);
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

    private void notifyEvent(String level, String msg) {
        Log.w(TAG, "[" + level + "] " + msg);
        AuditLogger.log(level, "SENTINELA_VPN", msg);
        if (sListener != null) {
            sListener.onPacketEvent(level, msg);
        }
    }
}

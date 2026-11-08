package com.scanner.tv;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class CoreScanner {

    // Assinaturas de C2, Backdoors, SDKs maliciosos e Infraestrutura Videostrong/BadBox/XCPE
    private static final byte[][] TARGET_PATTERNS = {
            "disablePackageVerify".getBytes(StandardCharsets.UTF_8),
            "package_verifier_user_consent".getBytes(StandardCharsets.UTF_8),
            "szbboys".getBytes(StandardCharsets.UTF_8),
            "mqtt.szbboys.com".getBytes(StandardCharsets.UTF_8),
            "ott.szbboys.com".getBytes(StandardCharsets.UTF_8),
            "anyevonline".getBytes(StandardCharsets.UTF_8),
            "extstb.anyevonline.com".getBytes(StandardCharsets.UTF_8),
            "mcstb.anyevonline.com".getBytes(StandardCharsets.UTF_8),
            "router.anyevonline.com".getBytes(StandardCharsets.UTF_8),
            "bestipip.com".getBytes(StandardCharsets.UTF_8),
            "bmw.bestipip.com".getBytes(StandardCharsets.UTF_8),
            "solo_ProxyLogger".getBytes(StandardCharsets.UTF_8),
            "Aviciiii/ott".getBytes(StandardCharsets.UTF_8),
            "ktpeng2026/ott_release".getBytes(StandardCharsets.UTF_8),
            "lw_android_agent".getBytes(StandardCharsets.UTF_8),
            "com.abc.nexus".getBytes(StandardCharsets.UTF_8),
            "219.134.163.210".getBytes(StandardCharsets.UTF_8),
            "videostrong".getBytes(StandardCharsets.UTF_8),
            "yokatvonline".getBytes(StandardCharsets.UTF_8),
            "titannet.io".getBytes(StandardCharsets.UTF_8),
            "getgrass.io".getBytes(StandardCharsets.UTF_8),
            "traffmonetizer.com".getBytes(StandardCharsets.UTF_8),
            "painet.work".getBytes(StandardCharsets.UTF_8),
            "dgjm.online".getBytes(StandardCharsets.UTF_8),
            "uota.club".getBytes(StandardCharsets.UTF_8),
            "uota.xyz".getBytes(StandardCharsets.UTF_8),
            "zorapslwsnic.com".getBytes(StandardCharsets.UTF_8),
            "cloudbrokerapi.xyz".getBytes(StandardCharsets.UTF_8),
            "floporin.com".getBytes(StandardCharsets.UTF_8),
            "ipmoyu.com".getBytes(StandardCharsets.UTF_8),
            "catmore88.com".getBytes(StandardCharsets.UTF_8),
            "file.long.tv".getBytes(StandardCharsets.UTF_8),
            "x.cpe.util.RunCmds".getBytes(StandardCharsets.UTF_8),
            "x.cpe.util.ExtraReadUtils".getBytes(StandardCharsets.UTF_8),
            "getAppsaltKey".getBytes(StandardCharsets.UTF_8),
            "getTraffmonetizerKey".getBytes(StandardCharsets.UTF_8),
            "nativeAdbRoot".getBytes(StandardCharsets.UTF_8),
            "x_ctrl_do_ctrl_msg".getBytes(StandardCharsets.UTF_8),
            "content://com.release.debug.provider".getBytes(StandardCharsets.UTF_8)
    };

    // Pacotes conhecidos de Trojans, Proxies Residenciais, Loaders e Ad Fraud (XCPE & BadBox 2.0 / Plume Whitepaper)
    private static final List<String> IOC_PACKAGES = Arrays.asList(
            "x.cpe", "com.oemservice", "com.abc.nexus", "sso.authHandler",
            "com.ota.service", "newtv.cboxtv", "com.vs.tvonline2",
            "com.release.debug.provider", "com.hs.app", "com.mz.sdk",
            "com.debby.devour", "io.popanet", "gaganode", "linkfog",
            "appsalt", "traffmonetizer", "cboxtv", "hiddenview", "moyu", "spirit",
            "android-grass", "com.grass", "appdnschange", "SmartPrivilege",
            "SmartEntertainment", "SmartThroughput", "EcoSaverDaemon", "titannet", "yokatv",
            "com.yk.debugtools", "com.droidlogic.vsota", "com.abcproxy.proxysdk", "com.appdns.change.rc",
            "com.dnschecker.rc", "com.ecosaver.daemon", "com.proxypeer.peerapp", "com.ycngmn.notubetv.service",
            "com.whale.screensaver", "com.yokatv.market", "com.yokatv.otaupdate"
    );

    // Portas de C2 / Proxyware conhecidas (incluindo portas MQTT, FRP e SSH reverso da Plume)
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
            3885, 3886, 3887, 8082, 8083, 16000, 18083, 4444, 5555, 6667, 8080, 8888, 9000, 9999, 5353,
            2222, 7000
    ));

    // Nomes de ficheiros de bibliotecas nativas e binários ELF maliciosos
    private static final Set<String> SUSPICIOUS_NATIVE_FILES = new HashSet<>(Arrays.asList(
            "libanl.so", "libexploit.so", "libnative_keys.so", "libjaguar.so",
            "libtraceroute.so", "lw_android_agent", "lw_android_agent_special_ndk_64",
            "p.jar", "q.jar"
    ));

    public interface ScanProgressListener {
        void onProgress(String message);
    }

    public static ScanResult scan(Context context, ScanProgressListener listener) {
        return executeScan(context, listener);
    }

    public static ScanResult executeScan(Context context, ScanProgressListener listener) {
        ScanResult result = new ScanResult();
        result.deviceDetails = Build.MANUFACTURER + " " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ", API " + Build.VERSION.SDK_INT + ")";

        // 1. Verificação do Google Play Protect
        if (listener != null) listener.onProgress("[1/6] A verificar estado do Google Play Protect...");
        try {
            int consent = Settings.Global.getInt(context.getContentResolver(), "package_verifier_user_consent", 1);
            if (consent == -1) {
                result.playProtectStatus = "DESATIVADO (Modificado por Malware)";
                result.addFinding("[CRÍTICO] Google Play Protect foi silenciosamente desativado (package_verifier_user_consent = -1)!", 8);
            } else {
                result.playProtectStatus = "ATIVO (Protegido)";
            }
        } catch (Exception e) {
            result.playProtectStatus = "DESCONHECIDO";
        }

        // 2. Sondagem do Content Provider C2 do XCPE (com.release.debug.provider)
        if (listener != null) listener.onProgress("[2/6] A sondar Content Provider C2 malicioso...");
        checkMaliciousContentProviders(context, result);

        // 3. Verificação de Propriedades de Sistema (getprop) e Kill-Switches
        if (listener != null) listener.onProgress("[3/6] A inspecionar propriedades de sistema e kill-switches...");
        checkSystemProperties(result);

        boolean hasTelephony = context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
        if (hasTelephony) {
            result.addFinding("[SUSPEITO] A box declara suporte GSM/Telefonia móvel (Típico de spoofing para ad-fraud).", 3);
        }

        // 4. Enumeração de Pacotes Instalados vs Lista de IoCs
        if (listener != null) listener.onProgress("[4/6] A procurar pacotes maliciosos conhecidos e backdoors...");
        PackageManager pm = context.getPackageManager();
        List<PackageInfo> installedPackages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);

        for (PackageInfo pkg : installedPackages) {
            String pkgName = pkg.packageName.toLowerCase();

            for (String ioc : IOC_PACKAGES) {
                if (pkgName.equals(ioc.toLowerCase()) || pkgName.contains(ioc.toLowerCase())) {
                    result.addFinding("[CRÍTICO] Pacote com assinatura de botnet/proxy encontrado: " + pkg.packageName, 8);
                }
            }

            // Heurística de privilégios de sistema
            if (!pkg.packageName.startsWith("com.android.") && !pkg.packageName.startsWith("com.google.") && !pkg.packageName.startsWith("android")) {
                if (pkg.sharedUserId != null && pkg.sharedUserId.equals("android.uid.system")) {
                    result.addFinding("[SUSPEITO] App OEM não-Google com privilégios de sistema (sharedUser=system): " + pkg.packageName, 2);
                }
            }
        }

        // 5. Inspeção Estática de APKs em /oem, /vendor, /system/priv-app (Filtrado para otimização de I/O em eMMC e respeito a SELinux)
        if (listener != null) listener.onProgress("[5/6] A analisar APKs e bibliotecas nativas (/oem, /vendor, /system/priv-app)...");
        for (PackageInfo pkg : installedPackages) {
            ApplicationInfo appInfo = pkg.applicationInfo;
            if (appInfo != null && appInfo.sourceDir != null) {
                String src = appInfo.sourceDir;
                // Respeita SELinux: usa appInfo.sourceDir que só requer permissão de travessia (x)
                // Otimização I/O: foca em diretórios com privilégios de fábrica / droppers
                if (src.startsWith("/oem") || src.startsWith("/vendor") || src.startsWith("/system/priv-app") || src.startsWith("/custom") || src.contains("oem")) {
                    result.scannedApks.add(src);
                    scanApkFile(src, result, listener);
                }
            }
        }
        checkStandaloneNativeLibraries(result);

        // 6. Varredura Heurística de Portas e Sockets de Rede
        if (listener != null) listener.onProgress("[6/6] A analisar tabela de conexões e portas ativas (incl. MQTT)...");
        scanNetworkSockets(result);

        // Exporta o log estruturado para /data/data/com.scanner.tv/files/last_scan.json
        saveScanReport(context, result);

        return result;
    }

    private static void checkMaliciousContentProviders(Context context, ScanResult result) {
        String authority = "com.release.debug.provider";
        try {
            ProviderInfo pInfo = context.getPackageManager().resolveContentProvider(authority, PackageManager.MATCH_ALL);
            if (pInfo != null) {
                result.addFinding("[CRÍTICO] Content Provider C2 do XCPE registado no sistema: " + authority + " (Pacote: " + pInfo.packageName + ")", 9);
            }
        } catch (Exception ignored) {
        }

        try {
            Uri uri = Uri.parse("content://" + authority + "/configs");
            try (Cursor cursor = context.getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null) {
                    result.addFinding("[CRÍTICO] Content Provider C2 respondeu ativamente à query content://" + authority + "/configs!", 10);
                }
            }
        } catch (SecurityException secEx) {
            result.addFinding("[CRÍTICO] Content Provider C2 detetado e ativo em memória (protegido por permissão de assinatura): " + authority, 9);
        } catch (Exception ignored) {
        }
    }

    private static void checkSystemProperties(ScanResult result) {
        String[] suspiciousProps = {
                "persist.networkstack.uninstall",
                "persist.networkstack.skip_system_install",
                "persist.networkstack.install_time"
        };
        for (String prop : suspiciousProps) {
            String val = getSystemProperty(prop);
            if (!val.isEmpty()) {
                result.addFinding("[CRÍTICO] Propriedade de controlo/evasão XCPE ativa: " + prop + " = " + val, 8);
            }
        }

        String mecool = getSystemProperty("ro.mecool.device");
        if ("true".equalsIgnoreCase(mecool)) {
            result.addFinding("[INFO] Identificador de firmware MECOOL/Videostrong detetado: ro.mecool.device = true", 1);
        }
    }

    private static void checkStandaloneNativeLibraries(ScanResult result) {
        String[] dirs = {"/system/lib", "/system/lib64", "/vendor/lib", "/vendor/lib64", "/oem/lib"};
        for (String d : dirs) {
            File dir = new File(d);
            if (dir.exists() && dir.isDirectory()) {
                for (String bin : SUSPICIOUS_NATIVE_FILES) {
                    File target = new File(dir, bin);
                    if (target.exists()) {
                        result.addFinding("[CRÍTICO] Biblioteca nativa/binário malicioso detetado em partição de sistema: " + target.getAbsolutePath(), 10);
                    }
                }
            }
        }
    }

    private static String getSystemProperty(String key) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            return (String) c.getMethod("get", String.class, String.class).invoke(null, key, "");
        } catch (Exception e) {
            return "";
        }
    }

    private static final long MAX_DEX_SCAN_SIZE_BYTES = 15 * 1024 * 1024; // Limite de 15 MB para evitar gargalos em eMMC lentos

    private static void scanApkFile(String apkPath, ScanResult result, ScanProgressListener listener) {
        File apkFile = new File(apkPath);
        if (!apkFile.exists() || !apkFile.canRead()) return;

        if (listener != null) listener.onProgress("   -> A analisar bytecode: " + apkFile.getName() + "...");

        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apkFile))) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];

            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                String simpleName = entryName.contains("/") ? entryName.substring(entryName.lastIndexOf('/') + 1) : entryName;

                if (SUSPICIOUS_NATIVE_FILES.contains(simpleName)) {
                    result.addFinding("[CRÍTICO] Payload embebido detetado dentro de " + apkFile.getName() + ": " + entryName, 9);
                }

                if (entryName.endsWith(".dex")) {
                    // Proteção contra ficheiros DEX gigantescos que degradam eMMC
                    long uncompressedSize = entry.getSize();
                    if (uncompressedSize > MAX_DEX_SCAN_SIZE_BYTES) {
                        zis.closeEntry();
                        continue;
                    }

                    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                    int len;
                    long totalRead = 0;
                    boolean exceeded = false;
                    while ((len = zis.read(buffer)) > 0) {
                        totalRead += len;
                        if (totalRead > MAX_DEX_SCAN_SIZE_BYTES) {
                            exceeded = true;
                            break;
                        }
                        byteStream.write(buffer, 0, len);
                    }
                    if (exceeded) {
                        zis.closeEntry();
                        continue;
                    }

                    byte[] dexBytes = byteStream.toByteArray();

                    for (byte[] pattern : TARGET_PATTERNS) {
                        if (containsSubArray(dexBytes, pattern)) {
                            String foundPattern = new String(pattern, StandardCharsets.UTF_8);
                            result.addFinding("[CRÍTICO] Assinatura maliciosa encontrada no bytecode de " + apkFile.getName() + ": " + foundPattern, 9);
                        }
                    }
                }
                zis.closeEntry();
            }
        } catch (Exception ignored) {
        }
    }

    private static void scanNetworkSockets(ScanResult result) {
        File tcpFile = new File("/proc/net/tcp");
        if (tcpFile.exists() && tcpFile.canRead()) {
            try (InputStream is = new FileInputStream(tcpFile)) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] data = new byte[4096];
                int nRead;
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                String content = buffer.toString("UTF-8");
                String[] lines = content.split("\n");
                for (String line : lines) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length > 2 && parts[1].contains(":")) {
                        String[] addressParts = parts[1].split(":");
                        if (addressParts.length == 2) {
                            try {
                                int port = Integer.parseInt(addressParts[1], 16);
                                if (SUSPICIOUS_PORTS.contains(port)) {
                                    result.addFinding("[CRÍTICO] Porta maliciosa de C2/MQTT ativa no dispositivo: " + port, 10);
                                }
                            } catch (Exception ignored) {
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    private static boolean containsSubArray(byte[] source, byte[] target) {
        if (target.length == 0 || source.length < target.length) return false;
        for (int i = 0; i <= source.length - target.length; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    private static void saveScanReport(Context context, ScanResult result) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"timestamp\": ").append(System.currentTimeMillis()).append(",\n");
            sb.append("  \"status\": \"").append(result.overallStatus.name()).append("\",\n");
            sb.append("  \"risk_score\": ").append(result.riskScore).append(",\n");
            sb.append("  \"device\": \"").append(result.deviceDetails).append("\",\n");
            sb.append("  \"play_protect\": \"").append(result.playProtectStatus).append("\",\n");
            sb.append("  \"scanned_oem_apks_count\": ").append(result.scannedApks.size()).append(",\n");
            sb.append("  \"findings\": [\n");
            for (int i = 0; i < result.findings.size(); i++) {
                sb.append("    \"").append(result.findings.get(i).replace("\"", "\\\"")).append("\"");
                if (i < result.findings.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ]\n");
            sb.append("}\n");

            byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream fos = new FileOutputStream(new File(context.getFilesDir(), "last_scan.json"))) {
                fos.write(bytes);
            }
            File extDir = context.getExternalFilesDir(null);
            if (extDir != null) {
                try (FileOutputStream fos = new FileOutputStream(new File(extDir, "last_scan.json"))) {
                    fos.write(bytes);
                }
            }
        } catch (Exception ignored) {
        }
    }
}

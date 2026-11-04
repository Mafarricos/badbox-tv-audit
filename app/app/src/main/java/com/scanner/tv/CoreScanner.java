package com.scanner.tv;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
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

    // Assinaturas de C2, Backdoors, SDKs maliciosos e Infraestrutura Videostrong/BadBox
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
            "Aviciiii/ott".getBytes(StandardCharsets.UTF_8),
            "ktpeng2026/ott_release".getBytes(StandardCharsets.UTF_8),
            "lw_android_agent_special_ndk".getBytes(StandardCharsets.UTF_8),
            "com.abc.nexus".getBytes(StandardCharsets.UTF_8),
            "219.134.163.210".getBytes(StandardCharsets.UTF_8),
            "filemail.com".getBytes(StandardCharsets.UTF_8),
            "videostrong".getBytes(StandardCharsets.UTF_8),
            "yokatvonline".getBytes(StandardCharsets.UTF_8),
            "titannet.io".getBytes(StandardCharsets.UTF_8),
            "getgrass.io".getBytes(StandardCharsets.UTF_8),
            "traffmonetizer.com".getBytes(StandardCharsets.UTF_8),
            "painet.work".getBytes(StandardCharsets.UTF_8),
            "dgjm.online".getBytes(StandardCharsets.UTF_8),
            "uota.club".getBytes(StandardCharsets.UTF_8),
            "uota.xyz".getBytes(StandardCharsets.UTF_8)
    };

    // Pacotes conhecidos de Trojans, Proxies Residenciais e Ad Fraud da campanha
    private static final List<String> IOC_PACKAGES = Arrays.asList(
            "x.cpe", "com.oemservice", "com.abc.nexus", "io.popanet", "gaganode",
            "linkfog", "appsalt", "traffmonetizer", "cboxtv", "hiddenview", "moyu", "spirit",
            "android-grass", "com.grass", "appdnschange", "SmartPrivilege", "SmartEntertainment",
            "SmartThroughput", "EcoSaverDaemon", "titannet", "yokatv"
    );

    // Portas conhecidas de C2 e Proxies
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
            1080, 8080, 9050, 4145, 3885, 3886, 3887, 8888, 7777, 9999, 5555, 6667,
            22345, 16000, 12000, 9992, 9994, 2375, 2095, 2082
    ));

    public interface ScanProgressListener {
        void onProgress(String message);
    }

    public static ScanResult executeScan(Context context, ScanProgressListener listener) {
        ScanResult result = new ScanResult();

        if (listener != null) listener.onProgress("[1/5] A verificar integridade do Google Play Protect...");

        // 1. Play Protect Tampering Check
        try {
            int userConsent = Settings.Global.getInt(context.getContentResolver(), "package_verifier_user_consent", 1);
            int verifierEnable = Settings.Global.getInt(context.getContentResolver(), "package_verifier_enable", 1);

            result.playProtectStatus = "user_consent=" + userConsent + " | enable=" + verifierEnable;

            if (userConsent == -1) {
                result.addFinding("[CRÍTICO] Google Play Protect foi forçado a desligar no firmware (user_consent = -1)!", 10);
            } else if (verifierEnable == 0) {
                result.addFinding("[SUSPEITO] Verificação de pacotes desligada nas definições do sistema.", 3);
            }
        } catch (Exception e) {
            result.playProtectStatus = "Erro ao ler definições: " + e.getMessage();
        }

        // 2. Hardware e Fingerprint Integrity Check
        if (listener != null) listener.onProgress("[2/5] A inspecionar assinaturas de firmware e propriedades...");
        String manufacturer = Build.MANUFACTURER.toLowerCase();
        String brand = Build.BRAND.toLowerCase();
        String model = Build.MODEL.toLowerCase();
        String fingerprint = Build.FINGERPRINT.toLowerCase();
        String tags = Build.TAGS.toLowerCase();

        result.deviceDetails = Build.MANUFACTURER + " " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ", SDK " + Build.VERSION.SDK_INT + ")";

        // Verificação informativa de histórico OEM (Synthient Videostrong)
        if (manufacturer.contains("videostrong") || brand.contains("mecool") || model.contains("km9") || model.contains("km2") || model.contains("km6") || model.contains("km7")) {
            result.addFinding("[AVISO INFORMATIVO] Dispositivo com linha de hardware Videostrong/MECOOL (historicamente visada pela botnet XCPE). Requer verificação rigorosa de evidências.", 0);
        }

        if (tags.contains("test-keys") || fingerprint.contains("test-keys")) {
            result.addFinding("[ALERTA] Firmware assinado com chaves públicas genéricas 'test-keys'.", 3);
        }

        boolean hasTelephony = context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
        if (hasTelephony) {
            result.addFinding("[SUSPEITO] A box declara suporte GSM/Telefonia móvel (Típico de spoofing para ad-fraud).", 3);
        }

        // 3. Enumeração de Pacotes Instalados vs Lista de IoCs
        if (listener != null) listener.onProgress("[3/5] A procurar pacotes maliciosos conhecidos e backdoors...");
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

        // 4. Inspeção Estática de APKs em /oem e /system (DEX/SO Scanner)
        if (listener != null) listener.onProgress("[4/5] A realizar desmontagem estática de APKs de sistema (/oem, /vendor)...");
        for (PackageInfo pkg : installedPackages) {
            ApplicationInfo appInfo = pkg.applicationInfo;
            if (appInfo != null && appInfo.sourceDir != null) {
                String src = appInfo.sourceDir;
                if (src.startsWith("/oem") || src.startsWith("/vendor") || src.startsWith("/custom") || src.contains("oem")) {
                    result.scannedApks.add(src);
                    scanApkFile(src, result, listener);
                }
            }
        }

        // 5. Varredura Heurística de Portas e Sockets de Rede
        if (listener != null) listener.onProgress("[5/5] A analisar tabela de conexões e portas ativas...");
        scanNetworkSockets(result);

        // Exporta o log estruturado para /data/data/com.scanner.tv/files/last_scan.json
        saveScanReport(context, result);

        return result;
    }

    private static void scanApkFile(String apkPath, ScanResult result, ScanProgressListener listener) {
        File apkFile = new File(apkPath);
        if (!apkFile.exists() || !apkFile.canRead()) return;

        if (listener != null) listener.onProgress("   -> A analisar bytecode: " + apkFile.getName() + "...");

        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apkFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name.endsWith(".dex") || name.endsWith(".so")) {
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    byte[] data = new byte[8192];
                    int nRead;
                    while ((nRead = zis.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, nRead);
                    }
                    byte[] bytes = buffer.toByteArray();

                    for (byte[] pattern : TARGET_PATTERNS) {
                        if (containsSubArray(bytes, pattern)) {
                            String foundString = new String(pattern, StandardCharsets.UTF_8);
                            result.addFinding("[CRÍTICO] String maliciosa de C2/Botnet encontrada em " + apkFile.getName() + " [" + name + "]: " + foundString, 10);
                        }
                    }
                }
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
                                    result.addFinding("[CRÍTICO] Porta maliciosa de C2 ativa no dispositivo: " + port, 10);
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
            File file = new File(context.getFilesDir(), "last_scan.json");
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

            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
        }
    }
}

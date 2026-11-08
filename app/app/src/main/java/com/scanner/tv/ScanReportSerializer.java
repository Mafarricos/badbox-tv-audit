package com.scanner.tv;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

/**
 * Serializador e parser de relatórios forenses (JT-04, APP-04).
 * Usa org.json para garantir conformidade estrita e escape correto de aspas, barras e caracteres de controlo.
 */
public class ScanReportSerializer {

    public static String serialize(
            String scanId,
            long timestamp,
            String overallStatus,
            int riskScore,
            String deviceDetails,
            String playProtectStatus,
            int scannedApksCount,
            List<String> findings
    ) throws JSONException {
        return serialize(scanId, timestamp, overallStatus, riskScore, deviceDetails, playProtectStatus, scannedApksCount, findings, overallStatus);
    }

    public static String serialize(
            String scanId,
            long timestamp,
            String overallStatus,
            int riskScore,
            String deviceDetails,
            String playProtectStatus,
            int scannedApksCount,
            List<String> findings,
            String verdict
    ) throws JSONException {
        JSONObject root = new JSONObject();
        root.put("schema_version", 2);
        root.put("scan_id", scanId != null ? scanId : "");
        root.put("timestamp", timestamp);
        root.put("status", overallStatus != null ? overallStatus : "CLEAN");
        root.put("risk_score", riskScore);
        root.put("device", deviceDetails != null ? deviceDetails : "");
        root.put("play_protect", playProtectStatus != null ? playProtectStatus : "");
        root.put("scanned_oem_apks_count", scannedApksCount);
        root.put("verdict", verdict != null ? verdict : "LIMPO / SEGURO");

        JSONArray findingsArray = new JSONArray();
        if (findings != null) {
            for (String f : findings) {
                findingsArray.put(f);
            }
        }
        root.put("findings", findingsArray);

        return root.toString(2);
    }

    public static JSONObject deserialize(String jsonStr) throws JSONException {
        return new JSONObject(jsonStr);
    }
}

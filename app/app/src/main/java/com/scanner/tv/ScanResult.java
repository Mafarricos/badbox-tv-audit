package com.scanner.tv;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ScanResult implements Serializable {
    public enum Status {
        LIMPO,
        SUSPEITO,
        INFETADO_CRITICO
    }

    public Status overallStatus = Status.LIMPO;
    public int riskScore = 0;
    public List<String> findings = new ArrayList<>();
    public List<String> scannedApks = new ArrayList<>();
    public List<String> userThreatPackages = new ArrayList<>();
    public List<String> systemThreatPackages = new ArrayList<>();
    public String deviceDetails = "";
    public String playProtectStatus = "";

    public void addFinding(String finding, int scoreWeight) {
        findings.add(finding);
        riskScore += scoreWeight;
        if (scoreWeight >= 5) {
            overallStatus = Status.INFETADO_CRITICO;
        } else if (scoreWeight >= 2 && overallStatus != Status.INFETADO_CRITICO) {
            overallStatus = Status.SUSPEITO;
        }
    }
}

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

    public static class FindingEntry implements Serializable {
        public final String text;
        public final int weight;

        public FindingEntry(String text, int weight) {
            this.text = text;
            this.weight = weight;
        }
    }

    public Status overallStatus = Status.LIMPO;
    public int riskScore = 0;
    public List<String> findings = new ArrayList<>();
    public List<FindingEntry> entries = new ArrayList<>();
    public List<String> scannedApks = new ArrayList<>();
    public List<String> userThreatPackages = new ArrayList<>();
    public List<String> systemThreatPackages = new ArrayList<>();
    public String deviceDetails = "";
    public String playProtectStatus = "";

    public void addFinding(String finding, int scoreWeight) {
        findings.add(finding);
        entries.add(new FindingEntry(finding, scoreWeight));
        riskScore += scoreWeight;
        if (scoreWeight >= 5) {
            overallStatus = Status.INFETADO_CRITICO;
        } else if (scoreWeight >= 2 && overallStatus != Status.INFETADO_CRITICO) {
            overallStatus = Status.SUSPEITO;
        }
    }

    /**
     * Retorna a contagem honesta de ameaças ativas reais (exclui itens meramente informativos ou desativados).
     */
    public int getThreatCount() {
        int count = 0;
        for (FindingEntry entry : entries) {
            if (entry.weight >= 4 && !entry.text.contains("[DESATIVADO]")) {
                count++;
            }
        }
        return count;
    }
}

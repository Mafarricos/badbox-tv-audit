package com.scanner.tv;

import java.util.Set;

/**
 * Parser de QNAME de pacotes DNS (JT-02).
 * Trata rótulos truncados, rótulos com mais de 63 caracteres, caracteres não-imprimíveis e limites de buffer sem lançar exceções.
 */
public class DnsPacketParser {

    public static String parseQName(byte[] packet, int dnsHeaderOffset) {
        if (packet == null || dnsHeaderOffset < 0 || dnsHeaderOffset + 12 >= packet.length) {
            return "";
        }

        int offset = dnsHeaderOffset + 12;
        StringBuilder qname = new StringBuilder();
        int totalLength = 0;

        try {
            while (offset < packet.length) {
                int len = packet[offset++] & 0xFF;
                if (len == 0) {
                    break;
                }

                if ((len & 0xC0) != 0 || len > 63) {
                    return "";
                }

                if (offset + len > packet.length) {
                    return "";
                }

                if (qname.length() > 0) {
                    qname.append(".");
                    totalLength++;
                }

                for (int i = 0; i < len; i++) {
                    int c = packet[offset++] & 0xFF;
                    if (c >= 33 && c <= 126) {
                        qname.append((char) Character.toLowerCase(c));
                    } else {
                        qname.append('_');
                    }
                    totalLength++;
                    if (totalLength > 253) {
                        return "";
                    }
                }
            }
        } catch (Exception e) {
            return "";
        }

        return qname.toString();
    }

    public static boolean isMatch(String domain, Set<String> c2Domains) {
        if (domain == null || domain.isEmpty() || c2Domains == null) return false;
        String lower = domain.toLowerCase();
        for (String c2 : c2Domains) {
            String c2Lower = c2.toLowerCase();
            if (lower.equals(c2Lower) || lower.endsWith("." + c2Lower)) {
                return true;
            }
        }
        return false;
    }
}

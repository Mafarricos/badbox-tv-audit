package com.scanner.tv;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Classificador determinístico de endereços IP (JT-01).
 * Classifica corretamente intervalos públicos vs privados (RFC 1918, CGNAT, Loopback, ULA, Link-Local).
 */
public class IpClassifier {

    public static boolean isPrivateOrLocal(String ipStr) {
        if (ipStr == null || ipStr.trim().isEmpty()) {
            return true;
        }
        String clean = ipStr.trim();
        if (clean.startsWith("::ffff:")) {
            clean = clean.substring(7);
        }

        try {
            InetAddress addr = InetAddress.getByName(clean);
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress() || addr.isAnyLocalAddress() || addr.isMulticastAddress()) {
                return true;
            }

            if (addr instanceof Inet4Address) {
                byte[] octets = addr.getAddress();
                int b0 = octets[0] & 0xFF;
                int b1 = octets[1] & 0xFF;

                // 10.0.0.0/8
                if (b0 == 10) return true;

                // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;

                // 192.168.0.0/16
                if (b0 == 192 && b1 == 168) return true;

                // CGNAT 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
                if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true;

                // 169.254.0.0/16 (Link-Local)
                if (b0 == 169 && b1 == 254) return true;

                return false;
            } else if (addr instanceof Inet6Address) {
                byte[] bytes = addr.getAddress();
                int b0 = bytes[0] & 0xFF;
                int b1 = bytes[1] & 0xFF;

                // ULA fc00::/7 (fc00::/8 e fd00::/8)
                if ((b0 & 0xFE) == 0xFC) return true;

                // Link-local fe80::/10
                if (b0 == 0xFE && (b1 & 0xC0) == 0x80) return true;

                return false;
            }
        } catch (Exception e) {
            return true;
        }

        return false;
    }

    public static boolean isPublic(String ipStr) {
        return !isPrivateOrLocal(ipStr);
    }

    public static boolean isInternalOrLocal(String ipStr) {
        return isPrivateOrLocal(ipStr);
    }

    public static boolean isGoogleInfrastructure(String ipStr) {
        if (ipStr == null || ipStr.trim().isEmpty()) return false;
        String ip = ipStr.trim();
        return ip.equals("8.8.8.8") || ip.equals("8.8.4.4")
                || ip.startsWith("142.250.") || ip.startsWith("172.217.")
                || ip.startsWith("216.58.") || ip.startsWith("74.125.");
    }
}

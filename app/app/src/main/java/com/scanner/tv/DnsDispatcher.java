package com.scanner.tv;

import java.net.InetAddress;
import java.util.Arrays;

/**
 * Despachador seguro de consultas DNS em threads separadas (JT-07, VPN-03).
 * Garante que o buffer despachado é uma cópia defensiva imutável do pacote original.
 */
public class DnsDispatcher {

    public interface DnsSendCallback {
        void send(byte[] payload);
    }

    public static byte[] prepareDnsPayload(byte[] packet, int offset, int length) {
        if (packet == null || offset < 0 || length <= 0 || offset + length > packet.length) {
            return new byte[0];
        }
        return Arrays.copyOfRange(packet, offset, offset + length);
    }

    public static void dispatch(byte[] packet, int offset, int length, DnsSendCallback callback) {
        byte[] payload = prepareDnsPayload(packet, offset, length);
        if (payload.length > 0 && callback != null) {
            callback.send(payload);
        }
    }

    public static byte[] buildDnsResponsePacket(String srcIp, String dstIp, int srcPort, int dstPort, byte[] dnsResponsePayload, int dnsResponseLen) {
        int totalLen = 20 + 8 + dnsResponseLen;
        byte[] resp = new byte[totalLen];
        // IPv4 Header (20 bytes)
        resp[0] = 0x45;
        resp[2] = (byte) ((totalLen >> 8) & 0xFF);
        resp[3] = (byte) (totalLen & 0xFF);
        resp[6] = 0x40; // DF
        resp[8] = 64;   // TTL
        resp[9] = 17;   // UDP (17)
        try {
            byte[] srcBytes = InetAddress.getByName(srcIp).getAddress();
            byte[] dstBytes = InetAddress.getByName(dstIp).getAddress();
            System.arraycopy(srcBytes, 0, resp, 12, 4);
            System.arraycopy(dstBytes, 0, resp, 16, 4);
        } catch (Exception ignored) {
        }
        int checksum = computeChecksum(resp, 20);
        resp[10] = (byte) ((checksum >> 8) & 0xFF);
        resp[11] = (byte) (checksum & 0xFF);

        // UDP Header (8 bytes)
        int udpLen = 8 + dnsResponseLen;
        resp[20] = (byte) ((srcPort >> 8) & 0xFF);
        resp[21] = (byte) (srcPort & 0xFF);
        resp[22] = (byte) ((dstPort >> 8) & 0xFF);
        resp[23] = (byte) (dstPort & 0xFF);
        resp[24] = (byte) ((udpLen >> 8) & 0xFF);
        resp[25] = (byte) (udpLen & 0xFF);

        if (dnsResponsePayload != null && dnsResponseLen > 0) {
            System.arraycopy(dnsResponsePayload, 0, resp, 28, dnsResponseLen);
        }
        return resp;
    }

    private static int computeChecksum(byte[] buf, int length) {
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
}

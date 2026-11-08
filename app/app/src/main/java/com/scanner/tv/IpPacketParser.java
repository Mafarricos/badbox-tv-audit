package com.scanner.tv;

import java.net.InetAddress;

/**
 * Parser determinístico de pacotes brutos IPv4 e IPv6 (JT-06, VPN-02).
 * Trata pacotes malformados ou incompletos sem lançar exceções não tratadas.
 */
public class IpPacketParser {

    public static class ParsedPacket {
        public final int ipVersion;
        public final String protocol; // "TCP", "UDP"
        public final String srcIp;
        public final String dstIp;
        public final int srcPort;
        public final int dstPort;
        public final int payloadOffset;

        public ParsedPacket(int ipVersion, String protocol, String srcIp, String dstIp, int srcPort, int dstPort, int payloadOffset) {
            this.ipVersion = ipVersion;
            this.protocol = protocol;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.payloadOffset = payloadOffset;
        }
    }

    public static ParsedPacket parse(byte[] packet, int length) {
        if (packet == null || length < 20) {
            return null;
        }

        try {
            int version = (packet[0] >> 4) & 0x0F;

            if (version == 4) {
                // IPv4: IHL mínimo 5 (20 bytes)
                int ihl = (packet[0] & 0x0F) * 4;
                if (ihl < 20 || ihl > length) {
                    return null;
                }

                int protoNum = packet[9] & 0xFF;
                String proto;
                if (protoNum == 6) {
                    proto = "TCP";
                } else if (protoNum == 17) {
                    proto = "UDP";
                } else {
                    return null;
                }

                // Extrair endereços IPv4 (offsets 12 e 16)
                byte[] srcBytes = new byte[4];
                byte[] dstBytes = new byte[4];
                System.arraycopy(packet, 12, srcBytes, 0, 4);
                System.arraycopy(packet, 16, dstBytes, 0, 4);
                String srcIp = InetAddress.getByAddress(srcBytes).getHostAddress();
                String dstIp = InetAddress.getByAddress(dstBytes).getHostAddress();

                // Cabeçalho de transporte (TCP/UDP exige pelo menos 4 bytes adicionais para portas)
                if (ihl + 4 > length) {
                    return null;
                }

                int srcPort = ((packet[ihl] & 0xFF) << 8) | (packet[ihl + 1] & 0xFF);
                int dstPort = ((packet[ihl + 2] & 0xFF) << 8) | (packet[ihl + 3] & 0xFF);
                int transportHeaderLen = (proto.equals("UDP")) ? 8 : ((packet[ihl + 12] >> 4) & 0x0F) * 4;
                int payloadOffset = ihl + transportHeaderLen;

                return new ParsedPacket(4, proto, srcIp, dstIp, srcPort, dstPort, payloadOffset);

            } else if (version == 6) {
                // IPv6: cabeçalho base fixo de 40 bytes
                if (length < 40) {
                    return null;
                }

                int nextHeader = packet[6] & 0xFF;
                String proto;
                if (nextHeader == 6) {
                    proto = "TCP";
                } else if (nextHeader == 17) {
                    proto = "UDP";
                } else {
                    return null;
                }

                byte[] srcBytes = new byte[16];
                byte[] dstBytes = new byte[16];
                System.arraycopy(packet, 8, srcBytes, 0, 16);
                System.arraycopy(packet, 24, dstBytes, 0, 16);
                String srcIp = InetAddress.getByAddress(srcBytes).getHostAddress();
                String dstIp = InetAddress.getByAddress(dstBytes).getHostAddress();

                int transportOffset = 40;
                if (transportOffset + 4 > length) {
                    return null;
                }

                int srcPort = ((packet[transportOffset] & 0xFF) << 8) | (packet[transportOffset + 1] & 0xFF);
                int dstPort = ((packet[transportOffset + 2] & 0xFF) << 8) | (packet[transportOffset + 3] & 0xFF);
                int transportHeaderLen = (proto.equals("UDP")) ? 8 : ((packet[transportOffset + 12] >> 4) & 0x0F) * 4;
                int payloadOffset = transportOffset + transportHeaderLen;

                return new ParsedPacket(6, proto, srcIp, dstIp, srcPort, dstPort, payloadOffset);
            }
        } catch (Exception e) {
            return null;
        }

        return null;
    }
}

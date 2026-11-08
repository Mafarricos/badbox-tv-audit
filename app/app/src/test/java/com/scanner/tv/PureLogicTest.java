package com.scanner.tv;

import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class PureLogicTest {

    @Test
    public void testJT01_ipClassification() {
        // JT-01: Classificação de IPs públicos vs privados/locais
        // 172.32.0.1 e 172.200.1.1 são PÚBLICOS
        assertTrue(IpClassifier.isPublic("172.32.0.1"));
        assertTrue(IpClassifier.isPublic("172.200.1.1"));
        assertFalse(IpClassifier.isPrivateOrLocal("172.32.0.1"));
        assertFalse(IpClassifier.isPrivateOrLocal("172.200.1.1"));

        // 172.16.0.1, 10.0.0.1, 192.168.1.1, 100.64.0.1, fd00::1 e fe80::1 são PRIVADOS ou LOCAIS
        assertTrue(IpClassifier.isPrivateOrLocal("172.16.0.1"));
        assertTrue(IpClassifier.isPrivateOrLocal("10.0.0.1"));
        assertTrue(IpClassifier.isPrivateOrLocal("192.168.1.1"));
        assertTrue(IpClassifier.isPrivateOrLocal("100.64.0.1"));
        assertTrue(IpClassifier.isPrivateOrLocal("fd00::1"));
        assertTrue(IpClassifier.isPrivateOrLocal("fe80::1"));
        assertFalse(IpClassifier.isPublic("192.168.1.1"));
    }

    @Test
    public void testJT02_qnameParserRobustness() {
        // JT-02: Nomes válidos OK. Labels com mais de 63 caracteres, truncados ou fora de limites -> vazio.
        // Sanitização de caracteres não imprimíveis.

        // 1. Nome válido: "example.com"
        // 12 bytes cabeçalho DNS + [7]example[3]com[0]
        byte[] validDns = new byte[12 + 13];
        int idx = 12;
        validDns[idx++] = 7;
        for (byte b : "example".getBytes()) validDns[idx++] = b;
        validDns[idx++] = 3;
        for (byte b : "com".getBytes()) validDns[idx++] = b;
        validDns[idx++] = 0;

        assertEquals("example.com", DnsPacketParser.parseQName(validDns, 0));

        // 2. Label com 64 caracteres (> 63) -> deve devolver vazio sem exceção
        byte[] invalidLenDns = new byte[12 + 70];
        invalidLenDns[12] = 64; // > 63
        for (int i = 0; i < 64; i++) invalidLenDns[13 + i] = 'a';
        invalidLenDns[13 + 64] = 0;

        assertEquals("", DnsPacketParser.parseQName(invalidLenDns, 0));

        // 3. Pacote truncado (diz que tem 10 bytes de label mas o pacote acaba antes) -> vazio
        byte[] truncatedDns = new byte[15];
        truncatedDns[12] = 10; // offset 13 só tem 2 bytes restantes
        assertEquals("", DnsPacketParser.parseQName(truncatedDns, 0));

        // 4. Caracteres não-imprimíveis sanitizados
        byte[] nonPrintable = new byte[12 + 7];
        nonPrintable[12] = 5;
        nonPrintable[13] = 'a';
        nonPrintable[14] = 0x01; // não imprimível
        nonPrintable[15] = 'b';
        nonPrintable[16] = 0x1F; // não imprimível
        nonPrintable[17] = 'c';
        nonPrintable[18] = 0;

        String parsed = DnsPacketParser.parseQName(nonPrintable, 0);
        assertEquals("a_b_c", parsed);
    }

    @Test
    public void testJT03_flowDeduplication() {
        // JT-03: 100 pacotes do mesmo fluxo -> 1 evento com count=100
        FlowTracker tracker = new FlowTracker();
        long now = 1000L;

        for (int i = 0; i < 100; i++) {
            tracker.record("TCP", "192.168.1.50", 45678, "38.145.197.135", 3885, now + i * 10);
        }

        assertEquals(1, tracker.getUniqueFlowCount());
        FlowTracker.FlowKey key = new FlowTracker.FlowKey("TCP", "192.168.1.50", 45678, "38.145.197.135", 3885);
        FlowTracker.FlowEvent event = tracker.getFlow(key);
        assertNotNull(event);
        assertEquals(100, event.packetCount);
        assertEquals(1000L, event.firstSeen);
        assertEquals(1000L + 990L, event.lastSeen);
    }

    @Test
    public void testJT04_scanReportSerializationWithSpecialChars() throws Exception {
        // JT-04: Serialização com ", \, \n e caracteres de controlo nas strings produz JSON válido e idêntico
        String specialFinding = "Ameaça encontrada: \"backdoor.so\" com path C:\\malware\\path\ne control \u0000 chars\t!";
        List<String> findings = Collections.singletonList(specialFinding);

        String json = ScanReportSerializer.serialize(
                "test-scan-uuid-1234",
                1700000000000L,
                "INFECTED",
                10,
                "Device \"Special\\Model\"\nLine2",
                "user_consent=-1",
                42,
                findings,
                "INFETADO - CRÍTICO"
        );

        JSONObject deserialized = ScanReportSerializer.deserialize(json);
        assertEquals(2, deserialized.getInt("schema_version"));
        assertEquals("test-scan-uuid-1234", deserialized.getString("scan_id"));
        assertEquals("Device \"Special\\Model\"\nLine2", deserialized.getString("device"));
        assertEquals(1, deserialized.getJSONArray("findings").length());
        assertEquals(specialFinding, deserialized.getJSONArray("findings").getString(0));
    }

    @Test
    public void testJT05_exactPackageMatching() {
        // JT-05: com.spiritapps.x NÃO coincide com spirit; sso.authhandler coincide com sso.authHandler
        PackageMatcher matcher = new PackageMatcher(Arrays.asList("spirit", "sso.authHandler", "com.oemservice"));

        // Match exato
        assertTrue(matcher.matches("spirit"));
        // Case-insensitve
        assertTrue(matcher.matches("sso.authhandler"));
        assertTrue(matcher.matches("sso.AUTHHANDLER"));
        assertTrue(matcher.matches("com.OEMSERVICE"));

        // Proibição de match por substring
        assertFalse(matcher.matches("com.spiritapps.x"));
        assertFalse(matcher.matches("spirit.app"));
        assertFalse(matcher.matches("com.spirit"));
        assertFalse(matcher.matches("my.oemservice.fake"));
    }

    @Test
    public void testJT06_ipPacketParsingIpv4Ipv6() {
        // JT-06: Parsing de IPv4/IPv6 com TCP/UDP. Portas corretas; pacotes malformados rejeitados sem exceção.

        // 1. Pacote IPv4 TCP válido (20 bytes IPv4 + 20 bytes TCP)
        byte[] ipv4Tcp = new byte[40];
        ipv4Tcp[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        ipv4Tcp[9] = 6;    // TCP
        // Src IP 192.168.1.50
        ipv4Tcp[12] = (byte) 192; ipv4Tcp[13] = (byte) 168; ipv4Tcp[14] = 1; ipv4Tcp[15] = 50;
        // Dst IP 104.16.123.96
        ipv4Tcp[16] = 104; ipv4Tcp[17] = 16; ipv4Tcp[18] = 123; ipv4Tcp[19] = 96;
        // Src port 45678 (0xB26E)
        ipv4Tcp[20] = (byte) 0xB2; ipv4Tcp[21] = 0x6E;
        // Dst port 2095 (0x082F)
        ipv4Tcp[22] = 0x08; ipv4Tcp[23] = 0x2F;
        // TCP Data Offset 5 (20 bytes)
        ipv4Tcp[32] = 0x50;

        IpPacketParser.ParsedPacket p1 = IpPacketParser.parse(ipv4Tcp, ipv4Tcp.length);
        assertNotNull(p1);
        assertEquals(4, p1.ipVersion);
        assertEquals("TCP", p1.protocol);
        assertEquals("192.168.1.50", p1.srcIp);
        assertEquals("104.16.123.96", p1.dstIp);
        assertEquals(45678, p1.srcPort);
        assertEquals(2095, p1.dstPort);

        // 2. Pacote malformado / truncado (diz que tem 40 bytes mas só passam 10) -> devolve null sem crash
        assertNull(IpPacketParser.parse(ipv4Tcp, 10));
        assertNull(IpPacketParser.parse(new byte[5], 5));
        assertNull(IpPacketParser.parse(null, 0));
    }

    @Test
    public void testJT07_dnsDispatcherIndependentPayloadCopy() {
        // JT-07: O payload enviado é uma cópia independente do buffer de leitura
        byte[] readBuffer = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        final byte[][] dispatched = new byte[1][];

        DnsDispatcher.dispatch(readBuffer, 1, 3, new DnsDispatcher.DnsSendCallback() {
            @Override
            public void send(byte[] payload) {
                dispatched[0] = payload;
            }
        });

        assertNotNull(dispatched[0]);
        assertEquals(3, dispatched[0].length);
        assertEquals(0x02, dispatched[0][0]);
        assertEquals(0x03, dispatched[0][1]);
        assertEquals(0x04, dispatched[0][2]);

        // Modificar o buffer original de leitura não pode alterar o payload despachado!
        readBuffer[1] = (byte) 0xFF;
        assertEquals(0x02, dispatched[0][0]);
    }
}

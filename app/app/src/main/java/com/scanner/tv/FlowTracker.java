package com.scanner.tv;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Gestor e agregador de fluxos de rede (JT-03, VPN-01).
 * Deduplica pacotes pertencentes ao mesmo fluxo de 5 tuplos (proto, srcIp, srcPort, dstIp, dstPort).
 */
public class FlowTracker {

    public static class FlowKey {
        public final String proto;
        public final String srcIp;
        public final int srcPort;
        public final String dstIp;
        public final int dstPort;

        public FlowKey(String proto, String srcIp, int srcPort, String dstIp, int dstPort) {
            this.proto = proto != null ? proto.toUpperCase() : "TCP";
            this.srcIp = srcIp != null ? srcIp : "";
            this.srcPort = srcPort;
            this.dstIp = dstIp != null ? dstIp : "";
            this.dstPort = dstPort;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FlowKey flowKey = (FlowKey) o;
            return srcPort == flowKey.srcPort &&
                    dstPort == flowKey.dstPort &&
                    Objects.equals(proto, flowKey.proto) &&
                    Objects.equals(srcIp, flowKey.srcIp) &&
                    Objects.equals(dstIp, flowKey.dstIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(proto, srcIp, srcPort, dstIp, dstPort);
        }

        @Override
        public String toString() {
            return proto + ":" + srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;
        }
    }

    public static class FlowEvent {
        public final FlowKey key;
        public int packetCount;
        public long firstSeen;
        public long lastSeen;

        public FlowEvent(FlowKey key, long timestamp) {
            this.key = key;
            this.packetCount = 1;
            this.firstSeen = timestamp;
            this.lastSeen = timestamp;
        }

        public void recordPacket(long timestamp) {
            this.packetCount++;
            this.lastSeen = timestamp;
        }
    }

    private final Map<FlowKey, FlowEvent> mFlows = new HashMap<>();

    public synchronized FlowEvent record(String proto, String srcIp, int srcPort, String dstIp, int dstPort, long timestamp) {
        FlowKey key = new FlowKey(proto, srcIp, srcPort, dstIp, dstPort);
        FlowEvent event = mFlows.get(key);
        if (event == null) {
            event = new FlowEvent(key, timestamp);
            mFlows.put(key, event);
        } else {
            event.recordPacket(timestamp);
        }
        return event;
    }

    public synchronized boolean shouldAlert(String srcIp, String dstIp, int dstPort, String proto) {
        FlowKey key = new FlowKey(proto, srcIp, 0, dstIp, dstPort);
        FlowEvent event = mFlows.get(key);
        if (event == null) {
            record(proto, srcIp, 0, dstIp, dstPort, System.currentTimeMillis());
            return true;
        }
        event.recordPacket(System.currentTimeMillis());
        return false;
    }

    public synchronized int getUniqueFlowCount() {
        return mFlows.size();
    }

    public synchronized FlowEvent getFlow(FlowKey key) {
        return mFlows.get(key);
    }

    public synchronized void clear() {
        mFlows.clear();
    }
}

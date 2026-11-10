package com.cyberattack.soc.dto;

import java.util.HashMap;
import java.util.Map;

public class StatsResponseDTO {
    private long totalFlowsCaptured = 0;
    private long observedFlowsCount = 0;
    private long simulatedFlowsCount = 0;
    private double currentPacketRatePps = 0.0;
    private double currentBandwidthBps = 0.0;
    private Map<String, Long> protocolDistribution = new HashMap<>();

    public StatsResponseDTO() {}

    public long getTotalFlowsCaptured() { return totalFlowsCaptured; }
    public void setTotalFlowsCaptured(long totalFlowsCaptured) { this.totalFlowsCaptured = totalFlowsCaptured; }

    public long getObservedFlowsCount() { return observedFlowsCount; }
    public void setObservedFlowsCount(long observedFlowsCount) { this.observedFlowsCount = observedFlowsCount; }

    public long getSimulatedFlowsCount() { return simulatedFlowsCount; }
    public void setSimulatedFlowsCount(long simulatedFlowsCount) { this.simulatedFlowsCount = simulatedFlowsCount; }

    public double getCurrentPacketRatePps() { return currentPacketRatePps; }
    public void setCurrentPacketRatePps(double currentPacketRatePps) { this.currentPacketRatePps = currentPacketRatePps; }

    public double getCurrentBandwidthBps() { return currentBandwidthBps; }
    public void setCurrentBandwidthBps(double currentBandwidthBps) { this.currentBandwidthBps = currentBandwidthBps; }

    public Map<String, Long> getProtocolDistribution() { return protocolDistribution; }
    public void setProtocolDistribution(Map<String, Long> protocolDistribution) { this.protocolDistribution = protocolDistribution; }
}

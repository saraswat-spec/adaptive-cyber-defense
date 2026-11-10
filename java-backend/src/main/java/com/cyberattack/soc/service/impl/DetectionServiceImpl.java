package com.cyberattack.soc.service.impl;

import com.cyberattack.soc.dto.*;
import com.cyberattack.soc.model.*;
import com.cyberattack.soc.model.enums.*;
import com.cyberattack.soc.repository.NetworkEventRepository;
import com.cyberattack.soc.repository.ThreatAlertRepository;
import com.cyberattack.soc.service.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional
public class DetectionServiceImpl implements DetectionService {

    private static final Logger logger = LoggerFactory.getLogger(DetectionServiceImpl.class);

    private final NetworkEventRepository networkEventRepository;
    private final ThreatAlertRepository threatAlertRepository;
    private final PythonMLClient pythonMLClient;
    private final RiskScoringService riskScoringService;
    private final AdaptiveThresholdService adaptiveThresholdService;
    private final IncidentManagementService incidentManagementService;

    public DetectionServiceImpl(NetworkEventRepository networkEventRepository,
                                ThreatAlertRepository threatAlertRepository,
                                PythonMLClient pythonMLClient,
                                RiskScoringService riskScoringService,
                                AdaptiveThresholdService adaptiveThresholdService,
                                IncidentManagementService incidentManagementService) {
        this.networkEventRepository = networkEventRepository;
        this.threatAlertRepository = threatAlertRepository;
        this.pythonMLClient = pythonMLClient;
        this.riskScoringService = riskScoringService;
        this.adaptiveThresholdService = adaptiveThresholdService;
        this.incidentManagementService = incidentManagementService;
    }

    @Override
    public DetectionResponseDTO processEvent(FlowIngestDTO dto) {
        // 1. Persist NetworkEvent
        NetworkEvent event = new NetworkEvent();
        event.setDataSource(dto.getDataSource());
        event.setSourceIp(dto.getSrcIp());
        event.setSourcePort(dto.getSrcPort());
        event.setDestinationIp(dto.getDstIp());
        event.setDestinationPort(dto.getDstPort());
        event.setProtocol(dto.getProtocol());
        event.setFlowDuration(dto.getFlowDuration());
        event.setTotalForwardPackets(dto.getTotFwdPkts());
        event.setTotalBackwardPackets(dto.getTotBwdPkts());
        event.setTotalLengthForwardPackets(dto.getTotLenFwdPkts() != null ? dto.getTotLenFwdPkts() : 64.0);
        event.setTotalLengthBackwardPackets(dto.getTotLenBwdPkts() != null ? dto.getTotLenBwdPkts() : 0.0);
        event.setFlowBytesPerSecond(dto.getFlowBytesPerSec());
        event.setFlowPacketsPerSecond(dto.getFlowPacketsPerSec());
        event.setSynFlagCount(dto.getSynFlagCnt());
        event.setAckFlagCount(dto.getAckFlagCnt());
        event.setFinFlagCount(dto.getFinFlagCnt());
        event.setRstFlagCount(dto.getRstFlagCnt());
        event.setPortEntropy(dto.getPortEntropy());
        event.setSimulationRunId(dto.getSimulationRunId());

        double totalPkts = Math.max(1, (dto.getTotFwdPkts() != null ? dto.getTotFwdPkts() : 1) +
                (dto.getTotBwdPkts() != null ? dto.getTotBwdPkts() : 0));
        event.setSynRatio((dto.getSynFlagCnt() != null ? dto.getSynFlagCnt() : 0) / totalPkts);

        NetworkEvent savedEvent = networkEventRepository.save(event);

        // 2. Prepare HTTP REST payload for Python ML Engine
        PythonMLPredictionRequest mlReq = new PythonMLPredictionRequest();
        mlReq.setData_source(dto.getDataSource().name());
        mlReq.setSrc_ip(dto.getSrcIp());
        mlReq.setSrc_port(dto.getSrcPort());
        mlReq.setDst_ip(dto.getDstIp());
        mlReq.setDst_port(dto.getDstPort());
        mlReq.setProtocol(dto.getProtocol());
        mlReq.setFlow_duration(dto.getFlowDuration());
        mlReq.setTot_fwd_pkts(dto.getTotFwdPkts());
        mlReq.setTot_bwd_pkts(dto.getTotBwdPkts());
        mlReq.setTot_len_fwd_pkts(dto.getTotLenFwdPkts() != null ? dto.getTotLenFwdPkts() : 64.0);
        mlReq.setTot_len_bwd_pkts(dto.getTotLenBwdPkts() != null ? dto.getTotLenBwdPkts() : 0.0);
        mlReq.setFlow_bytes_per_sec(dto.getFlowBytesPerSec());
        mlReq.setFlow_packets_per_sec(dto.getFlowPacketsPerSec());
        mlReq.setSyn_flag_cnt(dto.getSynFlagCnt());
        mlReq.setAck_flag_cnt(dto.getAckFlagCnt());
        mlReq.setFin_flag_cnt(dto.getFinFlagCnt());
        mlReq.setRst_flag_cnt(dto.getRstFlagCnt());
        mlReq.setPort_entropy(dto.getPortEntropy());

        Map<String, Object> mergedRaw = new HashMap<>();
        if (dto.getRawFeatures() != null) {
            mergedRaw.putAll(dto.getRawFeatures());
        }
        if (dto.getTotLenFwdPkts() != null) {
            mergedRaw.put("tot_len_fwd_pkts", dto.getTotLenFwdPkts());
        }
        if (dto.getTotLenBwdPkts() != null) {
            mergedRaw.put("tot_len_bwd_pkts", dto.getTotLenBwdPkts());
        }
        mlReq.setRaw_features(mergedRaw);

        // 3. Delegate ML inference exclusively to Python
        PythonMLPredictionResponse mlRes = pythonMLClient.getInference(mlReq);

        // 4. Retrieve current dynamic baseline threshold
        AdaptiveThreshold anomalyThreshold = adaptiveThresholdService.getThreshold("anomaly_score");
        double activeThreshold = anomalyThreshold.getCurrentThreshold();
        boolean mlAnomaly = mlRes.getAnomaly_score() < activeThreshold;
        boolean mlClassTriggered = !"Benign".equalsIgnoreCase(mlRes.getPredicted_class()) && (mlRes.getClass_probability() >= 0.45);

        // 5. Calculate Dynamic Risk Score in Java
        double riskScore = riskScoringService.calculateRiskScore(
                mlRes.getAnomaly_score(),
                activeThreshold,
                mlRes.getPredicted_class(),
                mlRes.getClass_probability(),
                mlRes.getRule_triggered(),
                mlRes.getRule_confidence(),
                dto.getDstIp()
        );
        RiskLevel riskLevel = riskScoringService.determineRiskLevel(riskScore);

        boolean isSuspicious = mlRes.getRule_triggered() || mlAnomaly || mlClassTriggered || riskScore >= 35.0;

        DetectionResult result = new DetectionResult(
                isSuspicious,
                mlRes.getRule_triggered(),
                (mlAnomaly || mlClassTriggered),
                mlRes.getAnomaly_score(),
                mlRes.getPredicted_class(),
                mlRes.getClass_probability(),
                riskScore,
                riskLevel,
                mlRes.getExplanation_narrative()
        );
        result.setRuleName(mlRes.getRule_name());
        result.setFallbackUsed(mlRes.getIs_fallback() != null && mlRes.getIs_fallback());

        // 6. If suspicious, create ThreatAlert and recommended PreventionActions
        ThreatAlert alert = null;
        if (isSuspicious) {
            String attackLabel = !"Benign".equalsIgnoreCase(mlRes.getPredicted_class())
                    ? mlRes.getPredicted_class()
                    : (mlRes.getRule_name() != null ? mlRes.getRule_name() : "Behavioral Anomaly");

            alert = new ThreatAlert(
                    dto.getDataSource(),
                    riskScore,
                    riskLevel,
                    attackLabel,
                    Math.max(mlRes.getClass_probability(), mlRes.getRule_confidence()),
                    dto.getSrcIp(),
                    dto.getDstIp(),
                    dto.getSrcPort(),
                    dto.getDstPort(),
                    dto.getProtocol(),
                    mlRes.getRule_triggered(),
                    (mlAnomaly || mlClassTriggered),
                    mlRes.getExplanation_narrative()
            );
            alert.setAnomalyScore(mlRes.getAnomaly_score());

            // Build Prevention Actions
            String iptablesBlock = "iptables -I INPUT -s " + dto.getSrcIp() + " -j DROP";
            String nftablesBlock = "nft add rule inet filter input ip saddr " + dto.getSrcIp() + " counter drop";
            String script = "# Immediate Containment Command\n" + iptablesBlock + "\n# nftables equivalent:\n" + nftablesBlock;

            PreventionAction blockAction = new PreventionAction(alert, ActionType.BLOCK_IP, dto.getSrcIp(), script);
            alert.addPreventionAction(blockAction);

            if ("DoS_DDoS".equalsIgnoreCase(mlRes.getPredicted_class())) {
                String rateScript = "iptables -A INPUT -p tcp --dport " + dto.getDstPort() + " -m limit --limit 25/minute --limit-burst 100 -j ACCEPT";
                PreventionAction rateAction = new PreventionAction(alert, ActionType.RATE_LIMIT, dto.getSrcIp(), rateScript);
                alert.addPreventionAction(rateAction);
            }

            ThreatAlert savedAlert = threatAlertRepository.save(alert);

            // Escalate critical/high alerts into structured Incidents
            if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.HIGH) {
                incidentManagementService.createIncidentFromAlert(savedAlert);
            }
        }

        return new DetectionResponseDTO(savedEvent, result, alert);
    }

    @Override
    public List<NetworkEvent> getRecentEvents(int limit, DataSource source) {
        if (source != null) {
            return networkEventRepository.findByDataSourceOrderByTimestampDesc(source, PageRequest.of(0, limit)).getContent();
        }
        return networkEventRepository.findTop50ByOrderByTimestampDesc();
    }

    @Override
    public StatsResponseDTO getTelemetryStats() {
        StatsResponseDTO stats = new StatsResponseDTO();
        long total = networkEventRepository.count();
        long observed = networkEventRepository.countByDataSource(DataSource.OBSERVED);
        long simulated = networkEventRepository.countByDataSource(DataSource.SIMULATED);

        stats.setTotalFlowsCaptured(total);
        stats.setObservedFlowsCount(observed);
        stats.setSimulatedFlowsCount(simulated);

        List<NetworkEvent> recent = networkEventRepository.findTop50ByOrderByTimestampDesc();
        if (!recent.isEmpty()) {
            double avgPps = recent.stream().mapToDouble(e -> e.getFlowPacketsPerSecond() != null ? e.getFlowPacketsPerSecond() : 0.0).average().orElse(0.0);
            double avgBps = recent.stream().mapToDouble(e -> e.getFlowBytesPerSecond() != null ? e.getFlowBytesPerSecond() : 0.0).average().orElse(0.0);
            stats.setCurrentPacketRatePps(Math.round(avgPps * 10.0) / 10.0);
            stats.setCurrentBandwidthBps(Math.round(avgBps * 10.0) / 10.0);

            Map<String, Long> protocols = new HashMap<>();
            recent.forEach(e -> {
                String proto = e.getProtocol() != null ? e.getProtocol() : "TCP";
                protocols.put(proto, protocols.getOrDefault(proto, 0L) + 1L);
            });
            stats.setProtocolDistribution(protocols);
        }

        return stats;
    }
}

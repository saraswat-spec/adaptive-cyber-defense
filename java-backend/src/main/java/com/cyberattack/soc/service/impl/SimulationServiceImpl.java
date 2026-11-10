package com.cyberattack.soc.service.impl;

import com.cyberattack.soc.dto.DetectionResponseDTO;
import com.cyberattack.soc.dto.FlowIngestDTO;
import com.cyberattack.soc.dto.SimulationLaunchDTO;
import com.cyberattack.soc.model.SimulationRun;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.repository.SimulationRunRepository;
import com.cyberattack.soc.service.DetectionService;
import com.cyberattack.soc.service.SimulationService;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Service orchestrating red-team attack simulations entirely in-process.
 * Generates synthetic telemetry flows tagged strictly with data_source='SIMULATED',
 * executes them through the DetectionService and ML prediction pipeline,
 * and maintains persistent simulation run lifecycle records in the database.
 */
@Service
public class SimulationServiceImpl implements SimulationService {

    private static final Logger logger = LoggerFactory.getLogger(SimulationServiceImpl.class);

    private final DetectionService detectionService;
    private final SimulationRunRepository simulationRunRepository;
    private final ExecutorService simulationExecutor = Executors.newFixedThreadPool(4);

    private static final List<Map<String, Object>> SCENARIO_TEMPLATES = List.of(
            Map.of(
                    "id", "SYN_FLOOD",
                    "name", "Volumetric SYN Flood (DDoS)",
                    "description", "Exhausts server connection buffers by generating a torrential burst of TCP SYN packets without ACKs.",
                    "category", "Denial of Service",
                    "default_rate_pps", 2500,
                    "default_duration_sec", 5.0,
                    "targeted_ports", List.of(80, 443)
            ),
            Map.of(
                    "id", "PORT_SCAN",
                    "name", "Reconnaissance / TCP Port Scan",
                    "description", "Rapid port sweeps across hundreds of destination endpoints to identify open attack surfaces and running daemons.",
                    "category", "Reconnaissance",
                    "default_rate_pps", 300,
                    "default_duration_sec", 3.0,
                    "targeted_ports", List.of(21, 22, 23, 25, 80, 443, 3306, 8080)
            ),
            Map.of(
                    "id", "BRUTE_FORCE",
                    "name", "Authentication Brute Force",
                    "description", "High-density dictionary credential cycling targeting SSH, FTP, or remote desktop protocols.",
                    "category", "Initial Access",
                    "default_rate_pps", 150,
                    "default_duration_sec", 6.0,
                    "targeted_ports", List.of(22, 21, 3389)
            ),
            Map.of(
                    "id", "WEB_ATTACK",
                    "name", "Web Application Exploit (SQLi / XSS)",
                    "description", "Transmits anomalous, oversized payload buffers containing SQL injection syntax and directory traversal sequences.",
                    "category", "Web Exploitation",
                    "default_rate_pps", 80,
                    "default_duration_sec", 4.0,
                    "targeted_ports", List.of(80, 443, 8080)
            ),
            Map.of(
                    "id", "INFILTRATION_BEACON",
                    "name", "Stealthy C2 Infiltration Beacon",
                    "description", "Low-frequency, highly periodic heartbeats mimicking malware command-and-control communication channels.",
                    "category", "Command & Control",
                    "default_rate_pps", 10,
                    "default_duration_sec", 10.0,
                    "targeted_ports", List.of(443, 8443, 53)
            )
    );

    public SimulationServiceImpl(DetectionService detectionService,
                                 SimulationRunRepository simulationRunRepository) {
        this.detectionService = detectionService;
        this.simulationRunRepository = simulationRunRepository;
    }

    @PreDestroy
    public void shutdownExecutor() {
        simulationExecutor.shutdown();
        try {
            if (!simulationExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                simulationExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            simulationExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public List<Map<String, Object>> getScenarioTemplates() {
        return SCENARIO_TEMPLATES;
    }

    @Override
    @Transactional
    public SimulationRun executeSimulation(SimulationLaunchDTO dto) {
        String runId = UUID.randomUUID().toString();
        SimulationRun run = new SimulationRun(
                runId,
                dto.getScenario(),
                dto.getTargetIp(),
                dto.getTargetPort(),
                dto.getDurationSeconds()
        );
        run = simulationRunRepository.save(run);
        simulationRunRepository.flush();

        final String finalRunId = runId;
        CompletableFuture.runAsync(() -> runSimulationTask(finalRunId, dto), simulationExecutor)
                .exceptionally(throwable -> {
                    // Safety net: if any error escapes the inner try-catch, mark the run FAILED
                    logger.error("Simulation run {} escaped error handler: {}", finalRunId, throwable.getMessage(), throwable);
                    try {
                        markRunFailed(finalRunId, throwable.getMessage());
                    } catch (Exception ex) {
                        logger.error("Failed to mark simulation run {} as FAILED: {}", finalRunId, ex.getMessage());
                    }
                    return null;
                });

        return run;
    }

    @Override
    public List<SimulationRun> getSimulationRuns() {
        return simulationRunRepository.findAllByOrderByStartedAtDesc();
    }

    /**
     * Executes the synthetic simulation lifecycle asynchronously.
     * Each pulse generates a synthetic flow, processes it through the detection engine,
     * and updates the simulation run progress in the database.
     */
    public void runSimulationTask(String runId, SimulationLaunchDTO dto) {
        logger.info("Starting simulation execution runId={}, scenario={}", runId, dto.getScenario());

        int totalPackets = 0;
        int detectedAlerts = 0;
        double duration = dto.getDurationSeconds() != null ? dto.getDurationSeconds() : 3.0;
        int pulses = Math.max(2, (int) Math.round(duration));
        long sleepIntervalMs = Math.min(300, Math.max(50, (long) (duration * 1000 / pulses)));

        try {
            for (int p = 0; p < pulses; p++) {
                FlowIngestDTO flow = buildSyntheticFlow(dto.getScenario(), dto.getTargetIp(), dto.getTargetPort(), runId, p);

                DetectionResponseDTO detectionResponse;
                try {
                    detectionResponse = detectionService.processEvent(flow);
                } catch (Exception detectionEx) {
                    logger.warn("Detection processing failed for pulse {} of run {}: {}", p, runId, detectionEx.getMessage());
                    // Count the flow as injected even if detection fails
                    int fwd = flow.getTotFwdPkts() != null ? flow.getTotFwdPkts() : 0;
                    int bwd = flow.getTotBwdPkts() != null ? flow.getTotBwdPkts() : 0;
                    totalPackets += (fwd + bwd);
                    updateRunProgress(runId, totalPackets, detectedAlerts);
                    continue;
                }

                int fwd = flow.getTotFwdPkts() != null ? flow.getTotFwdPkts() : 0;
                int bwd = flow.getTotBwdPkts() != null ? flow.getTotBwdPkts() : 0;
                totalPackets += (fwd + bwd);

                if (detectionResponse.getThreatAlert() != null) {
                    detectedAlerts++;
                }

                // Update intermediate progress
                updateRunProgress(runId, totalPackets, detectedAlerts);

                try {
                    Thread.sleep(sleepIntervalMs);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            // Mark completed
            markRunCompleted(runId, totalPackets, detectedAlerts);
            logger.info("Simulation run {} COMPLETED successfully. Injected {} packets, detected {} alerts.", runId, totalPackets, detectedAlerts);

        } catch (Exception ex) {
            logger.error("Simulation run {} FAILED with error: {}", runId, ex.getMessage(), ex);
            try {
                markRunFailed(runId, ex.getMessage() != null ? ex.getMessage() : "Unknown simulation error");
            } catch (Exception saveEx) {
                logger.error("Failed to persist FAILED status for run {}: {}", runId, saveEx.getMessage());
            }
        }
    }

    /**
     * Updates intermediate progress (packets injected, alerts detected) for a simulation run.
     * Each update is an independent database transaction to ensure progress is visible
     * to the frontend polling endpoint even while the simulation is still running.
     */
    private void updateRunProgress(String runId, int totalPackets, int detectedAlerts) {
        try {
            simulationRunRepository.findById(runId).ifPresent(run -> {
                run.setTotalPacketsInjected(totalPackets);
                run.setDetectedAlertsCount(detectedAlerts);
                simulationRunRepository.save(run);
            });
        } catch (Exception e) {
            logger.warn("Failed to update progress for run {}: {}", runId, e.getMessage());
        }
    }

    /**
     * Marks a simulation run as COMPLETED with final counts.
     */
    private void markRunCompleted(String runId, int totalPackets, int detectedAlerts) {
        simulationRunRepository.findById(runId).ifPresent(run -> {
            run.setStatus("COMPLETED");
            run.setEndedAt(LocalDateTime.now());
            run.setTotalPacketsInjected(totalPackets);
            run.setDetectedAlertsCount(detectedAlerts);
            simulationRunRepository.save(run);
        });
    }

    /**
     * Marks a simulation run as FAILED with the provided error message.
     */
    private void markRunFailed(String runId, String errorMessage) {
        simulationRunRepository.findById(runId).ifPresent(run -> {
            run.setStatus("FAILED");
            run.setErrorMessage(errorMessage != null ? errorMessage : "Unknown simulation error");
            run.setEndedAt(LocalDateTime.now());
            simulationRunRepository.save(run);
        });
    }

    /**
     * Synthesizes scientifically grounded network flow metrics matching CIC-IDS2017 profiles.
     */
    private FlowIngestDTO buildSyntheticFlow(String scenario, String targetIp, Integer targetPort, String runId, int pulseIndex) {
        String scen = scenario != null ? scenario.trim().toUpperCase().replace("-", "_") : "PORT_SCAN";
        String destIp = (targetIp != null && !targetIp.isBlank()) ? targetIp : "10.0.0.5";

        FlowIngestDTO flow = new FlowIngestDTO();
        flow.setDataSource(DataSource.SIMULATED);
        flow.setSimulationRunId(runId);
        flow.setProtocol("TCP");
        flow.setDstIp(destIp);

        Map<String, Object> raw = new HashMap<>();

        if ("PORT_SCAN".equals(scen)) {
            int[] ports = {21, 22, 23, 25, 80, 443, 3306, 8080};
            int dPort = (targetPort != null && targetPort > 0) ? targetPort : ports[pulseIndex % ports.length];
            flow.setDstPort(dPort);
            flow.setSrcIp("198.51.100." + (40 + (pulseIndex % 20)));
            flow.setSrcPort(40000 + (pulseIndex * 53) % 20000);

            double duration = 0.35 + (pulseIndex * 0.05);
            int fwdPkts = 50 + (pulseIndex * 5);
            int bwdPkts = 5;
            double fwdBytes = fwdPkts * 44.0;
            double bwdBytes = 200.0;

            flow.setFlowDuration(duration);
            flow.setTotFwdPkts(fwdPkts);
            flow.setTotBwdPkts(bwdPkts);
            flow.setTotLenFwdPkts(fwdBytes);
            flow.setTotLenBwdPkts(bwdBytes);
            flow.setFlowBytesPerSec((fwdBytes + bwdBytes) / duration);
            flow.setFlowPacketsPerSec((fwdPkts + bwdPkts) / duration);
            flow.setSynFlagCnt(fwdPkts);
            flow.setAckFlagCnt(0);
            flow.setFinFlagCnt(0);
            flow.setRstFlagCnt(bwdPkts);
            flow.setPortEntropy(0.92);

            raw.put("fwd_iat_mean", duration / fwdPkts);
            raw.put("fwd_iat_std", 0.005);
            raw.put("fwd_iat_max", duration * 0.1);
            raw.put("fwd_iat_min", 0.001);
            raw.put("bwd_iat_mean", 0.01);
            raw.put("bwd_iat_std", 0.005);
            raw.put("bwd_iat_max", 0.02);
            raw.put("bwd_iat_min", 0.001);
            raw.put("fwd_pkt_len_max", 44.0);
            raw.put("fwd_pkt_len_min", 40.0);
            raw.put("fwd_pkt_len_mean", 42.0);
            raw.put("fwd_pkt_len_std", 1.5);
            raw.put("bwd_pkt_len_max", 40.0);
            raw.put("bwd_pkt_len_min", 40.0);
            raw.put("bwd_pkt_len_mean", 40.0);
            raw.put("bwd_pkt_len_std", 0.0);
            raw.put("pkt_len_mean", 42.0);
            raw.put("pkt_len_std", 1.5);
            raw.put("pkt_len_var", 2.25);
            raw.put("psh_flag_cnt", 0);
            raw.put("urg_flag_cnt", 0);
            raw.put("ece_flag_cnt", 0);
            raw.put("down_up_ratio", (double) bwdPkts / fwdPkts);
            raw.put("pkt_size_avg", 42.0);
            raw.put("fwd_seg_size_avg", 42.0);
            raw.put("bwd_seg_size_avg", 40.0);
            raw.put("subflow_fwd_pkts", fwdPkts);
            raw.put("subflow_fwd_bytes", fwdBytes);

        } else if ("SYN_FLOOD".equals(scen)) {
            int dPort = (targetPort != null && targetPort > 0) ? targetPort : 80;
            flow.setDstPort(dPort);
            flow.setSrcIp("203.0.113." + (10 + (pulseIndex % 200)));
            flow.setSrcPort(1024 + (pulseIndex * 97) % 60000);

            double duration = 0.45;
            int fwdPkts = 1500;
            int bwdPkts = 0;
            double fwdBytes = 96000.0;
            double bwdBytes = 0.0;

            flow.setFlowDuration(duration);
            flow.setTotFwdPkts(fwdPkts);
            flow.setTotBwdPkts(bwdPkts);
            flow.setTotLenFwdPkts(fwdBytes);
            flow.setTotLenBwdPkts(bwdBytes);
            flow.setFlowBytesPerSec(fwdBytes / duration);
            flow.setFlowPacketsPerSec((double) fwdPkts / duration);
            flow.setSynFlagCnt(fwdPkts);
            flow.setAckFlagCnt(0);
            flow.setFinFlagCnt(0);
            flow.setRstFlagCnt(0);
            flow.setPortEntropy(0.05);

            raw.put("fwd_iat_mean", duration / fwdPkts);
            raw.put("fwd_iat_std", 0.0001);
            raw.put("fwd_iat_max", duration * 0.05);
            raw.put("fwd_iat_min", 0.00001);
            raw.put("bwd_iat_mean", 0.0);
            raw.put("bwd_iat_std", 0.0);
            raw.put("bwd_iat_max", 0.0);
            raw.put("bwd_iat_min", 0.0);
            raw.put("fwd_pkt_len_max", 128.0);
            raw.put("fwd_pkt_len_min", 40.0);
            raw.put("fwd_pkt_len_mean", 64.0);
            raw.put("fwd_pkt_len_std", 10.0);
            raw.put("bwd_pkt_len_max", 0.0);
            raw.put("bwd_pkt_len_min", 0.0);
            raw.put("bwd_pkt_len_mean", 0.0);
            raw.put("bwd_pkt_len_std", 0.0);
            raw.put("pkt_len_mean", 64.0);
            raw.put("pkt_len_std", 8.0);
            raw.put("pkt_len_var", 64.0);
            raw.put("psh_flag_cnt", 0);
            raw.put("urg_flag_cnt", 0);
            raw.put("ece_flag_cnt", 0);
            raw.put("down_up_ratio", 0.0);
            raw.put("pkt_size_avg", 64.0);
            raw.put("fwd_seg_size_avg", 64.0);
            raw.put("bwd_seg_size_avg", 0.0);
            raw.put("subflow_fwd_pkts", fwdPkts);
            raw.put("subflow_fwd_bytes", fwdBytes);

        } else if ("BRUTE_FORCE".equals(scen)) {
            int dPort = (targetPort != null && targetPort > 0) ? targetPort : 22;
            flow.setDstPort(dPort);
            flow.setSrcIp("198.51.100." + (120 + (pulseIndex % 80)));
            flow.setSrcPort(30000 + (pulseIndex * 89) % 30000);

            double duration = 4.5;
            int fwdPkts = 60;
            int bwdPkts = 50;
            double fwdBytes = 7200.0;
            double bwdBytes = 5500.0;

            flow.setFlowDuration(duration);
            flow.setTotFwdPkts(fwdPkts);
            flow.setTotBwdPkts(bwdPkts);
            flow.setTotLenFwdPkts(fwdBytes);
            flow.setTotLenBwdPkts(bwdBytes);
            flow.setFlowBytesPerSec((fwdBytes + bwdBytes) / duration);
            flow.setFlowPacketsPerSec((fwdPkts + bwdPkts) / duration);
            flow.setSynFlagCnt(10);
            flow.setAckFlagCnt(105);
            flow.setFinFlagCnt(5);
            flow.setRstFlagCnt(2);
            flow.setPortEntropy(0.04);

            raw.put("fwd_iat_mean", duration / fwdPkts);
            raw.put("fwd_iat_std", 0.05);
            raw.put("fwd_iat_max", 0.8);
            raw.put("fwd_iat_min", 0.01);
            raw.put("bwd_iat_mean", duration / bwdPkts);
            raw.put("bwd_iat_std", 0.05);
            raw.put("bwd_iat_max", 0.8);
            raw.put("bwd_iat_min", 0.01);
            raw.put("fwd_pkt_len_max", 250.0);
            raw.put("fwd_pkt_len_min", 40.0);
            raw.put("fwd_pkt_len_mean", 120.0);
            raw.put("fwd_pkt_len_std", 45.0);
            raw.put("bwd_pkt_len_max", 200.0);
            raw.put("bwd_pkt_len_min", 40.0);
            raw.put("bwd_pkt_len_mean", 110.0);
            raw.put("bwd_pkt_len_std", 35.0);
            raw.put("pkt_len_mean", 115.0);
            raw.put("pkt_len_std", 40.0);
            raw.put("pkt_len_var", 1600.0);
            raw.put("psh_flag_cnt", 25);
            raw.put("urg_flag_cnt", 0);
            raw.put("ece_flag_cnt", 0);
            raw.put("down_up_ratio", (double) bwdPkts / fwdPkts);
            raw.put("pkt_size_avg", 115.0);
            raw.put("fwd_seg_size_avg", 120.0);
            raw.put("bwd_seg_size_avg", 110.0);
            raw.put("subflow_fwd_pkts", fwdPkts);
            raw.put("subflow_fwd_bytes", fwdBytes);

        } else if ("WEB_ATTACK".equals(scen)) {
            int dPort = (targetPort != null && targetPort > 0) ? targetPort : 80;
            flow.setDstPort(dPort);
            flow.setSrcIp("198.51.100." + (10 + (pulseIndex % 30)));
            flow.setSrcPort(32000 + (pulseIndex * 71) % 25000);

            double duration = 1.8;
            int fwdPkts = 15;
            int bwdPkts = 12;
            double fwdBytes = 3200.0;
            double bwdBytes = 5400.0;

            flow.setFlowDuration(duration);
            flow.setTotFwdPkts(fwdPkts);
            flow.setTotBwdPkts(bwdPkts);
            flow.setTotLenFwdPkts(fwdBytes);
            flow.setTotLenBwdPkts(bwdBytes);
            flow.setFlowBytesPerSec((fwdBytes + bwdBytes) / duration);
            flow.setFlowPacketsPerSec((fwdPkts + bwdPkts) / duration);
            flow.setSynFlagCnt(1);
            flow.setAckFlagCnt(26);
            flow.setFinFlagCnt(1);
            flow.setRstFlagCnt(0);
            flow.setPortEntropy(0.10);

            raw.put("fwd_iat_mean", duration / fwdPkts);
            raw.put("fwd_iat_std", 0.02);
            raw.put("fwd_iat_max", duration * 0.4);
            raw.put("fwd_iat_min", 0.005);
            raw.put("bwd_iat_mean", duration / bwdPkts);
            raw.put("bwd_iat_std", 0.02);
            raw.put("bwd_iat_max", duration * 0.3);
            raw.put("bwd_iat_min", 0.005);
            raw.put("fwd_pkt_len_max", 2100.0);
            raw.put("fwd_pkt_len_min", 40.0);
            raw.put("fwd_pkt_len_mean", fwdBytes / fwdPkts);
            raw.put("fwd_pkt_len_std", 350.0);
            raw.put("bwd_pkt_len_max", 800.0);
            raw.put("bwd_pkt_len_min", 40.0);
            raw.put("bwd_pkt_len_mean", 450.0);
            raw.put("bwd_pkt_len_std", 120.0);
            raw.put("pkt_len_mean", (fwdBytes + bwdBytes) / (fwdPkts + bwdPkts));
            raw.put("pkt_len_std", 250.0);
            raw.put("pkt_len_var", 62500.0);
            raw.put("psh_flag_cnt", 5);
            raw.put("urg_flag_cnt", 0);
            raw.put("ece_flag_cnt", 0);
            raw.put("down_up_ratio", (double) bwdPkts / fwdPkts);
            raw.put("pkt_size_avg", (fwdBytes + bwdBytes) / (fwdPkts + bwdPkts));
            raw.put("fwd_seg_size_avg", fwdBytes / fwdPkts);
            raw.put("bwd_seg_size_avg", 450.0);
            raw.put("subflow_fwd_pkts", fwdPkts);
            raw.put("subflow_fwd_bytes", fwdBytes);

        } else { // INFILTRATION_BEACON
            int dPort = (targetPort != null && targetPort > 0) ? targetPort : 443;
            flow.setDstPort(dPort);
            flow.setSrcIp("10.0.0.10");
            flow.setSrcPort(49152 + (pulseIndex * 31) % 15000);

            double duration = 30.0;
            int fwdPkts = 8;
            int bwdPkts = 8;
            double fwdBytes = 640.0;
            double bwdBytes = 640.0;

            flow.setFlowDuration(duration);
            flow.setTotFwdPkts(fwdPkts);
            flow.setTotBwdPkts(bwdPkts);
            flow.setTotLenFwdPkts(fwdBytes);
            flow.setTotLenBwdPkts(bwdBytes);
            flow.setFlowBytesPerSec((fwdBytes + bwdBytes) / duration);
            flow.setFlowPacketsPerSec((fwdPkts + bwdPkts) / duration);
            flow.setSynFlagCnt(1);
            flow.setAckFlagCnt(15);
            flow.setFinFlagCnt(1);
            flow.setRstFlagCnt(0);
            flow.setPortEntropy(0.02);

            raw.put("fwd_iat_mean", duration / fwdPkts);
            raw.put("fwd_iat_std", 0.01);
            raw.put("fwd_iat_max", 4.0);
            raw.put("fwd_iat_min", 3.0);
            raw.put("bwd_iat_mean", duration / bwdPkts);
            raw.put("bwd_iat_std", 0.01);
            raw.put("bwd_iat_max", 4.0);
            raw.put("bwd_iat_min", 3.0);
            raw.put("fwd_pkt_len_max", 80.0);
            raw.put("fwd_pkt_len_min", 80.0);
            raw.put("fwd_pkt_len_mean", 80.0);
            raw.put("fwd_pkt_len_std", 0.0);
            raw.put("bwd_pkt_len_max", 80.0);
            raw.put("bwd_pkt_len_min", 80.0);
            raw.put("bwd_pkt_len_mean", 80.0);
            raw.put("bwd_pkt_len_std", 0.0);
            raw.put("pkt_len_mean", 80.0);
            raw.put("pkt_len_std", 0.0);
            raw.put("pkt_len_var", 0.0);
            raw.put("psh_flag_cnt", 4);
            raw.put("urg_flag_cnt", 0);
            raw.put("ece_flag_cnt", 0);
            raw.put("down_up_ratio", 1.0);
            raw.put("pkt_size_avg", 80.0);
            raw.put("fwd_seg_size_avg", 80.0);
            raw.put("bwd_seg_size_avg", 80.0);
            raw.put("subflow_fwd_pkts", fwdPkts);
            raw.put("subflow_fwd_bytes", fwdBytes);
        }

        flow.setRawFeatures(raw);
        return flow;
    }
}

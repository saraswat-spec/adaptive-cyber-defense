package com.cyberattack.soc;

import com.cyberattack.soc.controller.*;
import com.cyberattack.soc.dto.*;
import com.cyberattack.soc.model.*;
import com.cyberattack.soc.model.enums.*;
import com.cyberattack.soc.repository.*;
import com.cyberattack.soc.service.AdaptiveThresholdService;
import com.cyberattack.soc.service.DetectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * PROMPT 5: Complete Application, Database Integration, and End-to-End Test Suite.
 * Verifies all 7 JPA entities, 5 controllers, REST endpoints, fallback resilience,
 * and data integrity guarantees.
 */
@SpringBootTest
public class CompleteSystemVerificationTest {

    @Autowired
    private DetectionController detectionController;

    @Autowired
    private AlertController alertController;

    @Autowired
    private IncidentController incidentController;

    @Autowired
    private SimulationController simulationController;

    @Autowired
    private FeedbackController feedbackController;

    @Autowired
    private ModelAnalyticsController modelAnalyticsController;

    @Autowired
    private DetectionService detectionService;

    @Autowired
    private AdaptiveThresholdService adaptiveThresholdService;

    @Autowired
    private NetworkEventRepository networkEventRepository;

    @Autowired
    private ThreatAlertRepository threatAlertRepository;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private AnalystFeedbackRepository analystFeedbackRepository;

    @Autowired
    private PreventionActionRepository preventionActionRepository;

    @Autowired
    private AdaptiveThresholdRepository adaptiveThresholdRepository;

    @Autowired
    private SimulationRunRepository simulationRunRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = MockRestServiceServer.createServer(restTemplate);
        adaptiveThresholdService.initializeDefaultThresholdsIfEmpty();
        adaptiveThresholdService.setMinFeedbackSamples(2);
    }

    // =========================================================================
    // SECTION 1: DATABASE VERIFICATION (All 7 JPA Entities & Repositories)
    // =========================================================================
    @Test
    @DisplayName("Section 1: Database Entities & Foreign Key Relationships Verification")
    public void testDatabaseEntitiesAndRelationships() {
        // 1. NetworkEvent entity persistence & provenance
        NetworkEvent event = new NetworkEvent(DataSource.OBSERVED, "192.168.1.50", 55210, "10.0.0.5", 80, "TCP");
        event.setTotalForwardPackets(10);
        event.setTotalBackwardPackets(8);
        event.setFlowDuration(1.2);
        NetworkEvent savedEvent = networkEventRepository.save(event);
        assertNotNull(savedEvent.getId());
        assertEquals(DataSource.OBSERVED, savedEvent.getDataSource());

        // 2. ThreatAlert with cascade PreventionAction and Incident relationship
        ThreatAlert alert = new ThreatAlert(
                DataSource.SIMULATED,
                88.5,
                RiskLevel.CRITICAL,
                "SYN_FLOOD",
                0.95,
                "203.0.113.15",
                "10.0.0.5",
                49152,
                80,
                "TCP",
                true,
                true,
                "Volumetric SYN buffer exhaustion detected."
        );
        PreventionAction action = new PreventionAction(
                alert,
                ActionType.BLOCK_IP,
                "203.0.113.15",
                "iptables -I INPUT -s 203.0.113.15 -j DROP"
        );
        alert.addPreventionAction(action);
        ThreatAlert savedAlert = threatAlertRepository.save(alert);
        assertNotNull(savedAlert.getId());
        assertEquals(1, savedAlert.getPreventionActions().size());

        // Verify Cascade and Foreign Key to PreventionAction
        List<PreventionAction> actions = preventionActionRepository.findByThreatAlertId(savedAlert.getId());
        assertEquals(1, actions.size());
        assertEquals("203.0.113.15", actions.get(0).getTargetIp());

        // 3. Incident relationship
        Incident incident = new Incident("Critical Attack Cluster on 10.0.0.5", IncidentSeverity.CRITICAL, "SOC Automation");
        incident.addAlert(savedAlert);
        Incident savedIncident = incidentRepository.save(incident);
        assertNotNull(savedIncident.getId());
        assertEquals(IncidentStatus.OPEN, savedIncident.getStatus());
        assertEquals(1, savedIncident.getAlerts().size());

        // 4. AnalystFeedback persistence
        AnalystFeedback feedback = new AnalystFeedback(
                savedAlert.getId(),
                FeedbackType.CONFIRMED_THREAT,
                "Analyst confirmed malicious volumetric flood",
                false
        );
        AnalystFeedback savedFeedback = analystFeedbackRepository.save(feedback);
        assertNotNull(savedFeedback.getId());
        assertEquals(savedAlert.getId(), savedFeedback.getAlertId());
        assertFalse(savedFeedback.getThresholdAdjusted());

        // 5. AdaptiveThreshold repository operations
        AdaptiveThreshold threshold = adaptiveThresholdRepository.findById("anomaly_score").orElseThrow();
        assertNotNull(threshold.getCurrentThreshold());
        assertNotNull(threshold.getBaselineMean());
        assertNotNull(threshold.getBaselineStd());

        // 6. SimulationRun entity lifecycle
        SimulationRun run = new SimulationRun(
                UUID.randomUUID().toString(),
                "PORT_SCAN",
                "10.0.0.5",
                21,
                3.0
        );
        run.setTotalPacketsInjected(150);
        run.setStatus("COMPLETED");
        SimulationRun savedRun = simulationRunRepository.save(run);
        assertNotNull(savedRun.getId());
        assertEquals("COMPLETED", savedRun.getStatus());
    }

    // =========================================================================
    // SECTION 2: REST API ENDPOINTS TESTING
    // =========================================================================
    @Test
    @DisplayName("Section 2: Complete REST API Endpoints Verification")
    public void testAllRestEndpoints() {
        // Mock Python ML endpoints called by baseline & models controllers
        mockServer.expect(ExpectedCount.between(0, 5), requestTo("http://localhost:8000/api/v1/adaptive/baseline"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"status\":\"ACTIVE\",\"total_baseline_flows\":7000}", MediaType.APPLICATION_JSON));

        mockServer.expect(ExpectedCount.between(0, 5), requestTo("http://localhost:8000/api/v1/models/analytics"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"accuracy\":0.9995,\"status\":\"HEALTHY\"}", MediaType.APPLICATION_JSON));

        mockServer.expect(ExpectedCount.between(0, 5), requestTo("http://localhost:8000/api/v1/models/features"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("[{\"feature\":\"flow_duration\",\"importance\":0.18}]", MediaType.APPLICATION_JSON));

        // --- A. Telemetry Endpoints ---
        ResponseEntity<StatsResponseDTO> statsRes = detectionController.getTelemetryStats();
        assertEquals(HttpStatus.OK, statsRes.getStatusCode());
        assertNotNull(statsRes.getBody());

        ResponseEntity<List<NetworkEvent>> flowsRes = detectionController.getFlows(10, 0, "ALL");
        assertEquals(HttpStatus.OK, flowsRes.getStatusCode());
        assertNotNull(flowsRes.getBody());

        // --- B. Alerts Endpoints ---
        ResponseEntity<List<ThreatAlert>> alertsRes = alertController.getAlerts(null, null, "ALL", 20);
        assertEquals(HttpStatus.OK, alertsRes.getStatusCode());
        assertNotNull(alertsRes.getBody());

        if (!alertsRes.getBody().isEmpty()) {
            UUID testAlertId = alertsRes.getBody().get(0).getId();
            ResponseEntity<ThreatAlert> singleAlertRes = alertController.getAlertById(testAlertId);
            assertEquals(HttpStatus.OK, singleAlertRes.getStatusCode());
            assertNotNull(singleAlertRes.getBody());

            // Status PATCH endpoint
            ResponseEntity<ThreatAlert> patchStatusRes = alertController.updateAlertStatus(
                    testAlertId,
                    Map.of("status", "INVESTIGATING")
            );
            assertEquals(HttpStatus.OK, patchStatusRes.getStatusCode());
            assertEquals(AlertStatus.INVESTIGATING, patchStatusRes.getBody().getStatus());

            // Mitigation simulation endpoint
            MitigationRequestDTO mitReq = new MitigationRequestDTO();
            mitReq.setActionType(ActionType.BLOCK_IP);
            mitReq.setExecutionMode("SIMULATED");
            ResponseEntity<Map<String, Object>> mitRes = alertController.executeMitigation(testAlertId, mitReq);
            assertEquals(HttpStatus.OK, mitRes.getStatusCode());
            assertTrue((Boolean) mitRes.getBody().get("success"));
        }

        // --- C. Incidents Endpoints ---
        ResponseEntity<List<Incident>> incidentsRes = incidentController.getAllIncidents(null, null);
        assertEquals(HttpStatus.OK, incidentsRes.getStatusCode());
        assertNotNull(incidentsRes.getBody());

        if (!incidentsRes.getBody().isEmpty()) {
            UUID incidentId = incidentsRes.getBody().get(0).getId();
            ResponseEntity<Incident> patchIncRes = incidentController.updateIncidentStatus(
                    incidentId,
                    Map.of("status", "INVESTIGATING", "notes", "SOC investigation in progress")
            );
            assertEquals(HttpStatus.OK, patchIncRes.getStatusCode());
            assertEquals(IncidentStatus.INVESTIGATING, patchIncRes.getBody().getStatus());
        }

        // --- D. Simulation Endpoints ---
        ResponseEntity<List<Map<String, Object>>> scenariosRes = simulationController.getScenarios();
        assertEquals(HttpStatus.OK, scenariosRes.getStatusCode());
        assertEquals(5, scenariosRes.getBody().size());

        ResponseEntity<List<SimulationRun>> runsRes = simulationController.getSimulationRuns();
        assertEquals(HttpStatus.OK, runsRes.getStatusCode());
        assertNotNull(runsRes.getBody());

        // --- E. Adaptive Endpoints ---
        ResponseEntity<List<AdaptiveThreshold>> thresholdsRes = feedbackController.getThresholds();
        assertEquals(HttpStatus.OK, thresholdsRes.getStatusCode());
        assertEquals(4, thresholdsRes.getBody().size());

        ResponseEntity<Map<String, Object>> baselineRes = feedbackController.getBaselineProfile();
        assertEquals(HttpStatus.OK, baselineRes.getStatusCode());
        assertNotNull(baselineRes.getBody());

        // Threshold calibration PATCH endpoint
        CalibrationRequestDTO calReq = new CalibrationRequestDTO();
        calReq.setAnomalySensitivityFactor(1.10);
        ResponseEntity<List<AdaptiveThreshold>> calRes = feedbackController.calibrateThresholds(calReq);
        assertEquals(HttpStatus.OK, calRes.getStatusCode());
        assertNotNull(calRes.getBody());

        // --- F. Model Analytics Proxy Endpoints ---
        ResponseEntity<Map<String, Object>> analyticsRes = modelAnalyticsController.getModelAnalytics();
        assertEquals(HttpStatus.OK, analyticsRes.getStatusCode());
        assertNotNull(analyticsRes.getBody());

        ResponseEntity<List<Map<String, Object>>> featuresRes = modelAnalyticsController.getFeatureImportances();
        assertEquals(HttpStatus.OK, featuresRes.getStatusCode());
        assertNotNull(featuresRes.getBody());
    }

    // =========================================================================
    // SECTION 3: END-TO-END WORKFLOW (Ingest -> ML -> Alert -> Mitigation -> Feedback)
    // =========================================================================
    @Test
    @DisplayName("Section 3 & 4: Full End-to-End Workflow with ML Mock & Data Integrity")
    public void testFullEndToEndWorkflow() {
        // 1. Mock Python ML Service for incoming PortScan attack flow
        String mockPythonResponse = """
            {
                "anomaly_score": -0.2100,
                "predicted_class": "PortScan",
                "class_probability": 0.99,
                "rule_triggered": true,
                "rule_name": "RULE_PORT_SCAN_HIGH_ENTROPY",
                "rule_confidence": 0.92,
                "explanation_narrative": "Severe multi-port dispersion detected across network boundary.",
                "top_features": [],
                "is_fallback": false
            }
            """;

        mockServer.expect(requestTo("http://localhost:8000/api/v1/ml/predict"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(mockPythonResponse, MediaType.APPLICATION_JSON));

        // 2. Submit suspicious PortScan network telemetry
        FlowIngestDTO dto = new FlowIngestDTO();
        dto.setDataSource(DataSource.SIMULATED);
        dto.setSrcIp("198.51.100.88");
        dto.setSrcPort(45000);
        dto.setDstIp("10.0.0.5");
        dto.setDstPort(22);
        dto.setProtocol("TCP");
        dto.setFlowDuration(0.5);
        dto.setTotFwdPkts(60);
        dto.setTotBwdPkts(5);
        dto.setTotLenFwdPkts(2640.0);
        dto.setTotLenBwdPkts(200.0);
        dto.setFlowBytesPerSec(5680.0);
        dto.setFlowPacketsPerSec(130.0);
        dto.setSynFlagCnt(60);
        dto.setAckFlagCnt(0);
        dto.setFinFlagCnt(0);
        dto.setRstFlagCnt(5);
        dto.setPortEntropy(0.92);

        // 3. Process flow through Java Detection Pipeline
        DetectionResponseDTO detectionRes = detectionService.processEvent(dto);

        // Verify ML predictions & Dynamic Risk Scoring in Java
        assertNotNull(detectionRes);
        assertNotNull(detectionRes.getNetworkEvent());
        assertEquals(DataSource.SIMULATED, detectionRes.getNetworkEvent().getDataSource());
        assertNotNull(detectionRes.getDetectionResult());
        assertTrue(detectionRes.getDetectionResult().isSuspicious());
        assertEquals("PortScan", detectionRes.getDetectionResult().getPredictedAttackClass());
        assertTrue(detectionRes.getDetectionResult().getDynamicRiskScore() >= 60.0);

        // Verify Threat Alert was created
        ThreatAlert alert = detectionRes.getThreatAlert();
        assertNotNull(alert, "A threat alert must be generated for suspicious PortScan traffic");
        assertTrue(alert.getRiskScore() >= 60.0);
        assertEquals(RiskLevel.CRITICAL, alert.getRiskLevel());

        // Verify Incident Escalation for CRITICAL risk alert
        List<Incident> incidents = incidentRepository.findAll();
        boolean incidentFound = incidents.stream()
                .anyMatch(i -> i.getTitle().contains("PortScan") && i.getSeverity() == IncidentSeverity.CRITICAL);
        assertTrue(incidentFound, "Critical risk alert must be automatically escalated to an Incident");

        // Verify Prevention Actions generated with firewall script
        List<PreventionAction> actions = alert.getPreventionActions();
        assertFalse(actions.isEmpty(), "Prevention actions should be automatically synthesized");
        assertTrue(actions.get(0).getGeneratedScript().contains("iptables -I INPUT -s 198.51.100.88 -j DROP"));
        assertTrue(actions.get(0).getGeneratedScript().contains("nft add rule"));

        // Verify Simulated Dry-Run containment execution
        Map<String, Object> execRes = alertController.executeMitigation(alert.getId(), new MitigationRequestDTO()).getBody();
        assertNotNull(execRes);
        assertTrue((Boolean) execRes.get("success"));

        // Verify Analyst Feedback with CONFIRMED_THREAT preserves baseline
        FeedbackRequestDTO feedbackReq = new FeedbackRequestDTO();
        feedbackReq.setFeedbackType(FeedbackType.CONFIRMED_THREAT);
        feedbackReq.setAnalystNotes("Validated critical port reconnaissance sweep");
        feedbackReq.setAdjustThreshold(true);

        ResponseEntity<Map<String, Object>> fbRes = feedbackController.submitFeedback(alert.getId(), feedbackReq);
        assertEquals(HttpStatus.CREATED, fbRes.getStatusCode());
        assertEquals(false, fbRes.getBody().get("threshold_adjusted"));
        assertEquals("Threat confirmed. Threat intelligence profile updated; baseline thresholds preserved.", fbRes.getBody().get("message"));

        // Verify alert status updated to INVESTIGATING
        ThreatAlert reloadedAlert = threatAlertRepository.findById(alert.getId()).orElseThrow();
        assertEquals(AlertStatus.INVESTIGATING, reloadedAlert.getStatus());
    }

    // =========================================================================
    // SECTION 3.14: PYTHON SERVICE OUTAGE RESILIENCE & HEURISTIC FALLBACK
    // =========================================================================
    @Test
    @DisplayName("Section 3.14: Python Service Outage Fallback Test")
    public void testPythonServiceOutageHeuristicFallback() {
        // Mock Python service failure (HTTP 503)
        mockServer.expect(requestTo("http://localhost:8000/api/v1/ml/predict"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServerError());

        FlowIngestDTO dto = new FlowIngestDTO();
        dto.setDataSource(DataSource.SIMULATED);
        dto.setSrcIp("198.51.100.99");
        dto.setSrcPort(33333);
        dto.setDstIp("10.0.0.5");
        dto.setDstPort(80);
        dto.setProtocol("TCP");
        dto.setFlowDuration(1.0);
        dto.setTotFwdPkts(150);
        dto.setTotBwdPkts(0);
        dto.setSynFlagCnt(150); // Severe SYN flood to trigger heuristic fallback rule
        dto.setAckFlagCnt(0);
        dto.setPortEntropy(0.05);

        DetectionResponseDTO response = detectionService.processEvent(dto);

        assertNotNull(response);
        assertNotNull(response.getDetectionResult());
        assertTrue(response.getDetectionResult().isFallbackUsed(), "DetectionResult must indicate fallback_used=true");
        assertTrue(response.getDetectionResult().isSuspicious());
        assertEquals("DoS_DDoS", response.getDetectionResult().getPredictedAttackClass());
        assertTrue(response.getDetectionResult().getExplanationNarrative().contains("HEURISTIC FALLBACK"));

        // Verify fallback alert was still successfully created and saved in the database
        assertNotNull(response.getThreatAlert());
        assertEquals(DataSource.SIMULATED, response.getThreatAlert().getDataSource());
    }

    // =========================================================================
    // SECTION 4: DATA PROVENANCE PRESERVATION
    // =========================================================================
    @Test
    @DisplayName("Section 4: Provenance Tagging Guarantees")
    public void testDataProvenanceIntegrity() {
        // 1. SIMULATED events remain SIMULATED
        NetworkEvent simEvent = new NetworkEvent(DataSource.SIMULATED, "10.0.0.20", 1234, "10.0.0.5", 80, "TCP");
        NetworkEvent savedSim = networkEventRepository.save(simEvent);
        assertEquals(DataSource.SIMULATED, savedSim.getDataSource());

        // 2. OBSERVED events remain OBSERVED
        NetworkEvent obsEvent = new NetworkEvent(DataSource.OBSERVED, "172.16.0.4", 5555, "10.0.0.5", 443, "TCP");
        NetworkEvent savedObs = networkEventRepository.save(obsEvent);
        assertEquals(DataSource.OBSERVED, savedObs.getDataSource());

        // 3. DATASET events remain DATASET
        NetworkEvent datasetEvent = new NetworkEvent(DataSource.DATASET, "192.168.10.50", 8080, "10.0.0.5", 80, "TCP");
        NetworkEvent savedDs = networkEventRepository.save(datasetEvent);
        assertEquals(DataSource.DATASET, savedDs.getDataSource());

        // Counts verify provenance separation
        long simCount = networkEventRepository.countByDataSource(DataSource.SIMULATED);
        long obsCount = networkEventRepository.countByDataSource(DataSource.OBSERVED);
        long dsCount = networkEventRepository.countByDataSource(DataSource.DATASET);

        assertTrue(simCount > 0);
        assertTrue(obsCount > 0);
        assertTrue(dsCount > 0);
    }
}

package com.cyberattack.soc;

import com.cyberattack.soc.dto.SimulationLaunchDTO;
import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.SimulationRun;
import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.repository.NetworkEventRepository;
import com.cyberattack.soc.repository.SimulationRunRepository;
import com.cyberattack.soc.repository.ThreatAlertRepository;
import com.cyberattack.soc.service.SimulationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@SpringBootTest
public class SimulationIntegrationTest {

    @Autowired
    private SimulationService simulationService;

    @Autowired
    private SimulationRunRepository simulationRunRepository;

    @Autowired
    private NetworkEventRepository networkEventRepository;

    @Autowired
    private ThreatAlertRepository threatAlertRepository;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer mockServer;

    @BeforeEach
    public void setup() {
        mockServer = MockRestServiceServer.createServer(restTemplate);
    }

    @Test
    public void testPortScanSimulationLifecycleAndDetection() throws InterruptedException {
        // Mock Python ML response for PortScan predictions
        String pythonResponseJson = """
            {
                "anomaly_score": -0.1850,
                "predicted_class": "PortScan",
                "class_probability": 0.98,
                "rule_triggered": true,
                "rule_name": "RULE_PORT_SCAN_HIGH_ENTROPY",
                "rule_confidence": 0.92,
                "explanation_narrative": "Active reconnaissance port sweep pattern identified.",
                "top_features": [],
                "is_fallback": false
            }
            """;

        mockServer.expect(ExpectedCount.between(1, 20), requestTo("http://localhost:8000/api/v1/ml/predict"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(pythonResponseJson, MediaType.APPLICATION_JSON));

        // 1. Launch a PORT_SCAN simulation run
        SimulationLaunchDTO dto = new SimulationLaunchDTO();
        dto.setScenario("PORT_SCAN");
        dto.setTargetIp("10.0.0.5");
        dto.setTargetPort(21);
        dto.setDurationSeconds(2.0);
        dto.setPacketRatePps(300);

        SimulationRun initialRun = simulationService.executeSimulation(dto);

        // Verify initial state
        assertNotNull(initialRun);
        assertNotNull(initialRun.getId());
        assertEquals("PORT_SCAN", initialRun.getScenarioName());
        assertEquals("10.0.0.5", initialRun.getTargetIp());
        assertEquals(21, initialRun.getTargetPort());
        assertEquals("RUNNING", initialRun.getStatus());
        assertNotNull(initialRun.getStartedAt());
        assertNull(initialRun.getEndedAt());

        String runId = initialRun.getId();

        // 2. Poll until asynchronous execution completes (up to 15 seconds)
        SimulationRun completedRun = null;
        for (int i = 0; i < 100; i++) {
            Thread.sleep(150);
            SimulationRun current = simulationRunRepository.findById(runId).orElse(null);
            if (current != null && ("COMPLETED".equals(current.getStatus()) || "FAILED".equals(current.getStatus()))) {
                completedRun = current;
                break;
            }
        }

        // 3. Verify final completed state
        assertNotNull(completedRun, "Simulation run should transition from RUNNING to a terminal state (COMPLETED or FAILED)");

        if ("FAILED".equals(completedRun.getStatus())) {
            fail("Simulation run FAILED with error: " + completedRun.getErrorMessage());
        }

        assertEquals("COMPLETED", completedRun.getStatus());
        assertNotNull(completedRun.getEndedAt(), "ended_at must be set on completion");
        assertTrue(completedRun.getEndedAt().isAfter(completedRun.getStartedAt()) || completedRun.getEndedAt().isEqual(completedRun.getStartedAt()),
                "ended_at must be >= started_at");
        assertTrue(completedRun.getTotalPacketsInjected() > 0, "Packets injected count should be greater than zero, was: " + completedRun.getTotalPacketsInjected());
        assertTrue(completedRun.getDetectedAlertsCount() > 0, "Detected alerts count should be greater than zero, was: " + completedRun.getDetectedAlertsCount());

        // 4. Verify synthetic events reached DetectionService & database
        List<NetworkEvent> events = networkEventRepository.findAll();
        List<NetworkEvent> runEvents = events.stream()
                .filter(e -> runId.equals(e.getSimulationRunId()))
                .toList();
        assertFalse(runEvents.isEmpty(), "Simulation network events must be persisted");
        for (NetworkEvent event : runEvents) {
            assertEquals(DataSource.SIMULATED, event.getDataSource(), "All simulation events must be tagged SIMULATED");
            assertEquals("10.0.0.5", event.getDestinationIp());
            assertTrue(event.getTotalForwardPackets() > 0);
        }

        // 5. Verify ThreatAlerts were recorded
        List<ThreatAlert> alerts = threatAlertRepository.findAll();
        List<ThreatAlert> runAlerts = alerts.stream()
                .filter(a -> a.getAttackType() != null && a.getAttackType().contains("PortScan"))
                .toList();
        assertFalse(runAlerts.isEmpty(), "Threat alerts should be generated from PortScan simulation");

        System.out.println("=== SIMULATION INTEGRATION TEST RESULTS ===");
        System.out.println("Run ID:            " + completedRun.getId());
        System.out.println("Scenario:          " + completedRun.getScenarioName());
        System.out.println("Status:            " + completedRun.getStatus());
        System.out.println("Packets Injected:  " + completedRun.getTotalPacketsInjected());
        System.out.println("Alerts Detected:   " + completedRun.getDetectedAlertsCount());
        System.out.println("Events Persisted:  " + runEvents.size());
        System.out.println("Threat Alerts:     " + runAlerts.size());
        System.out.println("Started At:        " + completedRun.getStartedAt());
        System.out.println("Ended At:          " + completedRun.getEndedAt());
        System.out.println("All events SIMULATED: true");
        System.out.println("============================================");
    }
}

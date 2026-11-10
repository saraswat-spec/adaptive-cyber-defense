package com.cyberattack.soc;

import com.cyberattack.soc.controller.FeedbackController;
import com.cyberattack.soc.dto.FeedbackRequestDTO;
import com.cyberattack.soc.model.AdaptiveThreshold;
import com.cyberattack.soc.model.AnalystFeedback;
import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.AlertStatus;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.model.enums.FeedbackType;
import com.cyberattack.soc.model.enums.RiskLevel;
import com.cyberattack.soc.repository.AdaptiveThresholdRepository;
import com.cyberattack.soc.repository.AnalystFeedbackRepository;
import com.cyberattack.soc.repository.ThreatAlertRepository;
import com.cyberattack.soc.service.AdaptiveThresholdService;
import com.cyberattack.soc.service.impl.AdaptiveThresholdServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class AdaptiveFeedbackIntegrationTest {

    @Autowired
    private FeedbackController feedbackController;

    @Autowired
    private ThreatAlertRepository alertRepository;

    @Autowired
    private AnalystFeedbackRepository feedbackRepository;

    @Autowired
    private AdaptiveThresholdRepository thresholdRepository;

    @Autowired
    private AdaptiveThresholdService adaptiveThresholdService;

    @BeforeEach
    public void setup() {
        feedbackRepository.deleteAll();
        thresholdRepository.deleteAll();
        adaptiveThresholdService.initializeDefaultThresholdsIfEmpty();
        adaptiveThresholdService.setMinFeedbackSamples(2);
    }

    private ThreatAlert createTestAlert(String attackType, RiskLevel riskLevel) {
        ThreatAlert alert = new ThreatAlert(
                DataSource.SIMULATED,
                75.0,
                riskLevel,
                attackType,
                0.90,
                "192.0.2.10",
                "10.0.0.5",
                44444,
                80,
                "TCP",
                true,
                true,
                "Test synthetic alert for adaptive learning verification"
        );
        alert.setStatus(AlertStatus.NEW);
        return alertRepository.save(alert);
    }

    /**
     * TASK 5.A: CONFIRMED_THREAT verification
     * - Feedback is saved.
     * - Alert status is updated to INVESTIGATING.
     * - Thresholds remain unchanged (no baseline incorporation of attack traffic).
     * - threshold_adjusted=false.
     */
    @Test
    public void testConfirmedThreatPreservesBaselineThresholds() {
        ThreatAlert alert = createTestAlert("CONFIRMED_DOS_TEST", RiskLevel.HIGH);

        // Capture baseline threshold values and timestamps
        AdaptiveThreshold anomalyBefore = thresholdRepository.findById("anomaly_score").orElseThrow();
        double priorAnomaly = anomalyBefore.getCurrentThreshold();
        LocalDateTime priorUpdatedAt = anomalyBefore.getUpdatedAt();

        FeedbackRequestDTO dto = new FeedbackRequestDTO();
        dto.setFeedbackType(FeedbackType.CONFIRMED_THREAT);
        dto.setAnalystNotes("Validated active volumetric attack by SOC analyst");
        dto.setAdjustThreshold(true); // Even if true, CONFIRMED_THREAT must never modify thresholds

        ResponseEntity<Map<String, Object>> res = feedbackController.submitFeedback(alert.getId(), dto);

        // 1. Verify HTTP Status and Response Payload
        assertEquals(HttpStatus.CREATED, res.getStatusCode());
        Map<String, Object> body = res.getBody();
        assertNotNull(body);
        assertEquals("SUCCESS", body.get("status"));
        assertEquals(false, body.get("threshold_adjusted"), "CONFIRMED_THREAT must report threshold_adjusted=false");
        assertEquals("Threat confirmed. Threat intelligence profile updated; baseline thresholds preserved.",
                body.get("message"));

        // 2. Verify Alert Status Updated
        ThreatAlert updatedAlert = alertRepository.findById(alert.getId()).orElseThrow();
        assertEquals(AlertStatus.INVESTIGATING, updatedAlert.getStatus(), "Alert status should transition to INVESTIGATING");

        // 3. Verify Feedback record saved with threshold_adjusted=false
        List<AnalystFeedback> feedbacks = feedbackRepository.findByAlertIdOrderByCreatedAtDesc(alert.getId());
        assertFalse(feedbacks.isEmpty());
        AnalystFeedback feedback = feedbacks.get(0);
        assertEquals(FeedbackType.CONFIRMED_THREAT, feedback.getFeedbackType());
        assertFalse(feedback.getThresholdAdjusted(), "Persisted AnalystFeedback must record threshold_adjusted=false");

        // 4. Verify Baseline Thresholds remain completely unchanged
        AdaptiveThreshold anomalyAfter = thresholdRepository.findById("anomaly_score").orElseThrow();
        assertEquals(priorAnomaly, anomalyAfter.getCurrentThreshold(), 0.00001, "anomaly_score threshold must remain strictly unchanged");
        assertEquals(priorUpdatedAt, anomalyAfter.getUpdatedAt(), "Threshold update timestamp must not change on CONFIRMED_THREAT");
    }

    /**
     * TASK 5.B: FALSE_POSITIVE controlled recalibration & minimum samples requirement
     * - Minimum feedback count respected.
     * - Thresholds change only when conditions satisfied.
     * - Changes remain within safety boundaries.
     * - threshold_adjusted=true only after successful persistence.
     */
    @Test
    public void testFalsePositiveControlledRecalibrationAndMinimumFeedback() {
        adaptiveThresholdService.setMinFeedbackSamples(2);

        ThreatAlert alert1 = createTestAlert("SYN_BORDERLINE_TEST_1", RiskLevel.MEDIUM);
        ThreatAlert alert2 = createTestAlert("SYN_BORDERLINE_TEST_2", RiskLevel.MEDIUM);

        AdaptiveThreshold anomalyInitial = thresholdRepository.findById("anomaly_score").orElseThrow();
        double initialVal = anomalyInitial.getCurrentThreshold();

        // --- SUBMISSION 1: Below minimum feedback samples (1 of 2 required) ---
        FeedbackRequestDTO dto1 = new FeedbackRequestDTO();
        dto1.setFeedbackType(FeedbackType.FALSE_POSITIVE);
        dto1.setAnalystNotes("Benign backup synchronization traffic falsely flagged");
        dto1.setAdjustThreshold(true);

        ResponseEntity<Map<String, Object>> res1 = feedbackController.submitFeedback(alert1.getId(), dto1);
        assertEquals(HttpStatus.CREATED, res1.getStatusCode());
        Map<String, Object> body1 = res1.getBody();
        assertNotNull(body1);
        assertEquals(false, body1.get("threshold_adjusted"),
                "Threshold should not adjust when minimum feedback samples (2) are not yet met");
        assertEquals("False positive recorded. Threshold recalibration not performed.", body1.get("message"));

        // Verify alert1 status updated to FALSE_POSITIVE
        ThreatAlert updatedAlert1 = alertRepository.findById(alert1.getId()).orElseThrow();
        assertEquals(AlertStatus.FALSE_POSITIVE, updatedAlert1.getStatus());

        // Verify thresholds remained unchanged after 1st sample
        AdaptiveThreshold anomalyMid = thresholdRepository.findById("anomaly_score").orElseThrow();
        assertEquals(initialVal, anomalyMid.getCurrentThreshold(), 0.00001);

        // --- SUBMISSION 2: Reaching minimum feedback samples (2 of 2 required) ---
        FeedbackRequestDTO dto2 = new FeedbackRequestDTO();
        dto2.setFeedbackType(FeedbackType.FALSE_POSITIVE);
        dto2.setAnalystNotes("Second confirmed false alarm on backup sync pattern");
        dto2.setAdjustThreshold(true);

        ResponseEntity<Map<String, Object>> res2 = feedbackController.submitFeedback(alert2.getId(), dto2);
        assertEquals(HttpStatus.CREATED, res2.getStatusCode());
        Map<String, Object> body2 = res2.getBody();
        assertNotNull(body2);
        assertEquals(true, body2.get("threshold_adjusted"),
                "Threshold should adjust once minimum feedback requirement is fulfilled");
        assertEquals("False positive recorded. Baseline thresholds adaptively calibrated.", body2.get("message"));

        // Verify threshold was recalibrated down within boundaries
        AdaptiveThreshold anomalyFinal = thresholdRepository.findById("anomaly_score").orElseThrow();
        double expectedNewVal = Math.round((initialVal * AdaptiveThresholdServiceImpl.ANOMALY_ADJUSTMENT_RATE) * 10000.0) / 10000.0;
        assertEquals(expectedNewVal, anomalyFinal.getCurrentThreshold(), 0.0001);
        assertTrue(anomalyFinal.getCurrentThreshold() >= AdaptiveThresholdServiceImpl.MIN_ANOMALY_THRESHOLD,
                "Recalibrated threshold must remain above safety floor");
        assertNotNull(anomalyFinal.getReason());
        assertTrue(anomalyFinal.getReason().contains("prior="));

        // Verify second feedback entity recorded threshold_adjusted=true
        List<AnalystFeedback> feedbacks2 = feedbackRepository.findByAlertIdOrderByCreatedAtDesc(alert2.getId());
        assertFalse(feedbacks2.isEmpty());
        assertTrue(feedbacks2.get(0).getThresholdAdjusted());
    }

    /**
     * TASK 5.C: SAFETY - Duplicate feedback and safety floor clamping
     * - Repeated feedback on the same alert does not repeatedly adjust thresholds.
     * - Threshold cannot fall below MIN_ANOMALY_THRESHOLD.
     */
    @Test
    public void testSafetyDuplicatePreventionAndFloorClamping() {
        adaptiveThresholdService.setMinFeedbackSamples(1);

        ThreatAlert alert = createTestAlert("PORT_SWEEP_FALSE_ALARM", RiskLevel.LOW);

        // 1. First submission succeeds and adjusts threshold
        FeedbackRequestDTO dto = new FeedbackRequestDTO();
        dto.setFeedbackType(FeedbackType.FALSE_POSITIVE);
        dto.setAnalystNotes("Internal vulnerability scanner run");
        dto.setAdjustThreshold(true);

        ResponseEntity<Map<String, Object>> res1 = feedbackController.submitFeedback(alert.getId(), dto);
        assertTrue((Boolean) res1.getBody().get("threshold_adjusted"));

        double valAfterFirst = thresholdRepository.findById("anomaly_score").orElseThrow().getCurrentThreshold();

        // 2. Duplicate submission for the SAME alert
        ResponseEntity<Map<String, Object>> res2 = feedbackController.submitFeedback(alert.getId(), dto);
        assertEquals(false, res2.getBody().get("threshold_adjusted"),
                "Duplicate feedback on the same alert must not repeatedly adjust thresholds");
        assertEquals("False positive recorded. Threshold recalibration not performed.", res2.getBody().get("message"));

        double valAfterSecond = thresholdRepository.findById("anomaly_score").orElseThrow().getCurrentThreshold();
        assertEquals(valAfterFirst, valAfterSecond, 0.00001, "Threshold must remain unchanged on duplicate feedback");

        // 3. Safety Floor Clamping verification
        // Manually place threshold at the minimum boundary
        AdaptiveThreshold threshold = thresholdRepository.findById("anomaly_score").orElseThrow();
        threshold.setCurrentThreshold(AdaptiveThresholdServiceImpl.MIN_ANOMALY_THRESHOLD);
        thresholdRepository.save(threshold);

        ThreatAlert alertFloor = createTestAlert("SCAN_AT_FLOOR", RiskLevel.LOW);
        ResponseEntity<Map<String, Object>> resFloor = feedbackController.submitFeedback(alertFloor.getId(), dto);

        // At boundary, calculation clamps to MIN_ANOMALY_THRESHOLD. Since newVal == oldVal, no adjustment is reported.
        assertEquals(false, resFloor.getBody().get("threshold_adjusted"),
                "At boundary floor, threshold cannot relax further and threshold_adjusted must be false");
        assertEquals("False positive recorded. Threshold recalibration not performed.", resFloor.getBody().get("message"));

        double finalFloorVal = thresholdRepository.findById("anomaly_score").orElseThrow().getCurrentThreshold();
        assertEquals(AdaptiveThresholdServiceImpl.MIN_ANOMALY_THRESHOLD, finalFloorVal, 0.00001);
    }
}

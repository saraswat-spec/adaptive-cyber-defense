package com.cyberattack.soc.service.impl;

import com.cyberattack.soc.dto.CalibrationRequestDTO;
import com.cyberattack.soc.model.AdaptiveThreshold;
import com.cyberattack.soc.model.enums.FeedbackType;
import com.cyberattack.soc.repository.AdaptiveThresholdRepository;
import com.cyberattack.soc.repository.AnalystFeedbackRepository;
import com.cyberattack.soc.service.AdaptiveThresholdService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@Transactional
public class AdaptiveThresholdServiceImpl implements AdaptiveThresholdService {

    private static final Logger logger = LoggerFactory.getLogger(AdaptiveThresholdServiceImpl.class);

    // Safety boundary constraints to protect the baseline from runaway degradation
    public static final double MIN_ANOMALY_THRESHOLD = 0.0020;
    public static final double MAX_ANOMALY_THRESHOLD = 0.0500;
    public static final double MIN_SYN_FLOOD_RATIO = 0.70;
    public static final double MAX_SYN_FLOOD_RATIO = 0.95;
    public static final double ANOMALY_ADJUSTMENT_RATE = 0.92;
    public static final double SYN_RATIO_STEP = 0.02;

    private final AdaptiveThresholdRepository thresholdRepository;
    private final AnalystFeedbackRepository feedbackRepository;

    @Value("${soc.adaptive.min-feedback-samples:2}")
    private int minFeedbackSamples = 2;

    public AdaptiveThresholdServiceImpl(AdaptiveThresholdRepository thresholdRepository,
                                        AnalystFeedbackRepository feedbackRepository) {
        this.thresholdRepository = thresholdRepository;
        this.feedbackRepository = feedbackRepository;
    }

    @Override
    public int getMinFeedbackSamples() {
        return minFeedbackSamples;
    }

    @Override
    public void setMinFeedbackSamples(int minFeedbackSamples) {
        this.minFeedbackSamples = minFeedbackSamples;
    }

    @PostConstruct
    @Override
    public void initializeDefaultThresholdsIfEmpty() {
        if (thresholdRepository.count() == 0) {
            logger.info("Initializing baseline adaptive thresholds in database...");
            List<AdaptiveThreshold> defaults = Arrays.asList(
                    new AdaptiveThreshold("anomaly_score", 0.0126, 0.0126, 0.0758, 0.0325, "Initial calibrated P5 baseline"),
                    new AdaptiveThreshold("syn_flood_ratio", 0.85, 0.85, 0.06, 0.04, "Normal TCP handshake ratio baseline"),
                    new AdaptiveThreshold("flow_rate_pps", 1500.0, 1500.0, 85.0, 42.0, "Typical perimeter packet rate cutoff"),
                    new AdaptiveThreshold("port_scan_entropy", 0.75, 0.75, 0.18, 0.08, "Standard endpoint port dispersion index")
            );
            thresholdRepository.saveAll(defaults);
        }
    }

    @Override
    public List<AdaptiveThreshold> getAllThresholds() {
        return thresholdRepository.findAll();
    }

    @Override
    public AdaptiveThreshold getThreshold(String metricName) {
        return thresholdRepository.findById(metricName)
                .orElse(new AdaptiveThreshold(metricName, 0.0126, 0.0126, 0.0758, 0.0325, "Default"));
    }

    @Override
    public Map<String, Object> handleFalsePositive(UUID alertId, String attackType) {
        // 1. Prevent duplicate feedback on the same alert from repeatedly modifying thresholds
        if (alertId != null && feedbackRepository.existsByAlertIdAndThresholdAdjustedTrue(alertId)) {
            logger.info("Alert {} has already adjusted thresholds. Skipping duplicate recalibration.", alertId);
            return Collections.emptyMap();
        }

        // 2. Require configurable minimum number of validated FALSE_POSITIVE samples
        long previousFpCount = feedbackRepository.countByFeedbackType(FeedbackType.FALSE_POSITIVE);
        long totalValidatedSamples = previousFpCount + 1; // includes the current incoming validated feedback
        if (totalValidatedSamples < minFeedbackSamples) {
            logger.info("Validated FALSE_POSITIVE count ({} of required min {}). Threshold recalibration deferred.",
                    totalValidatedSamples, minFeedbackSamples);
            return Collections.emptyMap();
        }

        Map<String, Object> adjustments = new HashMap<>();

        // 3. Controlled, bounded Anomaly Score Threshold recalibration
        thresholdRepository.findById("anomaly_score").ifPresent(anomalyItem -> {
            double oldVal = anomalyItem.getCurrentThreshold();
            // Stricter/lower cutoff reduces future false alarms for borderline normal flows
            double calculated = Math.round((oldVal * ANOMALY_ADJUSTMENT_RATE) * 10000.0) / 10000.0;
            // Bound strictly within [MIN_ANOMALY_THRESHOLD, MAX_ANOMALY_THRESHOLD]
            double newVal = Math.max(MIN_ANOMALY_THRESHOLD, Math.min(MAX_ANOMALY_THRESHOLD, calculated));

            // Only report an adjustment and persist if the value actually changed
            if (Math.abs(newVal - oldVal) >= 0.0001) {
                anomalyItem.setPreviousThreshold(oldVal);
                anomalyItem.setCurrentThreshold(newVal);
                String auditReason = String.format("Recalibrated from false positive alert %s (%s): prior=%.4f, new=%.4f, rate=%.2f, minFloor=%.4f",
                        alertId, attackType != null ? attackType : "Anomaly", oldVal, newVal, ANOMALY_ADJUSTMENT_RATE, MIN_ANOMALY_THRESHOLD);
                anomalyItem.setReason(auditReason);
                anomalyItem.setUpdatedAt(LocalDateTime.now());
                thresholdRepository.save(anomalyItem);

                adjustments.put("anomaly_score", Map.of(
                        "previous", oldVal,
                        "updated", newVal,
                        "reason", auditReason,
                        "updated_at", anomalyItem.getUpdatedAt().toString()
                ));
                logger.info("Adaptive anomaly_score threshold recalibrated: {} -> {}", oldVal, newVal);
            } else {
                logger.info("Adaptive anomaly_score threshold is at boundary ({}) and unchanged. No adjustment applied.", oldVal);
            }
        });

        // 4. Controlled, bounded SYN Flood Ratio recalibration if applicable
        if (attackType != null && attackType.toUpperCase().contains("SYN")) {
            thresholdRepository.findById("syn_flood_ratio").ifPresent(synItem -> {
                double oldSyn = synItem.getCurrentThreshold();
                double calculated = Math.round((oldSyn + SYN_RATIO_STEP) * 100.0) / 100.0;
                double newSyn = Math.min(MAX_SYN_FLOOD_RATIO, Math.max(MIN_SYN_FLOOD_RATIO, calculated));

                if (Math.abs(newSyn - oldSyn) >= 0.005) {
                    synItem.setPreviousThreshold(oldSyn);
                    synItem.setCurrentThreshold(newSyn);
                    String auditReason = String.format("False positive on SYN ratio for alert %s; prior=%.2f, new=%.2f, maxCeiling=%.2f",
                            alertId, oldSyn, newSyn, MAX_SYN_FLOOD_RATIO);
                    synItem.setReason(auditReason);
                    synItem.setUpdatedAt(LocalDateTime.now());
                    thresholdRepository.save(synItem);

                    adjustments.put("syn_flood_ratio", Map.of(
                            "previous", oldSyn,
                            "updated", newSyn,
                            "reason", auditReason,
                            "updated_at", synItem.getUpdatedAt().toString()
                    ));
                    logger.info("Adaptive syn_flood_ratio threshold recalibrated: {} -> {}", oldSyn, newSyn);
                } else {
                    logger.info("Adaptive syn_flood_ratio is at upper ceiling ({}) and unchanged. No adjustment applied.", oldSyn);
                }
            });
        }

        return adjustments;
    }

    @Override
    public List<AdaptiveThreshold> calibrateThresholds(CalibrationRequestDTO dto) {
        if (dto.getAnomalySensitivityFactor() != null) {
            thresholdRepository.findById("anomaly_score").ifPresent(item -> {
                double base = 0.0126;
                double tuned = Math.round((base * dto.getAnomalySensitivityFactor()) * 10000.0) / 10000.0;
                double bounded = Math.max(MIN_ANOMALY_THRESHOLD, Math.min(MAX_ANOMALY_THRESHOLD, tuned));
                item.setPreviousThreshold(item.getCurrentThreshold());
                item.setCurrentThreshold(bounded);
                item.setReason("Manual SOC sensitivity calibration factor (" + dto.getAnomalySensitivityFactor() + "x)");
                item.setUpdatedAt(LocalDateTime.now());
                thresholdRepository.save(item);
            });
        }

        if (dto.getSynFloodRatioThreshold() != null) {
            thresholdRepository.findById("syn_flood_ratio").ifPresent(item -> {
                double bounded = Math.max(MIN_SYN_FLOOD_RATIO, Math.min(MAX_SYN_FLOOD_RATIO, dto.getSynFloodRatioThreshold()));
                item.setPreviousThreshold(item.getCurrentThreshold());
                item.setCurrentThreshold(bounded);
                item.setReason("Manual calibration update");
                item.setUpdatedAt(LocalDateTime.now());
                thresholdRepository.save(item);
            });
        }

        if (dto.getPortEntropyThreshold() != null) {
            thresholdRepository.findById("port_scan_entropy").ifPresent(item -> {
                item.setPreviousThreshold(item.getCurrentThreshold());
                item.setCurrentThreshold(dto.getPortEntropyThreshold());
                item.setReason("Manual calibration update");
                item.setUpdatedAt(LocalDateTime.now());
                thresholdRepository.save(item);
            });
        }

        return thresholdRepository.findAll();
    }
}

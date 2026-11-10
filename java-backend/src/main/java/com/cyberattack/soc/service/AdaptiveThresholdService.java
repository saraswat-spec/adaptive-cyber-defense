package com.cyberattack.soc.service;

import com.cyberattack.soc.dto.CalibrationRequestDTO;
import com.cyberattack.soc.model.AdaptiveThreshold;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface AdaptiveThresholdService {
    List<AdaptiveThreshold> getAllThresholds();
    AdaptiveThreshold getThreshold(String metricName);
    Map<String, Object> handleFalsePositive(UUID alertId, String attackType);
    List<AdaptiveThreshold> calibrateThresholds(CalibrationRequestDTO dto);
    void initializeDefaultThresholdsIfEmpty();
    int getMinFeedbackSamples();
    void setMinFeedbackSamples(int minFeedbackSamples);
}

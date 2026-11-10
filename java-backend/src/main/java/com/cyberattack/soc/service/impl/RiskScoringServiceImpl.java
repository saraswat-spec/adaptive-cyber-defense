package com.cyberattack.soc.service.impl;

import com.cyberattack.soc.model.enums.RiskLevel;
import com.cyberattack.soc.service.RiskScoringService;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of Dynamic Threat Risk Scoring.
 * Calculates composite 0-100 score factoring:
 * - Statistical anomaly deviation distance
 * - Random Forest multi-class attack classification confidence
 * - Deterministic heuristic rule breach boost
 * - Target asset criticality weight
 */
@Service
public class RiskScoringServiceImpl implements RiskScoringService {

    // Severity weights per attack taxonomy
    private static final Map<String, Double> SEVERITY_WEIGHTS;
    // Critical asset weighting map
    private static final Map<String, Double> ASSET_CRITICALITY_MAP;

    static {
        Map<String, Double> sev = new HashMap<>();
        sev.put("Benign", 0.0);
        sev.put("PortScan", 45.0);
        sev.put("BruteForce", 75.0);
        sev.put("WebAttack", 80.0);
        sev.put("DoS_DDoS", 90.0);
        sev.put("Infiltration", 95.0);
        SEVERITY_WEIGHTS = Collections.unmodifiableMap(sev);

        Map<String, Double> assets = new HashMap<>();
        assets.put("10.0.0.5", 1.15);   // Core Database / Production Server
        assets.put("10.0.0.10", 1.10);  // API Gateway
        assets.put("172.16.0.4", 1.05); // DMZ Web Node
        ASSET_CRITICALITY_MAP = Collections.unmodifiableMap(assets);
    }

    @Override
    public double calculateRiskScore(double anomalyScore, double anomalyThreshold,
                                     String attackClass, double classConfidence,
                                     boolean ruleTriggered, double ruleConfidence,
                                     String targetIp) {
        // 1. Anomaly Component (0 - 35 points)
        // Smaller anomaly score than threshold means greater deviation
        double anomalyDelta = Math.max(0.0, anomalyThreshold - anomalyScore);
        double anomalyPoints = Math.min(35.0, (anomalyDelta / 0.05) * 35.0);

        // 2. Attack Classification Component (0 - 45 points)
        double baseSeverity = SEVERITY_WEIGHTS.getOrDefault(attackClass, 50.0);
        double classificationPoints = (baseSeverity * classConfidence) * 0.45;

        // 3. Rule Component (0 - 20 points)
        double rulePoints = ruleTriggered ? (ruleConfidence * 20.0) : 0.0;

        // Composite Base
        double rawScore = anomalyPoints + classificationPoints + rulePoints;

        // 4. Asset Criticality Multiplier
        double assetMultiplier = ASSET_CRITICALITY_MAP.getOrDefault(targetIp, 1.0);
        double finalScore = rawScore * assetMultiplier;

        // Bounded in [0.0, 100.0]
        return Math.min(100.0, Math.max(0.0, Math.round(finalScore * 10.0) / 10.0));
    }

    @Override
    public RiskLevel determineRiskLevel(double score) {
        if (score >= 80.0) {
            return RiskLevel.CRITICAL;
        } else if (score >= 60.0) {
            return RiskLevel.HIGH;
        } else if (score >= 35.0) {
            return RiskLevel.MEDIUM;
        } else {
            return RiskLevel.LOW;
        }
    }
}

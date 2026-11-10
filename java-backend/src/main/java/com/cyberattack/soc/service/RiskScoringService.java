package com.cyberattack.soc.service;

import com.cyberattack.soc.model.enums.RiskLevel;

public interface RiskScoringService {
    double calculateRiskScore(double anomalyScore, double anomalyThreshold,
                              String attackClass, double classConfidence,
                              boolean ruleTriggered, double ruleConfidence,
                              String targetIp);

    RiskLevel determineRiskLevel(double score);
}

package com.cyberattack.soc.model;

import com.cyberattack.soc.model.enums.RiskLevel;
import java.io.Serializable;
import java.util.Objects;

/**
 * Encapsulates the output of the Hybrid Detection Engine
 * combining deterministic rules, Isolation Forest anomaly scoring,
 * and Random Forest multi-class attack classification.
 */
public class DetectionResult implements Serializable {

    private boolean suspicious;
    private boolean ruleTriggered;
    private String ruleName;
    private boolean mlTriggered;
    private Double anomalyScore;
    private String predictedAttackClass;
    private Double classificationConfidence;
    private Double dynamicRiskScore;
    private RiskLevel riskLevel;
    private String explanationNarrative;
    private boolean fallbackUsed = false;

    // Constructors
    public DetectionResult() {
        this.suspicious = false;
        this.ruleTriggered = false;
        this.mlTriggered = false;
        this.anomalyScore = 0.0;
        this.predictedAttackClass = "Benign";
        this.classificationConfidence = 0.0;
        this.dynamicRiskScore = 0.0;
        this.riskLevel = RiskLevel.LOW;
        this.explanationNarrative = "Normal perimeter flow behavior.";
    }

    public DetectionResult(boolean suspicious, boolean ruleTriggered, boolean mlTriggered,
                           Double anomalyScore, String predictedAttackClass,
                           Double classificationConfidence, Double dynamicRiskScore,
                           RiskLevel riskLevel, String explanationNarrative) {
        this.suspicious = suspicious;
        this.ruleTriggered = ruleTriggered;
        this.mlTriggered = mlTriggered;
        this.anomalyScore = anomalyScore;
        this.predictedAttackClass = predictedAttackClass;
        this.classificationConfidence = classificationConfidence;
        this.dynamicRiskScore = dynamicRiskScore;
        this.riskLevel = riskLevel;
        this.explanationNarrative = explanationNarrative;
    }

    // Encapsulation
    public boolean isSuspicious() {
        return suspicious;
    }

    public void setSuspicious(boolean suspicious) {
        this.suspicious = suspicious;
    }

    public boolean isRuleTriggered() {
        return ruleTriggered;
    }

    public void setRuleTriggered(boolean ruleTriggered) {
        this.ruleTriggered = ruleTriggered;
    }

    public String getRuleName() {
        return ruleName;
    }

    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    public boolean isMlTriggered() {
        return mlTriggered;
    }

    public void setMlTriggered(boolean mlTriggered) {
        this.mlTriggered = mlTriggered;
    }

    public Double getAnomalyScore() {
        return anomalyScore;
    }

    public void setAnomalyScore(Double anomalyScore) {
        this.anomalyScore = anomalyScore;
    }

    public String getPredictedAttackClass() {
        return predictedAttackClass;
    }

    public void setPredictedAttackClass(String predictedAttackClass) {
        this.predictedAttackClass = predictedAttackClass;
    }

    public Double getClassificationConfidence() {
        return classificationConfidence;
    }

    public void setClassificationConfidence(Double classificationConfidence) {
        this.classificationConfidence = classificationConfidence;
    }

    public Double getDynamicRiskScore() {
        return dynamicRiskScore;
    }

    public void setDynamicRiskScore(Double dynamicRiskScore) {
        this.dynamicRiskScore = dynamicRiskScore;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getExplanationNarrative() {
        return explanationNarrative;
    }

    public void setExplanationNarrative(String explanationNarrative) {
        this.explanationNarrative = explanationNarrative;
    }

    public boolean isFallbackUsed() {
        return fallbackUsed;
    }

    public void setFallbackUsed(boolean fallbackUsed) {
        this.fallbackUsed = fallbackUsed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectionResult that = (DetectionResult) o;
        return suspicious == that.suspicious &&
                Double.compare(that.dynamicRiskScore, dynamicRiskScore) == 0 &&
                Objects.equals(predictedAttackClass, that.predictedAttackClass);
    }

    @Override
    public int hashCode() {
        return Objects.hash(suspicious, predictedAttackClass, dynamicRiskScore);
    }

    @Override
    public String toString() {
        return "DetectionResult{" +
                "suspicious=" + suspicious +
                ", attackClass='" + predictedAttackClass + '\'' +
                ", riskScore=" + dynamicRiskScore +
                ", level=" + riskLevel +
                '}';
    }
}

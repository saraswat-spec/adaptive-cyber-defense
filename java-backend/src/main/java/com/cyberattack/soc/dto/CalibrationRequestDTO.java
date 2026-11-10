package com.cyberattack.soc.dto;

public class CalibrationRequestDTO {
    private Double anomalySensitivityFactor = 1.0;
    private Double confidenceFloor = 0.50;
    private Double synFloodRatioThreshold;
    private Double portEntropyThreshold;

    public CalibrationRequestDTO() {}

    public Double getAnomalySensitivityFactor() { return anomalySensitivityFactor; }
    public void setAnomalySensitivityFactor(Double anomalySensitivityFactor) { this.anomalySensitivityFactor = anomalySensitivityFactor; }

    public Double getConfidenceFloor() { return confidenceFloor; }
    public void setConfidenceFloor(Double confidenceFloor) { this.confidenceFloor = confidenceFloor; }

    public Double getSynFloodRatioThreshold() { return synFloodRatioThreshold; }
    public void setSynFloodRatioThreshold(Double synFloodRatioThreshold) { this.synFloodRatioThreshold = synFloodRatioThreshold; }

    public Double getPortEntropyThreshold() { return portEntropyThreshold; }
    public void setPortEntropyThreshold(Double portEntropyThreshold) { this.portEntropyThreshold = portEntropyThreshold; }
}

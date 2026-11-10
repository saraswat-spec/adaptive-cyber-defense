package com.cyberattack.soc.dto;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PythonMLPredictionResponse {
    private Double anomaly_score = 0.0;
    private String predicted_class = "Benign";
    private Double class_probability = 0.5;
    private Boolean rule_triggered = false;
    private String rule_name;
    private Double rule_confidence = 0.0;
    private String explanation_narrative;
    private List<Map<String, Object>> top_features = new ArrayList<>();
    private Boolean is_fallback = false;

    public PythonMLPredictionResponse() {}

    // Getters and Setters
    public Boolean getIs_fallback() { return is_fallback; }
    public void setIs_fallback(Boolean is_fallback) { this.is_fallback = is_fallback; }
    public Double getAnomaly_score() { return anomaly_score; }
    public void setAnomaly_score(Double anomaly_score) { this.anomaly_score = anomaly_score; }

    public String getPredicted_class() { return predicted_class; }
    public void setPredicted_class(String predicted_class) { this.predicted_class = predicted_class; }

    public Double getClass_probability() { return class_probability; }
    public void setClass_probability(Double class_probability) { this.class_probability = class_probability; }

    public Boolean getRule_triggered() { return rule_triggered; }
    public void setRule_triggered(Boolean rule_triggered) { this.rule_triggered = rule_triggered; }

    public String getRule_name() { return rule_name; }
    public void setRule_name(String rule_name) { this.rule_name = rule_name; }

    public Double getRule_confidence() { return rule_confidence; }
    public void setRule_confidence(Double rule_confidence) { this.rule_confidence = rule_confidence; }

    public String getExplanation_narrative() { return explanation_narrative; }
    public void setExplanation_narrative(String explanation_narrative) { this.explanation_narrative = explanation_narrative; }

    public List<Map<String, Object>> getTop_features() { return top_features; }
    public void setTop_features(List<Map<String, Object>> top_features) { this.top_features = top_features; }
}

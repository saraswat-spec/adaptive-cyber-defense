package com.cyberattack.soc.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Stores and manages adaptive anomaly thresholds that calibrate dynamically.
 */
@Entity
@Table(name = "adaptive_thresholds")
public class AdaptiveThreshold {

    @Id
    @NotBlank
    @Column(nullable = false, length = 60)
    private String metricName;

    @NotNull
    @Column(nullable = false)
    private Double currentThreshold;

    @NotNull
    @Column(nullable = false)
    private Double previousThreshold;

    @NotNull
    @Column(nullable = false)
    private Double baselineMean;

    @NotNull
    @Column(nullable = false)
    private Double baselineStd;

    @Column(length = 500)
    private String reason;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    // Constructors
    public AdaptiveThreshold() {
        this.updatedAt = LocalDateTime.now();
    }

    public AdaptiveThreshold(String metricName, Double currentThreshold, Double previousThreshold,
                             Double baselineMean, Double baselineStd, String reason) {
        this();
        this.metricName = metricName;
        this.currentThreshold = currentThreshold;
        this.previousThreshold = previousThreshold;
        this.baselineMean = baselineMean;
        this.baselineStd = baselineStd;
        this.reason = reason;
    }

    // Encapsulation
    public String getMetricName() {
        return metricName;
    }

    public void setMetricName(String metricName) {
        this.metricName = metricName;
    }

    public Double getCurrentThreshold() {
        return currentThreshold;
    }

    public void setCurrentThreshold(Double currentThreshold) {
        this.currentThreshold = currentThreshold;
    }

    public Double getPreviousThreshold() {
        return previousThreshold;
    }

    public void setPreviousThreshold(Double previousThreshold) {
        this.previousThreshold = previousThreshold;
    }

    public Double getBaselineMean() {
        return baselineMean;
    }

    public void setBaselineMean(Double baselineMean) {
        this.baselineMean = baselineMean;
    }

    public Double getBaselineStd() {
        return baselineStd;
    }

    public void setBaselineStd(Double baselineStd) {
        this.baselineStd = baselineStd;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AdaptiveThreshold that = (AdaptiveThreshold) o;
        return Objects.equals(metricName, that.metricName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(metricName);
    }

    @Override
    public String toString() {
        return "AdaptiveThreshold{" +
                "metricName='" + metricName + '\'' +
                ", currentThreshold=" + currentThreshold +
                ", updatedAt=" + updatedAt +
                '}';
    }
}

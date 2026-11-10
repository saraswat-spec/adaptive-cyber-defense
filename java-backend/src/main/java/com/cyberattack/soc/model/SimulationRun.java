package com.cyberattack.soc.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity tracking red-team attack simulation laboratory runs.
 * Records scenario configuration, execution lifecycle, injected packet volumes,
 * and detected SOC security alerts.
 */
@Entity
@Table(name = "simulation_runs")
public class SimulationRun {

    @Id
    @Column(nullable = false, length = 64)
    private String id;

    @Column(nullable = false, length = 50)
    private String scenarioName;

    @Column(nullable = false, length = 45)
    private String targetIp;

    private Integer targetPort;
    private Double durationSeconds;
    private Integer totalPacketsInjected = 0;
    private Integer detectedAlertsCount = 0;

    @Column(nullable = false, length = 20)
    private String status = "RUNNING"; // RUNNING, COMPLETED, FAILED

    @Column(length = 500)
    private String errorMessage;

    @Column(nullable = false)
    private LocalDateTime startedAt;

    private LocalDateTime endedAt;

    public SimulationRun() {
        this.startedAt = LocalDateTime.now();
        this.status = "RUNNING";
        this.totalPacketsInjected = 0;
        this.detectedAlertsCount = 0;
    }

    public SimulationRun(String id, String scenarioName, String targetIp, Integer targetPort, Double durationSeconds) {
        this();
        this.id = id;
        this.scenarioName = scenarioName;
        this.targetIp = targetIp;
        this.targetPort = targetPort;
        this.durationSeconds = durationSeconds;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("scenario_name")
    public String getScenarioName() {
        return scenarioName;
    }

    public void setScenarioName(String scenarioName) {
        this.scenarioName = scenarioName;
    }

    @JsonProperty("target_ip")
    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    @JsonProperty("target_port")
    public Integer getTargetPort() {
        return targetPort;
    }

    public void setTargetPort(Integer targetPort) {
        this.targetPort = targetPort;
    }

    @JsonProperty("duration_seconds")
    public Double getDurationSeconds() {
        return durationSeconds;
    }

    public void setDurationSeconds(Double durationSeconds) {
        this.durationSeconds = durationSeconds;
    }

    @JsonProperty("total_packets_injected")
    public Integer getTotalPacketsInjected() {
        return totalPacketsInjected;
    }

    public void setTotalPacketsInjected(Integer totalPacketsInjected) {
        this.totalPacketsInjected = totalPacketsInjected;
    }

    @JsonProperty("detected_alerts_count")
    public Integer getDetectedAlertsCount() {
        return detectedAlertsCount;
    }

    public void setDetectedAlertsCount(Integer detectedAlertsCount) {
        this.detectedAlertsCount = detectedAlertsCount;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("error_message")
    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    @JsonProperty("started_at")
    public LocalDateTime getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(LocalDateTime startedAt) {
        this.startedAt = startedAt;
    }

    @JsonProperty("ended_at")
    public LocalDateTime getEndedAt() {
        return endedAt;
    }

    public void setEndedAt(LocalDateTime endedAt) {
        this.endedAt = endedAt;
    }
}

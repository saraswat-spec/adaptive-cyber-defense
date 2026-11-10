package com.cyberattack.soc.model;

import com.cyberattack.soc.model.enums.FeedbackType;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents human analyst review feedback, powering the active learning
 * and false-positive reduction feedback loops.
 */
@Entity
@Table(name = "analyst_feedback")
public class AnalystFeedback {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotNull
    @Column(nullable = false)
    private UUID alertId;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private FeedbackType feedbackType;

    @Column(length = 1000)
    private String analystNotes;

    @Column(nullable = false)
    private Boolean thresholdAdjusted = false;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    // Constructors
    public AnalystFeedback() {
        this.createdAt = LocalDateTime.now();
    }

    public AnalystFeedback(UUID alertId, FeedbackType feedbackType, String analystNotes, Boolean thresholdAdjusted) {
        this();
        this.alertId = alertId;
        this.feedbackType = feedbackType;
        this.analystNotes = analystNotes;
        this.thresholdAdjusted = thresholdAdjusted;
    }

    // Encapsulation
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    @JsonProperty("alert_id")
    public UUID getAlertId() {
        return alertId;
    }

    public void setAlertId(UUID alertId) {
        this.alertId = alertId;
    }

    @JsonProperty("feedback_type")
    public FeedbackType getFeedbackType() {
        return feedbackType;
    }

    public void setFeedbackType(FeedbackType feedbackType) {
        this.feedbackType = feedbackType;
    }

    @JsonProperty("analyst_notes")
    public String getAnalystNotes() {
        return analystNotes;
    }

    public void setAnalystNotes(String analystNotes) {
        this.analystNotes = analystNotes;
    }

    @JsonProperty("threshold_adjusted")
    public Boolean getThresholdAdjusted() {
        return thresholdAdjusted;
    }

    public void setThresholdAdjusted(Boolean thresholdAdjusted) {
        this.thresholdAdjusted = thresholdAdjusted;
    }

    @JsonProperty("created_at")
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AnalystFeedback that = (AnalystFeedback) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "AnalystFeedback{" +
                "id=" + id +
                ", alertId=" + alertId +
                ", feedbackType=" + feedbackType +
                ", thresholdAdjusted=" + thresholdAdjusted +
                '}';
    }
}

package com.cyberattack.soc.model;

import com.cyberattack.soc.model.enums.ActionType;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents an automated or analyst-executed defensive mitigation script.
 */
@Entity
@Table(name = "prevention_actions")
public class PreventionAction {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "threat_alert_id", nullable = false)
    @JsonBackReference
    private ThreatAlert threatAlert;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private ActionType actionType;

    @NotBlank
    @Column(nullable = false, length = 45)
    private String targetIp;

    @NotBlank
    @Column(nullable = false, length = 2000)
    private String generatedScript;

    @Column(nullable = false, length = 30)
    private String status = "RECOMMENDED";

    @Column(nullable = false, length = 20)
    private String executionMode = "SIMULATED";

    @Column(nullable = false)
    private LocalDateTime createdAt;

    // Constructors
    public PreventionAction() {
        this.createdAt = LocalDateTime.now();
    }

    public PreventionAction(ThreatAlert threatAlert, ActionType actionType,
                            String targetIp, String generatedScript) {
        this();
        this.threatAlert = threatAlert;
        this.actionType = actionType;
        this.targetIp = targetIp;
        this.generatedScript = generatedScript;
    }

    // Encapsulation
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public ThreatAlert getThreatAlert() {
        return threatAlert;
    }

    public void setThreatAlert(ThreatAlert threatAlert) {
        this.threatAlert = threatAlert;
    }

    public ActionType getActionType() {
        return actionType;
    }

    public void setActionType(ActionType actionType) {
        this.actionType = actionType;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public String getGeneratedScript() {
        return generatedScript;
    }

    public void setGeneratedScript(String generatedScript) {
        this.generatedScript = generatedScript;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getExecutionMode() {
        return executionMode;
    }

    public void setExecutionMode(String executionMode) {
        this.executionMode = executionMode;
    }

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
        PreventionAction that = (PreventionAction) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "PreventionAction{" +
                "id=" + id +
                ", actionType=" + actionType +
                ", targetIp='" + targetIp + '\'' +
                ", status='" + status + '\'' +
                '}';
    }
}

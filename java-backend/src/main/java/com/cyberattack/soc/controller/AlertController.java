package com.cyberattack.soc.controller;

import com.cyberattack.soc.dto.MitigationRequestDTO;
import com.cyberattack.soc.exception.ResourceNotFoundException;
import com.cyberattack.soc.model.PreventionAction;
import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.ActionType;
import com.cyberattack.soc.model.enums.AlertStatus;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.model.enums.RiskLevel;
import com.cyberattack.soc.repository.ThreatAlertRepository;
import com.cyberattack.soc.service.IncidentManagementService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller managing Threat Alerts, status updates, and containment mitigation actions.
 */
@RestController
@RequestMapping("/api/v1/alerts")
public class AlertController {

    private final ThreatAlertRepository alertRepository;
    private final IncidentManagementService incidentManagementService;

    public AlertController(ThreatAlertRepository alertRepository,
                           IncidentManagementService incidentManagementService) {
        this.alertRepository = alertRepository;
        this.incidentManagementService = incidentManagementService;
    }

    /**
     * List threat alerts with optional filtering by status, risk severity, and data provenance.
     */
    @GetMapping
    public ResponseEntity<List<ThreatAlert>> getAlerts(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "ALL") String source,
            @RequestParam(defaultValue = "60") int limit) {

        List<ThreatAlert> alerts = alertRepository.findTop50ByOrderByTimestampDesc();

        if (status != null && !status.isBlank()) {
            try {
                AlertStatus alertStatus = AlertStatus.valueOf(status.toUpperCase());
                alerts = alerts.stream()
                        .filter(a -> a.getStatus() == alertStatus)
                        .collect(Collectors.toList());
            } catch (IllegalArgumentException ignored) {
            }
        }

        if (severity != null && !severity.isBlank()) {
            try {
                RiskLevel riskLevel = RiskLevel.valueOf(severity.toUpperCase());
                alerts = alerts.stream()
                        .filter(a -> a.getRiskLevel() == riskLevel)
                        .collect(Collectors.toList());
            } catch (IllegalArgumentException ignored) {
            }
        }

        if (source != null && !"ALL".equalsIgnoreCase(source)) {
            try {
                DataSource ds = DataSource.valueOf(source.toUpperCase());
                alerts = alerts.stream()
                        .filter(a -> a.getDataSource() == ds)
                        .collect(Collectors.toList());
            } catch (IllegalArgumentException ignored) {
            }
        }

        if (alerts.size() > limit) {
            alerts = alerts.subList(0, limit);
        }

        return ResponseEntity.ok(alerts);
    }

    /**
     * Retrieve single threat alert details by UUID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ThreatAlert> getAlertById(@PathVariable UUID id) {
        ThreatAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat alert not found: " + id));
        return ResponseEntity.ok(alert);
    }

    /**
     * Update triage status of an alert (e.g. INVESTIGATING, RESOLVED, FALSE_POSITIVE).
     */
    @PatchMapping("/{id}/status")
    public ResponseEntity<ThreatAlert> updateAlertStatus(
            @PathVariable UUID id,
            @RequestBody Map<String, String> payload) {

        ThreatAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat alert not found: " + id));

        String newStatusStr = payload.get("status");
        if (newStatusStr != null) {
            try {
                AlertStatus newStatus = AlertStatus.valueOf(newStatusStr.toUpperCase());
                alert.setStatus(newStatus);
                ThreatAlert updated = alertRepository.save(alert);
                return ResponseEntity.ok(updated);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid alert status: " + newStatusStr);
            }
        }

        return ResponseEntity.ok(alert);
    }

    /**
     * Execute recommended containment prevention action (Simulated dry-run or Active enforcement).
     */
    @PostMapping("/{id}/mitigate")
    public ResponseEntity<Map<String, Object>> executeMitigation(
            @PathVariable UUID id,
            @Valid @RequestBody MitigationRequestDTO req) {

        ThreatAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Threat alert not found: " + id));

        List<PreventionAction> actions = incidentManagementService.getActionsForAlert(id);
        PreventionAction targetAction = null;

        for (PreventionAction action : actions) {
            if (action.getActionType() == req.getActionType()) {
                targetAction = action;
                break;
            }
        }

        if (targetAction == null) {
            // Auto-generate prevention action for the alert if not already mapped
            ActionType actType = (req != null && req.getActionType() != null) ? req.getActionType() : ActionType.BLOCK_IP;
            String script = "# Immediate Containment Command\niptables -I INPUT -s " + alert.getSourceIp() + " -j DROP";
            targetAction = new PreventionAction(alert, actType, alert.getSourceIp(), script);
            alert.addPreventionAction(targetAction);
            alertRepository.save(alert);
        }

        Map<String, Object> execResult = incidentManagementService.executePreventionAction(
                targetAction.getId(),
                req.getExecutionMode() != null ? req.getExecutionMode() : "SIMULATED"
        );

        return ResponseEntity.ok(execResult);
    }
}

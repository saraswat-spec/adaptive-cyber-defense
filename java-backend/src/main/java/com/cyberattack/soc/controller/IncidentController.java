package com.cyberattack.soc.controller;

import com.cyberattack.soc.model.Incident;
import com.cyberattack.soc.model.enums.IncidentSeverity;
import com.cyberattack.soc.model.enums.IncidentStatus;
import com.cyberattack.soc.service.IncidentManagementService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Controller for SOC Incident Management lifecycle.
 * Manages escalated high-severity incidents, triage states, and resolution logs.
 */
@RestController
@RequestMapping("/api/v1/incidents")
public class IncidentController {

    private final IncidentManagementService incidentManagementService;

    public IncidentController(IncidentManagementService incidentManagementService) {
        this.incidentManagementService = incidentManagementService;
    }

    /**
     * List all recorded security incidents with optional filters.
     */
    @GetMapping
    public ResponseEntity<List<Incident>> getAllIncidents(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity) {

        IncidentStatus incidentStatus = null;
        if (status != null && !status.isBlank()) {
            try {
                incidentStatus = IncidentStatus.valueOf(status.toUpperCase());
            } catch (IllegalArgumentException ignored) {}
        }

        IncidentSeverity incidentSeverity = null;
        if (severity != null && !severity.isBlank()) {
            try {
                incidentSeverity = IncidentSeverity.valueOf(severity.toUpperCase());
            } catch (IllegalArgumentException ignored) {}
        }

        List<Incident> incidents = incidentManagementService.getAllIncidents(incidentStatus, incidentSeverity);
        return ResponseEntity.ok(incidents);
    }

    /**
     * Retrieve single incident by UUID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Incident> getIncidentById(@PathVariable UUID id) {
        Incident incident = incidentManagementService.getIncidentById(id);
        return ResponseEntity.ok(incident);
    }

    /**
     * Update incident status (e.g. TRIAGED, MITIGATED, CLOSED) and record resolution notes.
     */
    @PatchMapping("/{id}/status")
    public ResponseEntity<Incident> updateIncidentStatus(
            @PathVariable UUID id,
            @RequestBody Map<String, String> payload) {

        String statusStr = payload.get("status");
        String notes = payload.get("notes");

        IncidentStatus status = IncidentStatus.CLOSED;
        if (statusStr != null) {
            try {
                status = IncidentStatus.valueOf(statusStr.toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid incident status: " + statusStr);
            }
        }

        Incident updated = incidentManagementService.updateIncidentStatus(id, status, notes);
        return ResponseEntity.ok(updated);
    }
}

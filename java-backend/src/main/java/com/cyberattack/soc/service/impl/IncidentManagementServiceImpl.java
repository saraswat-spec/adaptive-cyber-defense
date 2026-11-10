package com.cyberattack.soc.service.impl;

import com.cyberattack.soc.exception.ResourceNotFoundException;
import com.cyberattack.soc.model.Incident;
import com.cyberattack.soc.model.PreventionAction;
import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.IncidentSeverity;
import com.cyberattack.soc.model.enums.IncidentStatus;
import com.cyberattack.soc.repository.IncidentRepository;
import com.cyberattack.soc.repository.PreventionActionRepository;
import com.cyberattack.soc.service.IncidentManagementService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@Transactional
public class IncidentManagementServiceImpl implements IncidentManagementService {

    private static final Logger logger = LoggerFactory.getLogger(IncidentManagementServiceImpl.class);

    private static final Set<String> SAFE_WHITELIST_IPS = Set.of(
            "127.0.0.1", "::1", "localhost", "192.168.1.1", "10.0.0.1"
    );

    private final IncidentRepository incidentRepository;
    private final PreventionActionRepository preventionActionRepository;

    public IncidentManagementServiceImpl(IncidentRepository incidentRepository,
                                         PreventionActionRepository preventionActionRepository) {
        this.incidentRepository = incidentRepository;
        this.preventionActionRepository = preventionActionRepository;
    }

    @Override
    public Incident createIncidentFromAlert(ThreatAlert alert) {
        IncidentSeverity severity = mapAlertLevelToSeverity(alert.getRiskLevel().name());
        String title = "Automated Incident Escalation: " + alert.getAttackType() + " detected on " + alert.getDestinationIp();

        Incident incident = new Incident(title, severity, "SOC Tier-1 Automation Agent");
        incident.addAlert(alert);

        logger.info("Escalating alert {} into new incident '{}' (Severity: {})", alert.getId(), title, severity);
        return incidentRepository.save(incident);
    }

    @Override
    public List<Incident> getAllIncidents(IncidentStatus status, IncidentSeverity severity) {
        if (status != null) {
            return incidentRepository.findByStatusOrderByCreatedAtDesc(status);
        } else if (severity != null) {
            return incidentRepository.findBySeverityOrderByCreatedAtDesc(severity);
        }
        return incidentRepository.findTop50ByOrderByCreatedAtDesc();
    }

    @Override
    public Incident getIncidentById(UUID id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + id));
    }

    @Override
    public Incident updateIncidentStatus(UUID id, IncidentStatus status, String notes) {
        Incident incident = getIncidentById(id);
        incident.setStatus(status);
        if (notes != null && !notes.isBlank()) {
            incident.setResolutionNotes(notes);
        }
        incident.setUpdatedAt(LocalDateTime.now());
        return incidentRepository.save(incident);
    }

    @Override
    public Map<String, Object> executePreventionAction(UUID actionId, String mode) {
        PreventionAction action = preventionActionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("Prevention action not found: " + actionId));

        String targetIp = action.getTargetIp();
        if (SAFE_WHITELIST_IPS.contains(targetIp)) {
            return Map.of(
                    "success", false,
                    "message", "Target IP " + targetIp + " is protected by the SOC safety whitelist. Execution blocked."
            );
        }

        if ("ACTIVE".equalsIgnoreCase(mode)) {
            action.setStatus("APPLIED");
            action.setExecutionMode("ACTIVE");
            preventionActionRepository.save(action);
            return Map.of(
                    "success", true,
                    "mode", "ACTIVE",
                    "message", "Enforced firewall containment rule for " + targetIp + "."
            );
        } else {
            action.setStatus("SIMULATED_APPLIED");
            action.setExecutionMode("SIMULATED");
            preventionActionRepository.save(action);
            return Map.of(
                    "success", true,
                    "mode", "SIMULATED",
                    "message", "Simulated firewall rule applied for " + targetIp + ". (Dry-run mode, host network unharmed)."
            );
        }
    }

    @Override
    public List<PreventionAction> getActionsForAlert(UUID alertId) {
        return preventionActionRepository.findByThreatAlertId(alertId);
    }

    private IncidentSeverity mapAlertLevelToSeverity(String level) {
        try {
            return IncidentSeverity.valueOf(level);
        } catch (Exception e) {
            return IncidentSeverity.MEDIUM;
        }
    }
}

package com.cyberattack.soc.service;

import com.cyberattack.soc.model.Incident;
import com.cyberattack.soc.model.PreventionAction;
import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.IncidentSeverity;
import com.cyberattack.soc.model.enums.IncidentStatus;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface IncidentManagementService {
    Incident createIncidentFromAlert(ThreatAlert alert);
    List<Incident> getAllIncidents(IncidentStatus status, IncidentSeverity severity);
    Incident getIncidentById(UUID id);
    Incident updateIncidentStatus(UUID id, IncidentStatus status, String notes);
    Map<String, Object> executePreventionAction(UUID actionId, String mode);
    List<PreventionAction> getActionsForAlert(UUID alertId);
}

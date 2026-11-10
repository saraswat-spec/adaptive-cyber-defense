package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.Incident;
import com.cyberattack.soc.model.enums.IncidentSeverity;
import com.cyberattack.soc.model.enums.IncidentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface IncidentRepository extends JpaRepository<Incident, UUID> {
    List<Incident> findByStatusOrderByCreatedAtDesc(IncidentStatus status);
    List<Incident> findBySeverityOrderByCreatedAtDesc(IncidentSeverity severity);
    List<Incident> findTop50ByOrderByCreatedAtDesc();
}

package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.PreventionAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PreventionActionRepository extends JpaRepository<PreventionAction, UUID> {
    List<PreventionAction> findByThreatAlertId(UUID alertId);
}

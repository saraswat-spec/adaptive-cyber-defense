package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.ThreatAlert;
import com.cyberattack.soc.model.enums.AlertStatus;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.model.enums.RiskLevel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ThreatAlertRepository extends JpaRepository<ThreatAlert, UUID> {
    List<ThreatAlert> findByStatusOrderByTimestampDesc(AlertStatus status);
    List<ThreatAlert> findByRiskLevelOrderByTimestampDesc(RiskLevel riskLevel);
    List<ThreatAlert> findByDataSourceOrderByTimestampDesc(DataSource dataSource);
    List<ThreatAlert> findTop50ByOrderByTimestampDesc();
    long countByStatus(AlertStatus status);
    long countByRiskLevel(RiskLevel riskLevel);
}

package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.AdaptiveThreshold;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdaptiveThresholdRepository extends JpaRepository<AdaptiveThreshold, String> {
    Optional<AdaptiveThreshold> findByMetricName(String metricName);
}

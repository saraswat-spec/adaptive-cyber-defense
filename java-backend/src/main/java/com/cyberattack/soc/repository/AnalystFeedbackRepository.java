package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.AnalystFeedback;
import com.cyberattack.soc.model.enums.FeedbackType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AnalystFeedbackRepository extends JpaRepository<AnalystFeedback, UUID> {
    List<AnalystFeedback> findByAlertIdOrderByCreatedAtDesc(UUID alertId);
    List<AnalystFeedback> findTop50ByOrderByCreatedAtDesc();
    long countByFeedbackType(FeedbackType feedbackType);
    boolean existsByAlertIdAndThresholdAdjustedTrue(UUID alertId);
}

package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.SimulationRun;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SimulationRunRepository extends JpaRepository<SimulationRun, String> {
    List<SimulationRun> findAllByOrderByStartedAtDesc();
}

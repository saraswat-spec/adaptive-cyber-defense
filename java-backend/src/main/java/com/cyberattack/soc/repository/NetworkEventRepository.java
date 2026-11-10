package com.cyberattack.soc.repository;

import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.enums.DataSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface NetworkEventRepository extends JpaRepository<NetworkEvent, UUID> {
    Page<NetworkEvent> findByDataSourceOrderByTimestampDesc(DataSource dataSource, Pageable pageable);
    List<NetworkEvent> findTop50ByOrderByTimestampDesc();
    long countByDataSource(DataSource dataSource);
}

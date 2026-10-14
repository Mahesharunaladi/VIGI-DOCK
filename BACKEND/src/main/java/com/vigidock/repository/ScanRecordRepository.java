package com.vigidock.repository;

import com.vigidock.entity.ScanRecord;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, String> {

    @Override
    @EntityGraph(attributePaths = "vulnerabilities")
    Optional<ScanRecord> findById(String id);

    @EntityGraph(attributePaths = "vulnerabilities")
    List<ScanRecord> findAllByOrderByScannedAtDesc();
}


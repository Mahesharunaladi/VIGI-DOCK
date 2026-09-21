package com.vigidock.repository;

import com.vigidock.entity.ScanRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, String> {
    List<ScanRecord> findAllByOrderByScannedAtDesc();
}


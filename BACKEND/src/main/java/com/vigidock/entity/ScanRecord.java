package com.vigidock.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan_records")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanRecord {

    @Id
    private String scanId;

    @Column(nullable = false)
    private String target; // Docker image name or K8s file name

    @Column(nullable = false)
    private String scanType; // DOCKER_IMAGE or K8S_CONFIG

    private String status; // COMPLETED, FAILED, RUNNING

    private int totalVulnerabilities;
    private int criticalCount;
    private int highCount;
    private int mediumCount;
    private int lowCount;

    private String overallRiskScore;

    @Column(columnDefinition = "TEXT")
    private String aiSummary;

    @OneToMany(mappedBy = "scanRecord", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<VulnerabilityDetail> vulnerabilities = new ArrayList<>();

    @Builder.Default
    private LocalDateTime scannedAt = LocalDateTime.now();
}


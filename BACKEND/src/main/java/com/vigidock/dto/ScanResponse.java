package com.vigidock.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResponse {

    private String scanId;
    private String target;          // Docker Image tag or K8s File name
    private String scanType;        // DOCKER_IMAGE or K8S_CONFIG
    private String status;          // COMPLETED, FAILED, RUNNING
    private int totalVulnerabilities;
    private int criticalCount;
    private int highCount;
    private int mediumCount;
    private int lowCount;
    private List<VulnerabilityDto> vulnerabilities;
    private Map<String, Object> summary;
    private String overallRiskScore;
    private String aiSummary;
    private LocalDateTime scannedAt;
}


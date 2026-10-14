package com.vigidock.service;

import com.vigidock.dto.ScanResponse;
import com.vigidock.dto.VulnerabilityDto;
import com.vigidock.entity.ScanRecord;
import com.vigidock.entity.VulnerabilityDetail;
import com.vigidock.exception.ResourceNotFoundException;
import com.vigidock.repository.ScanRecordRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final TrivyScannerService trivyScannerService;
    private final EpssService epssService;
    private final ScanRecordRepository scanRecordRepository;

    @Transactional
    public ScanResponse scanDockerImage(String imageName) {
        ScanResponse response = trivyScannerService.scanDockerImage(imageName);
        epssService.enrichWithEpss(response);
        persist(response);
        return response;
    }

    @Transactional
    public ScanResponse scanKubernetesYaml(MultipartFile file) {
        ScanResponse response = trivyScannerService.scanKubernetesYaml(file);
        epssService.enrichWithEpss(response);
        persist(response);
        return response;
    }

    @Transactional(readOnly = true)
    public ScanResponse getScan(String scanId) {
        return toResponse(findRecord(scanId));
    }

    @Transactional(readOnly = true)
    public List<ScanResponse> listScans() {
        return scanRecordRepository.findAllByOrderByScannedAtDesc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public ScanRecord findRecord(String scanId) {
        return scanRecordRepository.findById(scanId)
                .orElseThrow(() -> new ResourceNotFoundException("Scan not found: " + scanId));
    }

    private void persist(ScanResponse response) {
        ScanRecord record = ScanRecord.builder()
                .scanId(response.getScanId())
                .target(response.getTarget())
                .scanType(response.getScanType())
                .status(response.getStatus())
                .totalVulnerabilities(response.getTotalVulnerabilities())
                .criticalCount(response.getCriticalCount())
                .highCount(response.getHighCount())
                .mediumCount(response.getMediumCount())
                .lowCount(response.getLowCount())
                .overallRiskScore(response.getOverallRiskScore())
                .aiSummary(response.getAiSummary())
                .scannedAt(response.getScannedAt())
                .vulnerabilities(new ArrayList<>())
                .build();

        if (response.getVulnerabilities() != null) {
            for (VulnerabilityDto dto : response.getVulnerabilities()) {
                VulnerabilityDetail detail = VulnerabilityDetail.builder()
                        .vulnerabilityId(dto.getVulnerabilityId())
                        .packageName(dto.getPkgName())
                        .installedVersion(dto.getInstalledVersion())
                        .fixedVersion(dto.getFixedVersion())
                        .severity(dto.getSeverity())
                        .title(dto.getTitle())
                        .description(dto.getDescription())
                        .primaryUrl(dto.getPrimaryUrl())
                        .cvssScore(dto.getCvssScore())
                        .epssScore(dto.getEpssScore())
                        .epssPercentile(dto.getEpssPercentile())
                        .threatTag(dto.getThreatTag())
                        .aiExplanation(dto.getAiExplanation())
                        .aiRemediation(dto.getAiRemediation())
                        .scanRecord(record)
                        .build();
                record.getVulnerabilities().add(detail);
            }
        }

        scanRecordRepository.save(record);
        log.info("Persisted scan {} with {} findings", record.getScanId(), record.getTotalVulnerabilities());
    }

    private ScanResponse toResponse(ScanRecord record) {
        List<VulnerabilityDto> findings = record.getVulnerabilities() == null ? List.of()
                : record.getVulnerabilities().stream()
                .map(detail -> VulnerabilityDto.builder()
                        .vulnerabilityId(detail.getVulnerabilityId())
                        .pkgName(detail.getPackageName())
                        .installedVersion(detail.getInstalledVersion())
                        .fixedVersion(detail.getFixedVersion())
                        .severity(detail.getSeverity())
                        .title(detail.getTitle())
                        .description(detail.getDescription())
                        .primaryUrl(detail.getPrimaryUrl())
                        .cvssScore(detail.getCvssScore())
                        .epssScore(detail.getEpssScore())
                        .epssPercentile(detail.getEpssPercentile())
                        .threatTag(detail.getThreatTag())
                        .aiExplanation(detail.getAiExplanation())
                        .aiRemediation(detail.getAiRemediation())
                        .build())
                .toList();

        return ScanResponse.builder()
                .scanId(record.getScanId())
                .target(record.getTarget())
                .scanType(record.getScanType())
                .status(record.getStatus())
                .totalVulnerabilities(record.getTotalVulnerabilities())
                .criticalCount(record.getCriticalCount())
                .highCount(record.getHighCount())
                .mediumCount(record.getMediumCount())
                .lowCount(record.getLowCount())
                .vulnerabilities(findings)
                .overallRiskScore(record.getOverallRiskScore())
                .aiSummary(record.getAiSummary())
                .scannedAt(record.getScannedAt())
                .build();
    }
}

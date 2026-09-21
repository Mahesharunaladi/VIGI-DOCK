package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanRequest;
import com.vigidock.dto.ScanResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScanController {

    @PostMapping("/docker")
    public ResponseEntity<ApiResponse<ScanResponse>> scanDockerImage(
            @Valid @RequestBody ScanRequest scanRequest) {
        log.info("Received request to scan Docker image: {}", scanRequest.getImageName());

        // Standardized placeholder response structure ready for TrivyScannerService injection
        ScanResponse response = ScanResponse.builder()
                .scanId(UUID.randomUUID().toString())
                .target(scanRequest.getImageName())
                .scanType("DOCKER_IMAGE")
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .criticalCount(0)
                .highCount(0)
                .mediumCount(0)
                .lowCount(0)
                .vulnerabilities(Collections.emptyList())
                .scannedAt(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ApiResponse.success(response, "Docker image scan initiated successfully"));
    }

    @PostMapping(value = "/k8s", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<ScanResponse>> scanKubernetesManifest(
            @RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Uploaded Kubernetes YAML manifest file cannot be empty");
        }

        String originalFilename = file.getOriginalFilename();
        log.info("Received request to scan Kubernetes manifest: {} (size: {} bytes)",
                originalFilename, file.getSize());

        ScanResponse response = ScanResponse.builder()
                .scanId(UUID.randomUUID().toString())
                .target(originalFilename != null ? originalFilename : "k8s-manifest.yaml")
                .scanType("K8S_CONFIG")
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .criticalCount(0)
                .highCount(0)
                .mediumCount(0)
                .lowCount(0)
                .vulnerabilities(Collections.emptyList())
                .scannedAt(LocalDateTime.now())
                .build();

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ApiResponse.success(response, "Kubernetes manifest scan initiated successfully"));
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ApiResponse<ScanResponse>> getScanResult(
            @PathVariable("scanId") String scanId) {
        log.info("Fetching scan report for ID: {}", scanId);

        ScanResponse response = ScanResponse.builder()
                .scanId(scanId)
                .target("sample-target")
                .scanType("DOCKER_IMAGE")
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .vulnerabilities(Collections.emptyList())
                .scannedAt(LocalDateTime.now())
                .build();

        return ResponseEntity.ok(ApiResponse.success(response, "Scan details retrieved successfully"));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<ScanResponse>>> listScans() {
        log.info("Retrieving all historical scan records");
        return ResponseEntity.ok(ApiResponse.success(Collections.emptyList(), "Scan records retrieved successfully"));
    }
}


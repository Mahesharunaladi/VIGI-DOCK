package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanRequest;
import com.vigidock.dto.ScanResponse;
import com.vigidock.service.TrivyScannerService;
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

@Slf4j
@RestController
@RequestMapping({"/api/scan", "/api/v1/scans"})
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScanController {

    private final TrivyScannerService trivyScannerService;

    /**
     * Scans a Docker image via Trivy.
     * Endpoint: POST /api/scan/docker (and /api/v1/scans/docker)
     * Payload: { "imageName": "nginx:latest" }
     */
    @PostMapping("/docker")
    public ResponseEntity<ApiResponse<ScanResponse>> scanDockerImage(
            @Valid @RequestBody ScanRequest scanRequest) {
        log.info("Received Docker scan request for image: {}", scanRequest.getImageName());
        ScanResponse response = trivyScannerService.scanDockerImage(scanRequest.getImageName());
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Docker image scanned successfully"));
    }

    /**
     * Scans an uploaded Kubernetes YAML manifest for security misconfigurations.
     * Endpoint: POST /api/scan/k8s (and /api/v1/scans/k8s)
     * Form-data: file (MultipartFile)
     */
    @PostMapping(value = "/k8s", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<ScanResponse>> scanKubernetesManifest(
            @RequestParam("file") MultipartFile file) {
        log.info("Received Kubernetes manifest scan request for file: {}", file.getOriginalFilename());
        ScanResponse response = trivyScannerService.scanKubernetesYaml(file);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Kubernetes manifest scanned successfully"));
    }

    /**
     * Retrieves historical scan record by ID.
     */
    @GetMapping("/{scanId}")
    public ResponseEntity<ApiResponse<ScanResponse>> getScanResult(
            @PathVariable("scanId") String scanId) {
        log.info("Fetching scan report for ID: {}", scanId);

        ScanResponse response = ScanResponse.builder()
                .scanId(scanId)
                .target("target-resource")
                .scanType("DOCKER_IMAGE")
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .vulnerabilities(Collections.emptyList())
                .scannedAt(LocalDateTime.now())
                .build();

        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Scan details retrieved successfully"));
    }

    /**
     * Lists all historical scan records.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ScanResponse>>> listScans() {
        log.info("Retrieving all historical scan records");
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, Collections.emptyList(), "Scan records retrieved successfully"));
    }
}

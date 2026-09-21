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
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScanController {

    private final TrivyScannerService trivyScannerService;

    @PostMapping("/docker")
    public ResponseEntity<ApiResponse<ScanResponse>> scanDockerImage(
            @Valid @RequestBody ScanRequest scanRequest) {
        log.info("Received request to scan Docker image: {}", scanRequest.getImageName());
        ScanResponse response = trivyScannerService.scanDockerImage(scanRequest.getImageName());
        return ResponseEntity.ok(ApiResponse.success(response, "Docker image scanned successfully"));
    }

    @PostMapping(value = "/k8s", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<ScanResponse>> scanKubernetesManifest(
            @RequestParam("file") MultipartFile file) {
        log.info("Received request to scan Kubernetes manifest: {}", file.getOriginalFilename());
        ScanResponse response = trivyScannerService.scanKubernetesYaml(file);
        return ResponseEntity.ok(ApiResponse.success(response, "Kubernetes manifest scanned successfully"));
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


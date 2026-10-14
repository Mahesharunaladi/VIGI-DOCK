package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanRequest;
import com.vigidock.dto.ScanResponse;
import com.vigidock.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Slf4j
@RestController
@RequestMapping({"/api/scan", "/api/v1/scans"})
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;

    @PostMapping("/docker")
    public ResponseEntity<ApiResponse<ScanResponse>> scanDockerImage(
            @Valid @RequestBody ScanRequest scanRequest) {
        log.info("Received Docker scan request for image: {}", scanRequest.getImageName());
        ScanResponse response = scanService.scanDockerImage(scanRequest.getImageName());
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Docker image scanned successfully"));
    }

    @PostMapping(value = "/k8s", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<ScanResponse>> scanKubernetesManifest(
            @RequestParam("file") MultipartFile file) {
        log.info("Received Kubernetes manifest scan request for file: {}", file.getOriginalFilename());
        ScanResponse response = scanService.scanKubernetesYaml(file);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Kubernetes manifest scanned successfully"));
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ApiResponse<ScanResponse>> getScanResult(
            @PathVariable("scanId") String scanId) {
        log.info("Fetching scan report for ID: {}", scanId);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, scanService.getScan(scanId), "Scan details retrieved successfully"));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<ScanResponse>>> listScans() {
        log.info("Retrieving all historical scan records");
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, scanService.listScans(), "Scan records retrieved successfully"));
    }
}

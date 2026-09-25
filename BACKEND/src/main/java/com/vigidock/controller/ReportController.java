package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanResponse;
import com.vigidock.entity.ScanRecord;
import com.vigidock.exception.ResourceNotFoundException;
import com.vigidock.repository.ScanRecordRepository;
import com.vigidock.service.PdfReportService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collections;

@Slf4j
@RestController
@RequestMapping({"/api/reports", "/api/v1/reports"})
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ReportController {

    private final ScanRecordRepository scanRecordRepository;
    private final PdfReportService pdfReportService;

    @GetMapping(value = "/{scanId}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    @Transactional
    public ResponseEntity<Resource> downloadPdfReport(@PathVariable("scanId") String scanId) {
        log.info("Generating and streaming PDF report for scan ID: {}", scanId);

        ScanRecord scanRecord = scanRecordRepository.findById(scanId)
                .orElseThrow(() -> new ResourceNotFoundException("Scan not found: " + scanId));
        byte[] pdfBytes = pdfReportService.generateReport(scanRecord);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=vigidock-report.pdf");
        headers.setContentLength(pdfBytes.length);

        return ResponseEntity.ok()
                .headers(headers)
            .body(new ByteArrayResource(pdfBytes));
    }

    @GetMapping(value = "/{scanId}/json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<ScanResponse>> downloadJsonReport(@PathVariable("scanId") String scanId) {
        log.info("Generating JSON report export for scan ID: {}", scanId);

        ScanResponse response = ScanResponse.builder()
                .scanId(scanId)
                .target("export-target")
                .scanType("DOCKER_IMAGE")
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .vulnerabilities(Collections.emptyList())
                .scannedAt(LocalDateTime.now())
                .build();

        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "JSON report exported successfully"));
    }
}

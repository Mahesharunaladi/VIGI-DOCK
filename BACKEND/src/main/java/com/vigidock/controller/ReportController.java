package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Collections;

@Slf4j
@RestController
@RequestMapping("/api/v1/reports")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ReportController {

    @GetMapping(value = "/{scanId}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> downloadPdfReport(@PathVariable("scanId") String scanId) {
        log.info("Generating and streaming PDF report for scan ID: {}", scanId);

        // Placeholder byte buffer for PDF document (ready to be hooked to PdfReportService)
        byte[] pdfBytes = ("%PDF-1.4\n% VigiDock AI Security Report for Scan: " + scanId + "\n%%EOF")
                .getBytes(StandardCharsets.UTF_8);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDispositionFormData("attachment", "vigidock-security-report-" + scanId + ".pdf");
        headers.setContentLength(pdfBytes.length);

        return ResponseEntity.ok()
                .headers(headers)
                .body(pdfBytes);
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

        return ResponseEntity.ok(ApiResponse.success(response, "JSON report exported successfully"));
    }
}


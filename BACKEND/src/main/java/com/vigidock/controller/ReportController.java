package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanResponse;
import com.vigidock.entity.ScanRecord;
import com.vigidock.service.PdfReportService;
import com.vigidock.service.ScanService;
import com.vigidock.service.GcsReportStorageService;
import org.springframework.beans.factory.ObjectProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping({"/api/reports", "/api/v1/reports"})
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"}, exposedHeaders = {"Content-Disposition", "Content-Length", "Content-Type"}, allowCredentials = "true")
@RequiredArgsConstructor
public class ReportController {

    private final ScanService scanService;
    private final PdfReportService pdfReportService;
    private final ObjectProvider<GcsReportStorageService> gcsStorage;

    @GetMapping(value = "/cloud-url/{scanId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<java.util.Map<String, String>>> cloudUrl(@PathVariable String scanId) {
        ScanRecord record = scanService.findRecord(scanId);
        byte[] bytes = pdfReportService.generateReport(record);
        GcsReportStorageService storage = gcsStorage.getIfAvailable();
        if (storage == null) {
            return ResponseEntity.ok(ApiResponse.success(java.util.Map.of("downloadUrl", "/api/reports/download/" + scanId), "Cloud storage is not configured; use direct PDF download"));
        }
        try {
            String url = storage.uploadAndSign(scanId, bytes).toString();
            return ResponseEntity.ok(ApiResponse.success(java.util.Map.of("url", url), "Signed report URL expires in 15 minutes"));
        } catch (RuntimeException ex) {
            log.warn("GCS report archival unavailable for {}: {}", scanId, ex.getMessage());
            return ResponseEntity.ok(ApiResponse.success(java.util.Map.of("downloadUrl", "/api/reports/download/" + scanId), "Cloud archival unavailable; use direct PDF download"));
        }
    }

    @GetMapping(value = {"/download/{scanId}", "/{scanId}/pdf"}, produces = {MediaType.APPLICATION_PDF_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE, MediaType.ALL_VALUE})
    @Transactional(readOnly = true)
    public ResponseEntity<Resource> downloadPdfReport(@PathVariable("scanId") String scanId) {
        log.info("Generating and streaming PDF report for scan ID: {}", scanId);

        ScanRecord scanRecord = scanService.findRecord(scanId);
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

        ScanResponse response = scanService.getScan(scanId);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "JSON report exported successfully"));
    }
}

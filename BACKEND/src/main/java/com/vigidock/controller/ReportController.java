package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.ScanResponse;
import com.vigidock.entity.ScanRecord;
import com.vigidock.service.PdfReportService;
import com.vigidock.service.ScanService;
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
@RequiredArgsConstructor
public class ReportController {

    private final ScanService scanService;
    private final PdfReportService pdfReportService;

    @GetMapping(value = {"/download/{scanId}", "/{scanId}/pdf"}, produces = MediaType.APPLICATION_PDF_VALUE)
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

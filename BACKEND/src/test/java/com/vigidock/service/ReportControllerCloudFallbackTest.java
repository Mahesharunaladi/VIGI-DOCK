package com.vigidock.service;

import com.google.cloud.storage.Storage;
import com.vigidock.controller.ReportController;
import com.vigidock.entity.ScanRecord;
import com.vigidock.dto.ApiResponse;
import com.vigidock.service.GcsReportStorageService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReportControllerCloudFallbackTest {
    @Test void returnsDirectDownloadWhenCloudUploadFails() {
        ScanService scans = mock(ScanService.class);
        PdfReportService pdf = mock(PdfReportService.class);
        @SuppressWarnings("unchecked") ObjectProvider<GcsReportStorageService> provider = mock(ObjectProvider.class);
        GcsReportStorageService gcs = mock(GcsReportStorageService.class);
        when(scans.findRecord("scan-1")).thenReturn(ScanRecord.builder().scanId("scan-1").target("image").scanType("DOCKER_IMAGE").build());
        when(pdf.generateReport(any())).thenReturn(new byte[]{1, 2});
        when(provider.getIfAvailable()).thenReturn(gcs);
        when(gcs.uploadAndSign(eq("scan-1"), any())).thenThrow(new IllegalStateException("storage unavailable"));

        var response = new ReportController(scans, pdf, provider).cloudUrl("scan-1");
        ApiResponse<?> body = response.getBody();
        assertNotNull(body);
        assertEquals("/api/reports/download/scan-1", ((java.util.Map<?, ?>) body.getData()).get("downloadUrl"));
    }
}

package com.vigidock.service;

import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.concurrent.TimeUnit;

@Service
@ConditionalOnProperty(name = "vigidock.gcp.gcs-report-bucket")
public class GcsReportStorageService {
    private final Storage storage;
    private final String bucket;
    public GcsReportStorageService(@Value("${vigidock.gcp.gcs-report-bucket}") String bucket) {
        this.bucket = bucket;
        this.storage = StorageOptions.getDefaultInstance().getService();
    }
    public URL uploadAndSign(String scanId, byte[] pdfBytes) {
        String object = "reports/" + scanId + "/vigidock-report.pdf";
        BlobInfo info = BlobInfo.newBuilder(BlobId.of(bucket, object)).setContentType("application/pdf").build();
        storage.create(info, pdfBytes);
        return storage.signUrl(info, 15, TimeUnit.MINUTES, Storage.SignUrlOption.withV4Signature());
    }
}

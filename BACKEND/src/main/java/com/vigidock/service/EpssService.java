package com.vigidock.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vigidock.dto.EpssScore;
import com.vigidock.dto.ScanResponse;
import com.vigidock.dto.VulnerabilityDto;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class EpssService {

    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-\\d{4}-\\d{4,}$", Pattern.CASE_INSENSITIVE);
    static final String ACTIVE_THREAT = "ACTIVE_THREAT";
    static final String THEORETICAL_RISK = "THEORETICAL_RISK";
    static final String MONITORED = "MONITORED";

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    private final ExecutorService executor = Executors.newFixedThreadPool(
            Math.min(8, Math.max(2, Runtime.getRuntime().availableProcessors())),
            runnable -> {
                Thread thread = new Thread(runnable, "epss-enricher");
                thread.setDaemon(true);
                return thread;
            }
    );

    @Value("${vigidock.epss.api-url:https://api.first.org/data/v1/epss}")
    private String epssApiUrl;

    public void enrichWithEpss(ScanResponse scanResponse) {
        if (scanResponse == null || scanResponse.getVulnerabilities() == null || scanResponse.getVulnerabilities().isEmpty()) {
            return;
        }

        List<CompletableFuture<Void>> futures = scanResponse.getVulnerabilities().stream()
                .filter(finding -> isCve(finding.getVulnerabilityId()))
                .map(finding -> CompletableFuture.runAsync(() -> enrichFinding(finding), executor)
                        .exceptionally(error -> {
                            log.warn("EPSS enrichment failed for {}: {}", finding.getVulnerabilityId(), error.getMessage());
                            return null;
                        }))
                .toList();

        if (!futures.isEmpty()) {
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        }
    }

    public EpssScore fetchEpss(String cveId) {
        if (!isCve(cveId)) {
            return null;
        }

        URI uri = UriComponentsBuilder.fromUriString(epssApiUrl)
                .queryParam("cve", cveId)
                .build(true)
                .toUri();

        try {
            String body = restTemplate.getForObject(uri, String.class);
            if (!StringUtils.hasText(body)) {
                return null;
            }

            JsonNode data = objectMapper.readTree(body).path("data");
            if (!data.isArray() || data.isEmpty()) {
                return null;
            }

            JsonNode first = data.get(0);
            Double epss = parseDouble(first.path("epss").asText(null));
            Double percentile = parseDouble(first.path("percentile").asText(null));
            return EpssScore.builder()
                    .cveId(cveId)
                    .epss(epss)
                    .percentile(percentile)
                    .build();
        } catch (Exception e) {
            log.warn("FIRST EPSS API lookup failed for {}: {}", cveId, e.getMessage());
            return null;
        }
    }

    public String resolveThreatTag(Double cvssScore, Double epssScore) {
        if (cvssScore == null || epssScore == null) {
            return null;
        }
        if (cvssScore >= 7.0 && epssScore > 0.50) {
            return ACTIVE_THREAT;
        }
        if (cvssScore >= 7.0 && epssScore < 0.05) {
            return THEORETICAL_RISK;
        }
        return MONITORED;
    }

    private void enrichFinding(VulnerabilityDto finding) {
        EpssScore score = fetchEpss(finding.getVulnerabilityId());
        if (score == null) {
            return;
        }
        finding.setEpssScore(score.getEpss());
        finding.setEpssPercentile(score.getPercentile());
        finding.setThreatTag(resolveThreatTag(finding.getCvssScore(), score.getEpss()));
    }

    private boolean isCve(String vulnerabilityId) {
        return StringUtils.hasText(vulnerabilityId) && CVE_PATTERN.matcher(vulnerabilityId.trim()).matches();
    }

    private Double parseDouble(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}

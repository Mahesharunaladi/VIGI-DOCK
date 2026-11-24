package com.vigidock.service;

import com.vigidock.dto.AnsibleDeployRequest;
import com.vigidock.entity.ScanRecord;
import com.vigidock.exception.AnsibleExecutionException;
import com.vigidock.repository.ScanRecordRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AnsibleRemediationService {
    private final ScanRecordRepository records;
    @Value("${vigidock.ansible.enabled:false}") private boolean enabled;
    @Value("${vigidock.ansible.binary-path:ansible-playbook}") private String ansible;
    @Value("${vigidock.ansible.playbook-dir:src/main/resources/ansible/playbooks}") private String playbookDir;
    @Value("${vigidock.ansible.timeout-seconds:120}") private long timeoutSeconds;
    @Value("${vigidock.gcp.project-id:}") private String projectId;
    @Value("${vigidock.gcp.gke-cluster-name:vigidock-cluster}") private String cluster;
    @Value("${vigidock.gcp.gke-zone:asia-south1-a}") private String zone;

    public Map<String, Object> deployHardenedK8sManifest(AnsibleDeployRequest request) {
        if (!enabled) throw new AnsibleExecutionException("Ansible remediation is disabled");
        String env = request.getTargetEnvironment() == null ? "LOCAL" : request.getTargetEnvironment().toUpperCase(Locale.ROOT);
        if (!Set.of("LOCAL", "GKE").contains(env)) throw new IllegalArgumentException("targetEnvironment must be LOCAL or GKE");
        Path manifest = null, kubeconfig = null, logFile = null;
        long started = System.nanoTime();
        String output = "";
        boolean ok = false;
        try {
            manifest = Files.createTempFile("vigidock-manifest-", ".yaml");
            logFile = Files.createTempFile("vigidock-ansible-", ".log");
            Files.writeString(manifest, request.getManifestYaml());
            List<String> args = new ArrayList<>(List.of(ansible, "-i", "localhost,", "-c", "local", "-e",
                    "manifest_path=" + manifest.toAbsolutePath(), "-e", "target_namespace=" + safe(request.getTargetNamespace(), "default"),
                    "-e", "use_gke=" + env.equals("GKE"), "-e", "gke_cluster_name=" + cluster,
                    "-e", "gke_zone=" + zone, "-e", "gcp_project_id=" + projectId,
                    Path.of(playbookDir, "remediate-k8s.yml").toString()));
            ProcessBuilder pb = new ProcessBuilder(args).redirectErrorStream(true).redirectOutput(logFile.toFile());
            pb.environment().put("ANSIBLE_CONFIG", Path.of(playbookDir).getParent().resolve("ansible.cfg").toAbsolutePath().toString());
            if (env.equals("GKE")) {
                kubeconfig = Files.createTempFile("vigidock-kubeconfig-", ".yaml");
                pb.environment().put("KUBECONFIG", kubeconfig.toString());
                pb.environment().put("USE_GKE_GCLOUD_AUTH_PLUGIN", "True");
            }
            Process process = pb.start();
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) { process.destroyForcibly(); throw new AnsibleExecutionException("Ansible remediation timed out"); }
            output = Files.readString(logFile);
            if (process.exitValue() != 0) throw new AnsibleExecutionException("Ansible remediation failed: " + output);
            ok = true;
            return Map.of("status", "COMPLETED", "targetEnvironment", env, "executionMillis", TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started), "logs", output);
        } catch (IOException e) {
            throw new AnsibleExecutionException("Could not execute Ansible remediation: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); throw new AnsibleExecutionException("Ansible remediation interrupted", e);
        } finally {
            String state = ok ? "REMEDIATED" : "REMEDIATION_FAILED";
            String scanId = request.getScanId() == null || request.getScanId().isBlank() ? UUID.randomUUID().toString() : request.getScanId();
            ScanRecord rec = ScanRecord.builder().scanId(scanId).target("Kubernetes " + env).scanType("REMEDIATION")
                    .status(state).aiSummary(output).scannedAt(LocalDateTime.now()).build();
            records.save(rec);
            delete(manifest); delete(kubeconfig); delete(logFile);
        }
    }

    public Map<String, Object> runHostHardeningCheck() {
        try {
            Process process = new ProcessBuilder(ansible, "-i", "localhost,", "-c", "local", Path.of(playbookDir, "harden-docker-host.yml").toString()).redirectErrorStream(true).start();
            boolean done = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!done) { process.destroyForcibly(); throw new AnsibleExecutionException("Host hardening check timed out"); }
            String logs = new String(process.getInputStream().readAllBytes());
            if (process.exitValue()!=0) throw new AnsibleExecutionException("Host hardening check failed: " + logs);
            return Map.of("status", "COMPLETED", "logs", logs);
        } catch (IOException e) { throw new AnsibleExecutionException("Could not execute host hardening check", e); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AnsibleExecutionException("Host hardening check interrupted", e); }
    }
    private String safe(String value, String fallback) { return value == null || value.isBlank() ? fallback : value.replaceAll("[^A-Za-z0-9._-]", ""); }
    private void delete(Path p) { if (p != null) try { Files.deleteIfExists(p); } catch (IOException ignored) {} }
}

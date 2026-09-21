const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const TRIVY_BIN = process.env.TRIVY_BINARY_PATH || 'trivy';
const ENABLE_MOCK_FALLBACK = process.env.ENABLE_MOCK_FALLBACK !== 'false';

/**
 * Checks whether Trivy binary is available in the system PATH.
 */
const isTrivyAvailable = async () => {
  try {
    await execPromise(`${TRIVY_BIN} --version`);
    return true;
  } catch {
    return false;
  }
};

/**
 * Calculates a security health score from 0-100 based on severity counts.
 */
const calculateSecurityScore = ({ critical = 0, high = 0, medium = 0, low = 0 }) => {
  const penalty = (critical * 25) + (high * 10) + (medium * 3) + (low * 1);
  const score = Math.max(0, 100 - penalty);
  return Math.round(score);
};

/**
 * Normalizes raw Trivy JSON report into unified format.
 */
const parseTrivyOutput = (rawReport) => {
  const vulnerabilities = [];
  const misconfigurations = [];
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;

  if (rawReport && Array.isArray(rawReport.Results)) {
    for (const result of rawReport.Results) {
      if (Array.isArray(result.Vulnerabilities)) {
        for (const vuln of result.Vulnerabilities) {
          const sev = (vuln.Severity || 'UNKNOWN').toUpperCase();
          if (sev === 'CRITICAL') critical++;
          else if (sev === 'HIGH') high++;
          else if (sev === 'MEDIUM') medium++;
          else if (sev === 'LOW') low++;

          vulnerabilities.push({
            vulnerabilityId: vuln.VulnerabilityID || 'N/A',
            pkgName: vuln.PkgName || 'Unknown Package',
            installedVersion: vuln.InstalledVersion || 'N/A',
            fixedVersion: vuln.FixedVersion || 'None',
            severity: sev,
            title: vuln.Title || vuln.VulnerabilityID || 'Vulnerability',
            description: vuln.Description || 'No description provided.',
            primaryUrl: vuln.PrimaryURL || '',
            remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to version ${vuln.FixedVersion}` : 'No known fix version available yet.',
          });
        }
      }

      if (Array.isArray(result.Misconfigurations)) {
        for (const mis of result.Misconfigurations) {
          const sev = (mis.Severity || 'UNKNOWN').toUpperCase();
          if (sev === 'CRITICAL') critical++;
          else if (sev === 'HIGH') high++;
          else if (sev === 'MEDIUM') medium++;
          else if (sev === 'LOW') low++;

          misconfigurations.push({
            id: mis.ID || 'MISCONFIG',
            title: mis.Title || 'Configuration Issue',
            description: mis.Description || '',
            message: mis.Message || '',
            severity: sev,
            resolution: mis.Resolution || 'Review security configuration guidelines.',
            status: mis.Status || 'FAIL',
          });
        }
      }
    }
  }

  const summary = {
    critical,
    high,
    medium,
    low,
    totalVulnerabilities: vulnerabilities.length,
    totalMisconfigurations: misconfigurations.length,
    securityScore: calculateSecurityScore({ critical, high, medium, low }),
  };

  return {
    summary,
    vulnerabilities,
    misconfigurations,
    rawOutput: rawReport,
  };
};

/**
 * Generate simulated scan results for local testing when Trivy is not installed.
 */
const getSimulatedScan = (target, targetType) => {
  const isK8s = targetType === 'kubernetes-yaml';
  
  const vulnerabilities = isK8s ? [] : [
    {
      vulnerabilityId: 'CVE-2024-21626',
      pkgName: 'runc',
      installedVersion: '1.1.11',
      fixedVersion: '1.1.12',
      severity: 'CRITICAL',
      title: 'runc container breakout via internal file descriptor leak',
      description: 'A flaw in runc allows an attacker in a container to overwrite host binary and escalate privileges.',
      primaryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
      remediation: 'Upgrade runc to version >= 1.1.12 or use updated container base image.',
    },
    {
      vulnerabilityId: 'CVE-2023-44487',
      pkgName: 'nghttp2',
      installedVersion: '1.51.0',
      fixedVersion: '1.57.0',
      severity: 'HIGH',
      title: 'HTTP/2 Rapid Reset Denial of Service',
      description: 'The HTTP/2 protocol is susceptible to a reset flood attack enabling Denial of Service.',
      primaryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487',
      remediation: 'Upgrade nghttp2 package to 1.57.0 or apply web server patches.',
    },
    {
      vulnerabilityId: 'CVE-2023-38545',
      pkgName: 'curl',
      installedVersion: '7.88.1',
      fixedVersion: '8.4.0',
      severity: 'HIGH',
      title: 'curl SOCKS5 heap buffer overflow',
      description: 'A heap-based buffer overflow flaw was found in the SOCKS5 proxy handshake in curl.',
      primaryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38545',
      remediation: 'Upgrade libcurl / curl to 8.4.0 or rebuild container with latest security updates.',
    },
    {
      vulnerabilityId: 'CVE-2023-29491',
      pkgName: 'ncurses',
      installedVersion: '6.4-r0',
      fixedVersion: '6.4-r1',
      severity: 'MEDIUM',
      title: 'ncurses minor heap out-of-bounds read',
      description: 'Minor boundary condition issue in ncurses terminal formatting strings.',
      primaryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-29491',
      remediation: 'Upgrade package ncurses to 6.4-r1.',
    }
  ];

  const misconfigurations = [
    {
      id: 'KSV001',
      title: 'Container Running as Root',
      description: 'Running container processes as root provides excessive privileges to attackers on compromised pods.',
      message: 'Container should set securityContext.runAsNonRoot to true',
      severity: 'HIGH',
      resolution: 'Set securityContext.runAsNonRoot=true and specify securityContext.runAsUser with UID > 10000',
      status: 'FAIL',
    },
    {
      id: 'KSV012',
      title: 'Missing Memory and CPU Resource Limits',
      description: 'Containers without resource limits can cause Denial of Service to neighboring cluster workloads.',
      message: 'Resources limits.memory and limits.cpu not defined',
      severity: 'MEDIUM',
      resolution: 'Define explicit resource limits and requests in pod specification.',
      status: 'FAIL',
    },
    {
      id: 'KSV014',
      title: 'Root File System is Writable',
      description: 'A writable root filesystem allows malware or attackers to modify binaries and persist changes.',
      message: 'Container should set securityContext.readOnlyRootFilesystem to true',
      severity: 'LOW',
      resolution: 'Set securityContext.readOnlyRootFilesystem=true and mount emptyDir on /tmp if needed.',
      status: 'FAIL',
    }
  ];

  let critical = 0, high = 0, medium = 0, low = 0;
  [...vulnerabilities, ...misconfigurations].forEach(item => {
    if (item.severity === 'CRITICAL') critical++;
    else if (item.severity === 'HIGH') high++;
    else if (item.severity === 'MEDIUM') medium++;
    else if (item.severity === 'LOW') low++;
  });

  return {
    summary: {
      critical,
      high,
      medium,
      low,
      totalVulnerabilities: vulnerabilities.length,
      totalMisconfigurations: misconfigurations.length,
      securityScore: calculateSecurityScore({ critical, high, medium, low }),
    },
    vulnerabilities,
    misconfigurations,
    rawOutput: { simulated: true, target, targetType },
  };
};

const TrivyService = {
  /**
   * Scan a Docker container image.
   * @param {string} imageName - Docker image tag, e.g., 'nginx:alpine'
   */
  async scanImage(imageName) {
    const hasTrivy = await isTrivyAvailable();
    if (!hasTrivy) {
      if (ENABLE_MOCK_FALLBACK) {
        console.warn(`[TrivyService] Trivy CLI not detected. Returning simulated scan for image: ${imageName}`);
        return getSimulatedScan(imageName, 'docker-image');
      }
      throw new Error('Trivy CLI is not installed on this system. Install Trivy or enable ENABLE_MOCK_FALLBACK in .env.');
    }

    try {
      const cmd = `${TRIVY_BIN} image --format json --quiet ${imageName}`;
      const { stdout } = await execPromise(cmd, { maxBuffer: 1024 * 1024 * 20 });
      const parsedJson = JSON.parse(stdout);
      return parseTrivyOutput(parsedJson);
    } catch (err) {
      if (err.stdout) {
        try {
          const parsed = JSON.parse(err.stdout);
          return parseTrivyOutput(parsed);
        } catch {
          // fall through
        }
      }
      throw new Error(`Trivy image scan failed: ${err.message}`);
    }
  },

  /**
   * Scan Kubernetes YAML or Dockerfile configuration.
   * @param {string} filePath - Path to the YAML or Dockerfile
   * @param {string} targetType - 'kubernetes-yaml' or 'dockerfile'
   */
  async scanConfigFile(filePath, targetType = 'kubernetes-yaml') {
    const hasTrivy = await isTrivyAvailable();
    if (!hasTrivy) {
      if (ENABLE_MOCK_FALLBACK) {
        console.warn(`[TrivyService] Trivy CLI not detected. Returning simulated config scan for: ${filePath}`);
        return getSimulatedScan(filePath, targetType);
      }
      throw new Error('Trivy CLI is not installed on this system. Install Trivy or enable ENABLE_MOCK_FALLBACK in .env.');
    }

    try {
      const cmd = `${TRIVY_BIN} config --format json --quiet "${filePath}"`;
      const { stdout } = await execPromise(cmd, { maxBuffer: 1024 * 1024 * 20 });
      const parsedJson = JSON.parse(stdout);
      return parseTrivyOutput(parsedJson);
    } catch (err) {
      if (err.stdout) {
        try {
          const parsed = JSON.parse(err.stdout);
          return parseTrivyOutput(parsed);
        } catch {
          // fall through
        }
      }
      throw new Error(`Trivy config scan failed: ${err.message}`);
    }
  },
};

module.exports = TrivyService;

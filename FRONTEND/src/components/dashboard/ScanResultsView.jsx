import { AlertTriangle, Bot, CircleCheck, ExternalLink, ShieldAlert } from 'lucide-react'

const value = (item, ...keys) => keys.map((key) => item?.[key]).find((itemValue) => itemValue !== undefined && itemValue !== null && itemValue !== '')
const numberValue = (item, ...keys) => Number(value(item, ...keys) || 0)
const severityClass = (severity) => String(severity || 'unknown').toLowerCase()

function threatFor(finding) {
  const cvss = numberValue(finding, 'cvssScore', 'cvss')
  const epss = numberValue(finding, 'epssScore', 'epss')
  const probability = epss <= 1 ? epss * 100 : epss
  if (cvss >= 7 && probability > 50) return { label: 'ACTIVE THREAT', className: 'active-threat' }
  if (cvss >= 7 && probability < 5) return { label: 'THEORETICAL RISK', className: 'theoretical-risk' }
  return { label: value(finding, 'threatTag') || 'MONITORED', className: 'monitored' }
}

export default function ScanResultsView({ scan, onExplain }) {
  if (!scan) return <div className="results-empty"><ShieldAlert size={23} /><h3>Your security results will appear here</h3><p>Run an image or manifest audit to review vulnerabilities, EPSS probability, and remediation guidance.</p></div>
  const findings = scan.vulnerabilities || []
  const counts = { critical: scan.criticalCount ?? findings.filter((f) => severityClass(f.severity) === 'critical').length, high: scan.highCount ?? findings.filter((f) => severityClass(f.severity) === 'high').length, medium: scan.mediumCount ?? findings.filter((f) => severityClass(f.severity) === 'medium').length, low: scan.lowCount ?? findings.filter((f) => severityClass(f.severity) === 'low').length }
  const total = scan.totalVulnerabilities ?? findings.length
  const risk = total === 0 ? { label: 'PASSED', className: 'safe' } : counts.critical || counts.high ? { label: counts.critical ? 'ACTIVE THREATS DETECTED' : 'ACTION REQUIRED', className: 'danger' } : { label: 'ACTION REQUIRED', className: 'warning' }

  return <section className="results-panel"><div className="results-header"><div><p className="eyebrow">SCAN RESULTS</p><h2>{scan.target || 'Security scan'}</h2><span>{scan.scanType === 'K8S_CONFIG' ? 'Kubernetes manifest' : 'Container image'} · {scan.scannedAt ? new Date(scan.scannedAt).toLocaleString() : 'Just now'}</span></div><div className={`risk-tag ${risk.className}`}>{risk.className === 'safe' ? <CircleCheck size={14} /> : <AlertTriangle size={14} />}{risk.label}</div></div><div className="executive-bar"><div className="total-risk"><strong>{total}</strong><span>Total vulnerabilities</span></div>{[['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([key, label]) => <div className={`summary-count ${key}`} key={key}><b>{counts[key]}</b><span>{label}</span></div>)}</div><div className="matrix-heading"><div><p className="eyebrow">EPSS RISK MATRIX</p><h3>Prioritized findings</h3></div><span>{findings.length} finding{findings.length === 1 ? '' : 's'}</span></div>{findings.length === 0 ? <div className="results-empty compact"><CircleCheck size={22} /><h3>No vulnerabilities detected</h3><p>This target passed the current security checks.</p></div> : <div className="risk-table-wrap"><table className="risk-table"><thead><tr><th>CVE ID</th><th>Severity (CVSS)</th><th>Exploit probability</th><th>Threat tag</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Actions</th></tr></thead><tbody>{findings.map((finding, index) => { const threat = threatFor(finding); const epss = numberValue(finding, 'epssScore', 'epss'); const probability = epss <= 1 ? epss * 100 : epss; return <tr key={`${value(finding, 'vulnerabilityId', 'id')}-${index}`}><td><strong>{value(finding, 'vulnerabilityId', 'id') || 'Finding'}</strong><a href={finding.primaryUrl} target="_blank" rel="noreferrer" aria-label="Open vulnerability reference"><ExternalLink size={12} /></a></td><td><span className={`severity-chip ${severityClass(finding.severity)}`}>{value(finding, 'severity') || 'UNKNOWN'} <b>{numberValue(finding, 'cvssScore', 'cvss').toFixed(1)}</b></span></td><td><strong>{probability.toFixed(1)}%</strong><div className="probability-track"><i style={{ width: `${Math.min(probability, 100)}%` }} /></div></td><td><span className={`threat-tag ${threat.className}`}>{threat.label}</span></td><td>{value(finding, 'pkgName', 'packageName') || '—'}</td><td>{value(finding, 'installedVersion') || '—'}</td><td>{value(finding, 'fixedVersion') || 'Not fixed'}</td><td><button className="ai-action" onClick={() => onExplain(finding)}><Bot size={14} /> Explain with AI</button></td></tr> })}</tbody></table></div>}</section>
}

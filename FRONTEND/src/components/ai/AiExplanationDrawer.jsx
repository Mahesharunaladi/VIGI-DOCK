import { useEffect, useMemo, useState } from 'react'
import { Bot, Check, Copy, Download, LoaderCircle, X } from 'lucide-react'
import { dashboardApi } from '../../api'

const field = (item, ...keys) => keys.map((key) => item?.[key]).find((value) => value !== undefined && value !== null && value !== '')

export default function AiExplanationDrawer({ scan, finding, onClose, onError }) {
  const [tab, setTab] = useState('summary')
  const [analysis, setAnalysis] = useState(null)
  const [patch, setPatch] = useState(null)
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState(false)
  const isKubernetes = scan?.scanType === 'K8S_CONFIG' || scan?.scanType === 'KUBERNETES' || Boolean(field(finding, 'misconfigRule', 'ruleId') || String(field(finding, 'vulnerabilityId', 'id') || '').startsWith('KSV'))
  const findingId = field(finding, 'vulnerabilityId', 'id', 'misconfigRule', 'ruleId') || 'Security finding'
  const packageName = field(finding, 'pkgName', 'packageName') || (isKubernetes ? 'Kubernetes configuration' : scan?.target) || 'Security finding'

  const fallbackPatch = useMemo(() => field(analysis, 'patchedManifestSnippet', 'unifiedDiff', 'recommendedFix', 'remediation') || field(finding, 'aiRemediation') || 'No automated patch was returned for this finding.', [analysis, finding])
  const summary = field(analysis, 'plainEnglishSummary', 'summary') || field(finding, 'description') || 'This finding may affect the security posture of the scanned workload.'
  const impact = field(analysis, 'impactAnalysis', 'impact') || 'An attacker could use this weakness to affect the workload depending on exposure, privileges, and runtime configuration.'
  const recommendation = field(analysis, 'recommendedFix', 'remediation') || field(finding, 'aiRemediation') || 'Apply the fixed version or hardened configuration, then rebuild and rescan the workload.'

  useEffect(() => {
    let cancelled = false
    const loadAnalysis = async () => {
      setLoading(true); setAnalysis(null); setPatch(null)
      if (finding.demo) {
        setAnalysis({
          plainEnglishSummary: 'This sample finding demonstrates how an outdated OpenSSL package can expose a container to known attacks. In a real scan, this text is generated from the vulnerability metadata.',
          impactAnalysis: 'If an attacker can reach the application, the vulnerable package may be used as a stepping stone to read data or execute code inside the container.',
          recommendedFix: 'Upgrade the base image to a patched tag containing OpenSSL 3.0.13, rebuild the image, and rescan it before release.',
        })
        setPatch({ unifiedDiff: '- FROM nginx:1.19\n+ FROM nginx:1.25-alpine\n\n# Rebuild with the patched OpenSSL package\n+ RUN apk upgrade --no-cache openssl' })
        setLoading(false)
        return
      }
      try {
        const response = isKubernetes
          ? await dashboardApi.explainKubernetes({
              misconfigRule: field(finding, 'misconfigRule', 'ruleId', 'title', 'vulnerabilityId') || findingId,
              yamlContent: field(finding, 'yamlContent', 'patchedManifestSnippet') || '',
              resourceName: scan?.target || '',
              severity: finding?.severity || 'UNKNOWN',
            })
          : await dashboardApi.explainCve(finding)
        if (!cancelled) setAnalysis(response)
        try {
          const generatedPatch = await dashboardApi.generatePatch(isKubernetes
            ? { patchType: 'K8S', originalYaml: field(finding, 'yamlContent') || '', misconfigRule: findingId }
            : { patchType: 'DOCKERFILE', vulnerablePackage: packageName, fixedVersion: field(finding, 'fixedVersion') || '' })
          if (!cancelled) setPatch(generatedPatch)
        } catch { /* AI analysis remains useful if a concrete patch is unavailable. */ }
      } catch (error) {
        if (!cancelled) onError(error.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    loadAnalysis()
    return () => { cancelled = true }
  }, [finding, scan, isKubernetes, findingId, packageName, onError])

  if (!finding) return null
  const codeDiff = field(patch, 'unifiedDiff', 'patchedContent') || fallbackPatch
  const copyPatch = async () => {
    try { await navigator.clipboard.writeText(codeDiff) } catch { onError('Copy is unavailable in this browser') }
    setCopied(true); window.setTimeout(() => setCopied(false), 1800)
  }

  return <div className="drawer-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="ai-drawer" role="dialog" aria-modal="true" aria-labelledby="ai-drawer-title"><header className="ai-drawer-header"><div className="ai-title"><div className="ai-icon"><Bot size={19} /></div><div><p className="eyebrow">AI SECURITY ANALYST</p><h2 id="ai-drawer-title">{findingId}</h2><span>{packageName}</span></div></div><button className="icon-button" onClick={onClose} aria-label="Close AI explanation"><X size={18} /></button></header><div className="ai-tabs" role="tablist"><button role="tab" aria-selected={tab === 'summary'} className={tab === 'summary' ? 'active' : ''} onClick={() => setTab('summary')}>Plain-English Summary</button><button role="tab" aria-selected={tab === 'fix'} className={tab === 'fix' ? 'active' : ''} onClick={() => setTab('fix')}>Automated Fix &amp; Code Diff</button></div><div className="ai-body">{loading ? <div className="ai-loading"><LoaderCircle className="spin" size={24} /><strong>Generating security guidance...</strong><span>Reviewing {isKubernetes ? 'manifest configuration' : 'container impact'} and remediation paths</span></div> : tab === 'summary' ? <div className="analysis-copy"><div className="analysis-block"><h3>What this means</h3><p>{summary}</p></div><div className="analysis-block"><h3>{isKubernetes ? 'Cluster impact' : 'Container runtime impact'}</h3><p>{impact}</p></div><div className="analysis-block"><h3>Recommended next step</h3><p>{recommendation}</p></div></div> : <div className="diff-view"><div className="diff-toolbar"><span>{isKubernetes ? 'Hardened Kubernetes YAML' : 'Suggested Dockerfile/package update'}</span><button className="copy-button" onClick={copyPatch}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'Copied' : 'Copy patch'}</button></div><pre aria-label="Generated code diff"><code>{codeDiff}</code></pre>{copied && <span className="copy-feedback" role="status"><Check size={13} /> Fixed YAML / patch copied</span>}</div>}</div><footer className="ai-drawer-footer"><button className="secondary-action" onClick={copyPatch}><Copy size={15} />Copy Fixed YAML / Patch</button>{scan?.scanId && !finding.demo && <a className="primary-action compact" href={`http://localhost:8080/api/reports/download/${encodeURIComponent(scan.scanId)}`}><Download size={15} />Download PDF Report</a>}{finding.demo && <span className="secondary-action preview-only-action"><Download size={15} />PDF available after a real scan</span>}</footer></aside></div>
}

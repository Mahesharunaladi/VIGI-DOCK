import { useEffect, useMemo, useState } from 'react'
import { api } from './api'

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const navItems = [
  { id: 'overview', label: 'Overview', icon: '⌂' },
  { id: 'scan', label: 'New scan', icon: '⌁' },
  { id: 'history', label: 'Scan history', icon: '◷' },
]

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function severity(value) {
  return String(value || 'UNKNOWN').toUpperCase()
}

function Icon({ children }) {
  return <span className="icon" aria-hidden="true">{children}</span>
}

function StatCard({ label, value, tone, detail }) {
  return <div className={`stat-card ${tone || ''}`}>
    <div className="stat-label">{label}</div>
    <strong>{value}</strong>
    {detail && <span>{detail}</span>}
  </div>
}

function RiskBadge({ value }) {
  const text = severity(value)
  return <span className={`risk-badge ${text.toLowerCase()}`}>{text}</span>
}

function EmptyState({ title, description, action }) {
  return <div className="empty-state">
    <div className="empty-icon">✦</div>
    <h3>{title}</h3>
    <p>{description}</p>
    {action}
  </div>
}

function App() {
  const [authenticated, setAuthenticated] = useState(() => Boolean(window.localStorage.getItem('vigidock-session')))
  const [authMode, setAuthMode] = useState(null)
  const [activePage, setActivePage] = useState('overview')
  const [scanMode, setScanMode] = useState('docker')
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [loadingHistory, setLoadingHistory] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const [feedbackOpen, setFeedbackOpen] = useState(false)
  const [feedbackText, setFeedbackText] = useState('')

  const loadHistory = async () => {
    setRefreshing(true)
    try {
      const history = await api.listScans()
      setScans(Array.isArray(history) ? history : [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoadingHistory(false)
      setRefreshing(false)
    }
  }

  useEffect(() => { if (authenticated) loadHistory() }, [authenticated])

  if (!authenticated) {
    return <>
      <LandingPage onGetStarted={() => setAuthMode('signin')} onLearnMore={() => setAuthMode('learn')} onSignIn={() => setAuthMode('signin')} onRegister={() => setAuthMode('register')} />
      {authMode === 'learn' && <LearnMoreModal onClose={() => setAuthMode(null)} />}
      {(authMode === 'signin' || authMode === 'register') && <AuthModal mode={authMode} onModeChange={setAuthMode} onClose={() => setAuthMode(null)} onAuthenticated={() => { window.localStorage.setItem('vigidock-session', 'active'); setAuthenticated(true); setAuthMode(null) }} />}
    </>
  }

  const handleScanComplete = (result) => {
    setSelectedScan(result)
    setScans((current) => [result, ...current.filter((scan) => scan.scanId !== result.scanId)])
    setNotice('Scan completed successfully')
    setActivePage('overview')
  }

  const navigate = (page) => {
    setActivePage(page)
    setMobileNav(false)
    setError('')
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? 'open' : ''}`}>
      <div className="brand">
        <div className="brand-mark">V</div>
        <div><strong>VigiDock</strong><small>Security console</small></div>
      </div>
      <nav aria-label="Primary navigation">
        <span className="nav-caption">Workspace</span>
        {navItems.map((item) => <button key={item.id} className={`nav-item ${activePage === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)}>
          <Icon>{item.icon}</Icon>{item.label}
        </button>)}
      </nav>
      <div className="sidebar-footer">
        <div className="connection-dot"><span /> API connected</div>
        <p>Protect every image and manifest before it reaches production.</p>
        <button className="feedback-link" onClick={() => setFeedbackOpen(true)}>Share feedback →</button>
        <button className="signout-link" onClick={() => { window.localStorage.removeItem('vigidock-session'); setAuthenticated(false) }}>Sign out</button>
      </div>
    </aside>
    {mobileNav && <button className="mobile-overlay" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <main className="main-content">
      <header className="topbar">
        <button className="menu-button" onClick={() => setMobileNav(true)} aria-label="Open navigation">☰</button>
        <div className="breadcrumb"><span>Workspace</span><b>/</b><strong>{navItems.find((item) => item.id === activePage)?.label || 'Overview'}</strong></div>
        <div className="topbar-actions"><span className="environment"><i /> Local environment</span><div className="avatar">MA</div></div>
      </header>
      <div className="page-container">
        {notice && <div className="notice success"><span>✓</span>{notice}<button onClick={() => setNotice('')} aria-label="Dismiss">×</button></div>}
        {error && <div className="notice error"><span>!</span>{error}<button onClick={() => setError('')} aria-label="Dismiss">×</button></div>}
        {activePage === 'overview' && <Overview scans={scans} selectedScan={selectedScan} loading={loadingHistory} refreshing={refreshing} onRefresh={loadHistory} onNewScan={() => navigate('scan')} onSelect={setSelectedScan} />}
        {activePage === 'scan' && <ScanPage mode={scanMode} setMode={setScanMode} onComplete={handleScanComplete} setError={setError} />}
        {activePage === 'history' && <HistoryPage scans={scans} loading={loadingHistory} onRefresh={loadHistory} onSelect={setSelectedScan} onNewScan={() => navigate('scan')} />}
      </div>
    </main>
    {feedbackOpen && <FeedbackDialog value={feedbackText} onChange={setFeedbackText} onClose={() => setFeedbackOpen(false)} onSubmit={() => { const previous = JSON.parse(window.localStorage.getItem('vigidock-feedback') || '[]'); window.localStorage.setItem('vigidock-feedback', JSON.stringify([...previous, { message: feedbackText.trim(), submittedAt: new Date().toISOString() }])); setFeedbackOpen(false); setFeedbackText(''); setNotice('Thanks — your feedback has been recorded.') }} />}
  </div>
}

function LandingPage({ onGetStarted, onLearnMore, onSignIn, onRegister }) {
  return <div className="landing-page">
    <header className="landing-nav"><div className="brand"><div className="brand-mark">V</div><div><strong>VigiDock</strong><small>Security console</small></div></div><div className="landing-nav-actions"><button className="link-button" onClick={onSignIn}>Sign in</button><button className="button primary small" onClick={onRegister}>Register</button></div></header>
    <main className="landing-content"><section className="landing-copy"><div className="landing-kicker"><span /> Secure releases, made simple</div><h1>Ship with confidence.<br /><em>Secure by default.</em></h1><p>VigiDock helps teams find vulnerabilities in container images and Kubernetes manifests before they reach production.</p><div className="landing-actions"><button className="button primary landing-button" onClick={onGetStarted}>Get Started <span>→</span></button><button className="button secondary landing-button" onClick={onLearnMore}>Learn More</button></div><div className="landing-proof"><span>✓ Trivy-powered scanning</span><span>✓ Actionable insights</span><span>✓ Built for developers</span></div></section><section className="landing-visual" aria-label="VigiDock security overview"><div className="visual-glow" /><div className="visual-card main-visual-card"><div className="visual-card-header"><span className="visual-dot" /><span>Security overview</span><b>Today</b></div><div className="visual-score"><div className="score-ring"><strong>92</strong><small>risk score</small></div><div><strong className="safe-text">Healthy baseline</strong><p>Across 12 scanned targets</p></div></div><div className="visual-bars"><span style={{ width: '84%' }}><i>Container images</i><b>84%</b></span><span style={{ width: '68%' }}><i>Kubernetes configs</i><b>68%</b></span><span style={{ width: '93%' }}><i>Policy coverage</i><b>93%</b></span></div></div><div className="visual-card floating-card"><span className="floating-icon">✓</span><div><strong>No critical issues</strong><small>Last scan completed</small></div></div></section></main><footer className="landing-footer"><span>© 2026 VigiDock</span><span>Secure every release.</span></footer>
  </div>
}

function LearnMoreModal({ onClose }) {
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="info-modal" role="dialog" aria-modal="true"><button className="close-button" onClick={onClose} aria-label="Close">×</button><div className="modal-icon">✦</div><p className="eyebrow">ABOUT VIGIDOCK</p><h2>Security clarity for every release.</h2><p>VigiDock brings container and Kubernetes security checks into one focused workspace. Scan an image, upload a manifest, review findings, and get practical remediation guidance.</p><div className="modal-features"><div><strong>01</strong><span>Find vulnerabilities early</span></div><div><strong>02</strong><span>Understand the risk quickly</span></div><div><strong>03</strong><span>Fix issues with confidence</span></div></div></section></div>
}

function AuthModal({ mode, onModeChange, onClose, onAuthenticated }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const register = mode === 'register'
  const submit = (event) => {
    event.preventDefault(); setError('')
    if (!email.includes('@') || password.length < 6 || (register && !name.trim())) { setError(register ? 'Enter your name, a valid email, and a password with at least 6 characters.' : 'Enter a valid email and a password with at least 6 characters.'); return }
    if (register) { const users = JSON.parse(window.localStorage.getItem('vigidock-users') || '[]'); window.localStorage.setItem('vigidock-users', JSON.stringify([...users.filter((user) => user.email !== email), { name, email, password }])); }
    onAuthenticated()
  }
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><section className="auth-modal" role="dialog" aria-modal="true"><button className="close-button" onClick={onClose} aria-label="Close">×</button><div className="auth-heading"><div className="brand-mark">V</div><p className="eyebrow">WELCOME TO VIGIDOCK</p><h2>{register ? 'Create your account' : 'Welcome back'}</h2><p>{register ? 'Start securing your releases in minutes.' : 'Sign in to open your security workspace.'}</p></div><form onSubmit={submit}>{register && <label>Full name<input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" /></label>}<label>Email address<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" /></label><label>Password<input required type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 6 characters" /></label>{error && <div className="auth-error">{error}</div>}<button className="button primary full-width" type="submit">{register ? 'Create account' : 'Sign in'} <span>→</span></button></form><p className="auth-switch">{register ? 'Already have an account?' : 'New to VigiDock?'} <button onClick={() => { setError(''); onModeChange(register ? 'signin' : 'register') }}>{register ? 'Sign in' : 'Register'}</button></p><small className="auth-note">Demo access is stored locally in this browser.</small></section></div>
}

function FeedbackDialog({ value, onChange, onClose, onSubmit }) {
  return <div className="feedback-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <form className="feedback-card" onSubmit={(event) => { event.preventDefault(); if (value.trim()) onSubmit() }}>
      <div className="panel-heading" style={{ padding: 0 }}><div><p className="eyebrow">USER FEEDBACK</p><h2>Help us improve VigiDock</h2></div><button type="button" className="close-button" onClick={onClose} aria-label="Close feedback">×</button></div>
      <p>Tell us what felt clear, confusing, or missing. Your feedback helps us make security workflows easier for everyone.</p>
      <label htmlFor="feedback">Your feedback</label>
      <textarea id="feedback" required value={value} onChange={(event) => onChange(event.target.value)} placeholder="What could make this experience better?" autoFocus />
      <div className="feedback-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button type="submit" className="button primary">Send feedback</button></div>
    </form>
  </div>
}

function Overview({ scans, selectedScan, loading, refreshing, onRefresh, onNewScan, onSelect }) {
  const summary = useMemo(() => scans.reduce((acc, scan) => {
    acc.total += Number(scan.totalVulnerabilities || 0)
    acc.critical += Number(scan.criticalCount || 0)
    acc.high += Number(scan.highCount || 0)
    acc.medium += Number(scan.mediumCount || 0)
    acc.low += Number(scan.lowCount || 0)
    return acc
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0 }), [scans])

  return <>
    <section className="hero-row">
      <div><p className="eyebrow">SECURITY OVERVIEW</p><h1>Stay ahead of vulnerabilities.</h1><p className="subtitle">Scan container images and Kubernetes manifests from one focused workspace.</p></div>
      <div className="hero-actions"><button className="button secondary" onClick={onRefresh} disabled={refreshing}><Icon>↻</Icon>{refreshing ? 'Refreshing' : 'Refresh'}</button><button className="button primary" onClick={onNewScan}><Icon>＋</Icon>New scan</button></div>
    </section>
    <div className="stats-grid">
      <StatCard label="Total scans" value={scans.length} detail="Across this workspace" />
      <StatCard label="Vulnerabilities" value={summary.total} detail="Found in recent scans" />
      <StatCard label="Critical findings" value={summary.critical} tone="critical" detail="Immediate attention" />
      <StatCard label="High findings" value={summary.high} tone="high" detail="Prioritize soon" />
    </div>
    <div className="content-grid">
      <section className="panel recent-panel"><div className="panel-heading"><div><p className="eyebrow">ACTIVITY</p><h2>Recent scans</h2></div><button className="text-button" onClick={() => onSelect(scans[0])}>View details <span>→</span></button></div>
        {loading ? <LoadingRows /> : scans.length === 0 ? <EmptyState title="Your workspace is clear" description="Run your first scan to see security findings and risk insights here." action={<button className="button primary" onClick={onNewScan}>Start a scan</button>} /> : <ScanTable scans={scans.slice(0, 6)} onSelect={onSelect} />}
      </section>
      <section className="panel insight-panel"><div className="panel-heading"><div><p className="eyebrow">RISK INSIGHT</p><h2>Findings by severity</h2></div><span className="mini-label">All scans</span></div><SeverityChart summary={summary} />
        <div className="insight-tip"><span>✦</span><div><strong>Keep your baseline clean</strong><p>Scan images before release to catch issues earlier in the delivery cycle.</p></div></div>
      </section>
    </div>
    {selectedScan && <ResultPanel scan={selectedScan} onClose={() => onSelect(null)} />}
  </>
}

function LoadingRows() { return <div className="loading-list">{[1, 2, 3].map((item) => <div className="loading-row" key={item}><span /><span /><span /><span /></div>)}</div> }

function ScanTable({ scans, onSelect }) {
  return <div className="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Findings</th><th>Scanned</th><th /></tr></thead><tbody>{scans.map((scan, index) => <tr key={scan.scanId || `${scan.target}-${index}`} onClick={() => onSelect(scan)}><td><strong className="target-name">{scan.target || 'Unnamed target'}</strong><small>{scan.scanId || 'Pending ID'}</small></td><td><span className="type-pill">{scan.scanType === 'K8S_CONFIG' ? 'Kubernetes' : 'Container'}</span></td><td><RiskBadge value={scan.overallRiskScore || (scan.criticalCount ? 'CRITICAL' : scan.highCount ? 'HIGH' : 'LOW')} /></td><td><strong>{scan.totalVulnerabilities ?? 0}</strong></td><td className="muted">{formatDate(scan.scannedAt)}</td><td className="arrow">→</td></tr>)}</tbody></table></div>
}

function SeverityChart({ summary }) {
  const total = Math.max(summary.critical + summary.high + summary.medium + summary.low, 1)
  const values = [{ label: 'Critical', value: summary.critical, color: 'critical' }, { label: 'High', value: summary.high, color: 'high' }, { label: 'Medium', value: summary.medium, color: 'medium' }, { label: 'Low', value: summary.low, color: 'low' }]
  return <div className="severity-chart"><div className="bar-chart">{values.map((item) => <div className="bar-column" key={item.label}><div className={`bar ${item.color}`} style={{ height: `${Math.max((item.value / total) * 100, item.value ? 12 : 4)}%` }}><span>{item.value}</span></div><small>{item.label}</small></div>)}</div><div className="chart-total"><strong>{summary.total}</strong><span>Total vulnerabilities</span></div></div>
}

function ScanPage({ mode, setMode, onComplete, setError }) {
  const [running, setRunning] = useState(false)
  const [dockerImage, setDockerImage] = useState('')
  const [threshold, setThreshold] = useState('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
  const [enableAi, setEnableAi] = useState(true)
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setRunning(true); setError('')
    try {
      const result = mode === 'docker'
        ? await api.scanDocker({ imageName: dockerImage, severityThreshold: threshold, enableAiAnalysis: enableAi })
        : await api.scanKubernetes(file)
      onComplete(result)
    } catch (err) { setError(err.message) } finally { setRunning(false) }
  }
  const chooseFile = (chosen) => { if (chosen && chosen.size <= 25 * 1024 * 1024) setFile(chosen); else if (chosen) setError('Choose a manifest smaller than 25 MB') }
  return <section className="scan-page"><div className="hero-row compact"><div><p className="eyebrow">NEW SECURITY SCAN</p><h1>Inspect before you ship.</h1><p className="subtitle">Choose a target and VigiDock will surface actionable security findings.</p></div></div>
    <div className="scan-layout"><div className="panel scan-form-panel"><div className="mode-switch" role="tablist" aria-label="Scan type"><button className={mode === 'docker' ? 'active' : ''} onClick={() => setMode('docker')} role="tab"><span>◈</span> Container image</button><button className={mode === 'kubernetes' ? 'active' : ''} onClick={() => setMode('kubernetes')} role="tab"><span>⌘</span> Kubernetes YAML</button></div>
      <form onSubmit={submit}>{mode === 'docker' ? <><label htmlFor="image">Container image</label><div className="input-with-icon"><span>◈</span><input id="image" required value={dockerImage} onChange={(event) => setDockerImage(event.target.value)} placeholder="e.g. nginx:alpine" /></div><p className="field-help">Use a public image tag or an image available to your local Docker/Trivy environment.</p><label htmlFor="threshold">Severity threshold</label><select id="threshold" value={threshold} onChange={(event) => setThreshold(event.target.value)}><option value="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL">All severities</option><option value="MEDIUM,HIGH,CRITICAL">Medium and above</option><option value="HIGH,CRITICAL">High and critical only</option><option value="CRITICAL">Critical only</option></select><label className="check-row"><input type="checkbox" checked={enableAi} onChange={(event) => setEnableAi(event.target.checked)} /><span><strong>Enable AI context</strong><small>Prepare findings for plain-English remediation guidance.</small></span></label></> : <><label htmlFor="manifest">Kubernetes manifest</label><div className={`dropzone ${dragging ? 'dragging' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0]) }}><input id="manifest" type="file" accept=".yaml,.yml,application/yaml,text/yaml" onChange={(event) => chooseFile(event.target.files[0])} /><div className="upload-icon">↑</div>{file ? <><strong>{file.name}</strong><span>{(file.size / 1024).toFixed(1)} KB · Ready to scan</span><button type="button" className="text-button" onClick={() => setFile(null)}>Choose another</button></> : <><strong>Drop your YAML file here</strong><span>or click to browse · Max 25 MB</span></>}</div><p className="field-help">Upload a deployment, service, pod, or other Kubernetes YAML manifest for configuration analysis.</p></>}
        <button className="button primary full-width submit-button" disabled={running || (mode === 'kubernetes' && !file)}>{running ? <><span className="spinner" />Running security scan…</> : <>Start {mode === 'docker' ? 'image' : 'manifest'} scan <span>→</span></>}</button>
      </form>
    </div><div className="scan-side-note"><div className="shield-art">✓</div><h3>Built for confident releases</h3><p>VigiDock combines vulnerability detection with practical remediation context so your team can act quickly.</p><div className="feature-list"><span>✓ Trivy-powered scanning</span><span>✓ Kubernetes misconfiguration checks</span><span>✓ AI-assisted remediation</span></div></div></div>
  </section>
}

function HistoryPage({ scans, loading, onRefresh, onSelect, onNewScan }) {
  return <section><div className="hero-row compact"><div><p className="eyebrow">AUDIT TRAIL</p><h1>Scan history</h1><p className="subtitle">Review previous security checks and export their reports.</p></div><div className="hero-actions"><button className="button secondary" onClick={onRefresh}><Icon>↻</Icon>Refresh</button><button className="button primary" onClick={onNewScan}>＋ New scan</button></div></div><div className="panel history-panel">{loading ? <LoadingRows /> : scans.length ? <ScanTable scans={scans} onSelect={onSelect} /> : <EmptyState title="No scan history yet" description="Your completed scans will appear here." action={<button className="button primary" onClick={onNewScan}>Run your first scan</button>} />}</div></section>
}

function ResultPanel({ scan, onClose }) {
  const [aiResult, setAiResult] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')
  const findings = scan.vulnerabilities || []
  const requestAi = async (finding) => { setAiLoading(true); setAiError(''); try { setAiResult(await api.explainCve(finding)) } catch (err) { setAiError(err.message) } finally { setAiLoading(false) } }
  const downloadJson = async () => { try { const body = await api.reportJson(scan.scanId); const blob = new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }); downloadBlob(blob, `vigidock-${scan.scanId}.json`) } catch (err) { setAiError(err.message) } }
  const downloadPdf = async () => { try { downloadBlob(await api.reportPdf(scan.scanId), `vigidock-${scan.scanId}.pdf`) } catch (err) { setAiError(err.message) } }
  return <div className="result-overlay"><section className="result-drawer" role="dialog" aria-modal="true"><div className="drawer-header"><div><p className="eyebrow">SCAN RESULT</p><h2>{scan.target || 'Security scan'}</h2><p className="muted">{scan.scanType === 'K8S_CONFIG' ? 'Kubernetes manifest' : 'Container image'} · {formatDate(scan.scannedAt)}</p></div><button className="close-button" onClick={onClose} aria-label="Close result">×</button></div><div className="drawer-actions"><RiskBadge value={scan.overallRiskScore || 'COMPLETED'} /><span className="scan-status">● {scan.status || 'COMPLETED'}</span><span className="action-spacer" /><button className="button small secondary" onClick={downloadJson}>↓ JSON</button><button className="button small secondary" onClick={downloadPdf}>↓ PDF</button></div>{aiError && <div className="inline-error">{aiError}</div>}<div className="result-stats"><StatCard label="Total findings" value={scan.totalVulnerabilities ?? findings.length} /><StatCard label="Critical" value={scan.criticalCount ?? countSeverity(findings, 'CRITICAL')} tone="critical" /><StatCard label="High" value={scan.highCount ?? countSeverity(findings, 'HIGH')} tone="high" /><StatCard label="Medium" value={scan.mediumCount ?? countSeverity(findings, 'MEDIUM')} tone="medium" /></div><div className="findings-section"><div className="panel-heading"><div><p className="eyebrow">DETAILS</p><h3>Vulnerability findings</h3></div></div>{findings.length ? <div className="finding-list">{findings.map((finding, index) => <article className="finding-card" key={`${finding.vulnerabilityId || finding.id}-${index}`}><div className="finding-top"><RiskBadge value={finding.severity} /><strong>{finding.vulnerabilityId || finding.id || 'Security finding'}</strong><span className="finding-package">{finding.packageName || finding.pkgName || 'Configuration issue'}</span><button className="text-button" onClick={() => requestAi(finding)}>Explain with AI →</button></div><p>{finding.description || 'No description was returned for this finding.'}</p><div className="finding-meta"><span>Installed: <b>{finding.installedVersion || '—'}</b></span><span>Fixed: <b>{finding.fixedVersion || 'Not available'}</b></span></div></article>)}</div> : <EmptyState title="No findings detected" description="This target passed the checks included in the scan." />}</div>{(aiLoading || aiResult) && <div className="ai-card"><div className="ai-card-title"><span className="ai-spark">✦</span><div><p className="eyebrow">AI SECURITY GUIDE</p><h3>{aiLoading ? 'Preparing explanation…' : 'What this means'}</h3></div></div>{aiLoading ? <div className="ai-loading"><span /><span /><span /></div> : <><p>{aiResult?.plainEnglishSummary || aiResult?.impactAnalysis}</p>{aiResult?.recommendedFix && <div className="recommendation"><strong>Recommended fix</strong><p>{aiResult.recommendedFix}</p></div>}{aiResult?.remediationCommands?.length > 0 && <pre>{aiResult.remediationCommands.join('\n')}</pre>}</>}</div>}</section></div>
}

function countSeverity(findings, target) { return findings.filter((finding) => severity(finding.severity) === target).length }
function downloadBlob(blob, name) { const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url) }

export default App

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ArrowRight, Box, CheckCircle2, FileCode2, ShieldCheck } from 'lucide-react'
import AppLayout from './components/layout/AppLayout'
import DockerScanForm from './components/scanner/DockerScanForm'
import K8sFileUpload from './components/scanner/K8sFileUpload'
import ScanResultsView from './components/dashboard/ScanResultsView'
import AiExplanationDrawer from './components/ai/AiExplanationDrawer'
import ReportsPage from './pages/ReportsPage'
import { dashboardApi } from './api'

function count(scans, field) { return scans.reduce((total, scan) => total + Number(scan[field] || 0), 0) }
function formatDate(value) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString([], { dateStyle: 'medium' }) }

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [theme, setTheme] = useState(() => window.localStorage.getItem('vigidock-theme') || 'light')
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [scannerTab, setScannerTab] = useState('docker')

  const loadScans = async () => { setLoading(true); try { setScans(await dashboardApi.listScans()) } catch (requestError) { setError(requestError.message) } finally { setLoading(false) } }
  useEffect(() => { loadScans() }, [])
  useEffect(() => { window.localStorage.setItem('vigidock-theme', theme) }, [theme])

  const completeScan = (result) => { setScans((current) => [result, ...current.filter((scan) => scan.scanId !== result.scanId)]); setSelectedScan(result); setNotice('Security scan completed successfully'); setActivePage('dashboard') }
  const totals = useMemo(() => ({ vulnerabilities: count(scans, 'totalVulnerabilities'), critical: count(scans, 'criticalCount'), high: count(scans, 'highCount'), medium: count(scans, 'mediumCount') }), [scans])
  const handleError = (message) => { setError(message); setNotice('') }

  return <AppLayout activePage={activePage} onNavigate={setActivePage} theme={theme} onToggleTheme={() => setTheme((value) => value === 'dark' ? 'light' : 'dark')}><div className="toast-stack">{notice && <div className="toast success"><CheckCircle2 size={16} />{notice}<button onClick={() => setNotice('')} aria-label="Dismiss">×</button></div>}{error && <div className="toast error"><AlertTriangle size={16} />{error}<button onClick={() => setError('')} aria-label="Dismiss">×</button></div>}</div>{activePage === 'dashboard' && <Dashboard scans={scans} totals={totals} loading={loading} onRefresh={loadScans} onNavigate={setActivePage} onSelect={setSelectedScan} selectedScan={selectedScan} onExplain={setFinding} />}{activePage === 'scanner' && <ScannerPage tab={scannerTab} setTab={setScannerTab} onComplete={completeScan} onError={handleError} />}{activePage === 'manifest' && <ScannerPage tab="manifest" setTab={setScannerTab} onComplete={completeScan} onError={handleError} />}{activePage === 'reports' && <ReportsPage onSelect={setSelectedScan} onError={handleError} onNotice={setNotice} />}{finding && <AiExplanationDrawer scan={selectedScan} finding={finding} onClose={() => setFinding(null)} onError={handleError} />}{selectedScan && !finding && activePage === 'dashboard' && <div className="selected-result-bar"><span>Viewing results for <strong>{selectedScan.target}</strong></span><button onClick={() => setSelectedScan(null)}>Clear selection</button></div>}</AppLayout>
}

function Dashboard({ scans, totals, loading, onRefresh, onNavigate, onSelect, selectedScan, onExplain }) {
  const recent = scans.slice(0, 5)
  return <section className="page-section"><div className="page-heading"><div><p className="eyebrow">SECURITY OVERVIEW</p><h1>Ship secure, stay ahead.</h1><p>Monitor vulnerability exposure across your container images and Kubernetes workloads.</p></div><div className="heading-actions"><button className="secondary-action" onClick={onRefresh}>Refresh data</button><button className="primary-action compact" onClick={() => onNavigate('scanner')}><Box size={15} />New scan <ArrowRight size={14} /></button></div></div><div className="overview-grid"><MetricCard label="Total vulnerabilities" value={totals.vulnerabilities} detail="Across all scans" /><MetricCard label="Critical findings" value={totals.critical} detail="Immediate attention" tone="critical" /><MetricCard label="High findings" value={totals.high} detail="Prioritize soon" tone="high" /><MetricCard label="Scans completed" value={scans.length} detail="Audit history" tone="safe" /></div><div className="dashboard-grid"><section className="recent-card"><div className="section-header"><div><p className="eyebrow">ACTIVITY</p><h2>Recent scans</h2></div><button className="link-action" onClick={() => onNavigate('reports')}>View reports <ArrowRight size={14} /></button></div>{loading ? <div className="loading-state">Loading scan history...</div> : recent.length === 0 ? <div className="empty-dashboard"><ShieldCheck size={25} /><h3>Your workspace is clear</h3><p>Run your first scan to see actionable findings here.</p><button className="secondary-action" onClick={() => onNavigate('scanner')}>Start a scan</button></div> : <div className="recent-list">{recent.map((scan) => <button className="recent-row" key={scan.scanId} onClick={() => onSelect(scan)}><span className={`scan-type-icon ${scan.scanType === 'K8S_CONFIG' ? 'manifest' : ''}`}>{scan.scanType === 'K8S_CONFIG' ? <FileCode2 size={16} /> : <Box size={16} />}</span><span className="recent-target"><strong>{scan.target || 'Unnamed target'}</strong><small>{scan.scanId} · {formatDate(scan.scannedAt)}</small></span><span className="row-count"><b>{scan.totalVulnerabilities || 0}</b><small>findings</small></span><span className={`mini-risk ${(scan.criticalCount || scan.highCount) ? 'risk' : 'safe'}`}>{scan.criticalCount || scan.highCount ? 'Review' : 'Passed'}</span><ArrowRight size={15} /></button>)}</div>}</section><aside className="posture-card"><div className="posture-icon"><ShieldCheck size={21} /></div><p className="eyebrow">SECURITY POSTURE</p><h2>{totals.critical ? 'Action required' : 'Healthy baseline'}</h2><p>{totals.critical ? 'Critical findings need attention before release.' : 'Keep scanning regularly to maintain your baseline.'}</p><div className="posture-meter"><span style={{ width: `${Math.max(12, 100 - Math.min(totals.critical * 10 + totals.high * 3, 88))}%` }} /></div><div className="posture-footer"><span>Workspace health</span><strong>{totals.critical ? 'Needs review' : 'Protected'}</strong></div></aside></div>{selectedScan && <ScanResultsView scan={selectedScan} onExplain={onExplain} />}</section>
}

function MetricCard({ label, value, detail, tone = '' }) { return <div className={`metric-card ${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div> }
function ScannerPage({ tab, setTab, onComplete, onError }) { return <section className="page-section"><div className="page-heading"><div><p className="eyebrow">SECURITY SCANNERS</p><h1>Inspect before you ship.</h1><p>Choose a target and VigiDock will surface exploitable risk and practical fixes.</p></div></div><div className="scanner-tabs"><button className={tab === 'docker' ? 'active' : ''} onClick={() => setTab('docker')}><Box size={17} />Image Scanner</button><button className={tab === 'manifest' ? 'active' : ''} onClick={() => setTab('manifest')}><FileCode2 size={17} />Manifest Auditor</button></div><div className="scanner-layout">{tab === 'docker' ? <DockerScanForm onComplete={onComplete} onError={onError} /> : <K8sFileUpload onComplete={onComplete} onError={onError} />}<div className="scanner-aside"><div className="aside-shield"><ShieldCheck size={25} /></div><h3>Built for confident releases</h3><p>Combine Trivy detection, EPSS prioritization, and AI remediation in one workflow.</p><div><span><CheckCircle2 size={14} />Trivy-powered scanning</span><span><CheckCircle2 size={14} />EPSS threat intelligence</span><span><CheckCircle2 size={14} />Actionable AI guidance</span></div></div></div></section> }

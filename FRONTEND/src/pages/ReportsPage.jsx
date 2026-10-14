import { useEffect, useState } from 'react'
import { CalendarDays, Download, FileBarChart2, LoaderCircle, RefreshCw } from 'lucide-react'
import { dashboardApi } from '../api'

function downloadBlob(blob, filename) { const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url) }
function dateLabel(value) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString([], { dateStyle: 'medium' }) }

export default function ReportsPage({ onSelect, onError, onNotice }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState('')
  const load = async () => { setLoading(true); try { setScans(await dashboardApi.listScans()) } catch (error) { onError(error.message) } finally { setLoading(false) } }
  useEffect(() => { load() }, [])
  const download = async (scan) => { setDownloading(scan.scanId); try { downloadBlob(await dashboardApi.downloadReport(scan.scanId), `vigidock-${scan.scanId}.pdf`); onNotice('Executive PDF report downloaded') } catch (error) { onError(error.message) } finally { setDownloading('') } }

  return <section className="page-section"><div className="page-heading"><div><p className="eyebrow">REPORT CENTER</p><h1>Executive reports</h1><p>Export a clear security record for every image and manifest audit.</p></div><button className="secondary-action" onClick={load} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} />Refresh history</button></div><section className="reports-table-card"><div className="table-title"><div><FileBarChart2 size={18} /><div><h2>Scan export history</h2><span>{scans.length} completed audit{scans.length === 1 ? '' : 's'}</span></div></div><span className="pdf-label">PDF READY</span></div>{loading ? <div className="table-loading"><LoaderCircle className="spin" size={21} />Loading scan history...</div> : scans.length === 0 ? <div className="table-loading"><CalendarDays size={21} />No scan history available yet.</div> : <div className="risk-table-wrap"><table className="reports-table"><thead><tr><th>Target name</th><th>Date</th><th>Severity breakdown</th><th>Status</th><th /></tr></thead><tbody>{scans.map((scan) => <tr key={scan.scanId}><td><button className="table-target" onClick={() => onSelect(scan)}><strong>{scan.target || 'Unnamed target'}</strong><span>{scan.scanId}</span></button></td><td>{dateLabel(scan.scannedAt)}</td><td><div className="severity-inline"><b className="critical-text">{scan.criticalCount || 0} C</b><b className="high-text">{scan.highCount || 0} H</b><b className="medium-text">{scan.mediumCount || 0} M</b><b className="low-text">{scan.lowCount || 0} L</b></div></td><td><span className="status-badge">{scan.status || 'COMPLETED'}</span></td><td><button className="download-action" onClick={() => download(scan)} disabled={downloading === scan.scanId}>{downloading === scan.scanId ? <LoaderCircle size={14} className="spin" /> : <Download size={14} />} {downloading === scan.scanId ? 'Generating...' : 'Download report'}</button></td></tr>)}</tbody></table></div>}</section></section>
}

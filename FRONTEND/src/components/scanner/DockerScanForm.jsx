import { useEffect, useState } from 'react'
import { ArrowRight, CheckCircle2, Container, LoaderCircle, ScanLine } from 'lucide-react'
import { dashboardApi } from '../../api'

const presets = ['nginx:latest', 'node:18-alpine', 'alpine:3.12', 'redis:7-alpine']
const phases = ['Pulling metadata...', 'Running Trivy scan...', 'Fetching EPSS probabilities...']

export default function DockerScanForm({ onComplete, onError }) {
  const [imageName, setImageName] = useState('')
  const [preset, setPreset] = useState('')
  const [running, setRunning] = useState(false)
  const [phase, setPhase] = useState(0)

  useEffect(() => { if (!running) return undefined; const timer = window.setInterval(() => setPhase((current) => Math.min(current + 1, phases.length - 1)), 1800); return () => window.clearInterval(timer) }, [running])

  const submit = async (event) => {
    event.preventDefault()
    if (!imageName.trim()) return
    setRunning(true); setPhase(0)
    try { const result = await dashboardApi.scanDocker({ imageName: imageName.trim(), severityThreshold: 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', enableAiAnalysis: true }); onComplete(result) } catch (error) { onError(error.message) } finally { setRunning(false) }
  }

  return <form className="scanner-card" onSubmit={submit}><div className="form-icon"><Container size={19} /></div><div className="form-heading"><p className="eyebrow">CONTAINER SECURITY</p><h2>Scan a Docker image</h2><p>Find exploitable packages before they reach your registry or cluster.</p></div><label htmlFor="docker-image">Image name</label><input id="docker-image" value={imageName} onChange={(event) => { setImageName(event.target.value); setPreset('') }} placeholder="e.g. nginx:1.19" disabled={running} /><div className="preset-row"><span>Quick test:</span>{presets.map((value) => <button type="button" key={value} className={preset === value ? 'selected' : ''} onClick={() => { setImageName(value); setPreset(value) }}>{value}</button>)}</div><button className="primary-action" disabled={running || !imageName.trim()}>{running ? <><LoaderCircle className="spin" size={17} />{phases[phase]}</> : <><ScanLine size={17} />Scan Image <ArrowRight size={16} /></>}</button>{running && <div className="phase-list">{phases.map((item, index) => <div key={item} className={index <= phase ? 'done' : ''}>{index < phase ? <CheckCircle2 size={14} /> : <span className="phase-dot" />}{item}</div>)}</div>}</form>
}

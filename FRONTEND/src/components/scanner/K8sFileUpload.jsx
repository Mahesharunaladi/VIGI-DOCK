import { useRef, useState } from 'react'
import { CheckCircle2, FileCode2, FileUp, LoaderCircle, Trash2 } from 'lucide-react'
import { dashboardApi } from '../../api'

const MAX_FILE_SIZE = 10 * 1024 * 1024

export default function K8sFileUpload({ onComplete, onError }) {
  const inputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [running, setRunning] = useState(false)

  const chooseFile = (candidate) => {
    if (!candidate) return
    if (!/\.ya?ml$/i.test(candidate.name)) return onError('Choose a Kubernetes YAML file ending in .yaml or .yml')
    if (candidate.size > MAX_FILE_SIZE) return onError('Choose a manifest smaller than 10 MB')
    setFile(candidate)
  }
  const submit = async () => { if (!file) return; setRunning(true); try { onComplete(await dashboardApi.scanKubernetes(file)) } catch (error) { onError(error.message) } finally { setRunning(false) } }

  return <div className="scanner-card manifest-card"><div className="form-icon violet"><FileCode2 size={19} /></div><div className="form-heading"><p className="eyebrow">KUBERNETES SECURITY</p><h2>Audit a manifest</h2><p>Detect risky configuration and get hardened YAML recommendations.</p></div><div className={`file-dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0]) }} onClick={() => !file && inputRef.current?.click()}>{file ? <div className="file-preview"><div className="file-type"><FileCode2 size={21} /></div><div><strong>{file.name}</strong><span>{(file.size / 1024).toFixed(1)} KB · Ready to audit</span></div><button type="button" onClick={(event) => { event.stopPropagation(); setFile(null) }} aria-label="Remove file"><Trash2 size={16} /></button></div> : <><FileUp size={24} /><strong>Drop your YAML file here</strong><span>or click to browse · .yaml and .yml · max 10 MB</span></>}<input ref={inputRef} type="file" accept=".yaml,.yml,application/yaml,text/yaml" hidden onChange={(event) => chooseFile(event.target.files[0])} /></div><button type="button" className="primary-action" disabled={!file || running} onClick={submit}>{running ? <><LoaderCircle className="spin" size={17} />Auditing manifest...</> : <><CheckCircle2 size={17} />Run Manifest Audit</>}</button></div>
}

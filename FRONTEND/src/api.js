const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8080').replace(/\/$/, '')

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, options)
  const contentType = response.headers.get('content-type') || ''
  const body = contentType.includes('application/json') ? await response.json() : await response.text()

  if (!response.ok) {
    throw new Error(body?.message || body?.error || `Request failed with status ${response.status}`)
  }
  return body
}

function unwrap(body) {
  return body?.data ?? body
}

export const api = {
  async listScans() {
    return unwrap(await request('/api/v1/scans')) || []
  },
  async scanDocker(payload) {
    return unwrap(await request('/api/v1/scans/docker', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }))
  },
  async scanKubernetes(file) {
    const formData = new FormData()
    formData.append('file', file)
    return unwrap(await request('/api/v1/scans/k8s', { method: 'POST', body: formData }))
  },
  async explainCve(vulnerability) {
    return unwrap(await request('/api/v1/ai/explain-cve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vulnerabilityId: vulnerability.vulnerabilityId || vulnerability.id || 'Unknown vulnerability',
        packageName: vulnerability.packageName || vulnerability.pkgName || 'Unknown package',
        installedVersion: vulnerability.installedVersion || vulnerability.installedVersion || '',
        fixedVersion: vulnerability.fixedVersion || vulnerability.fixedVersion || '',
        severity: vulnerability.severity || 'UNKNOWN',
        description: vulnerability.description || '',
        context: 'VigiDock security dashboard',
      }),
    }))
  },
  async explainKubernetes(payload) {
    return unwrap(await request('/api/v1/ai/explain-k8s', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }))
  },
  async reportJson(scanId) {
    return request(`/api/v1/reports/${encodeURIComponent(scanId)}/json`)
  },
  async reportPdf(scanId) {
    const response = await fetch(`${API_URL}/api/v1/reports/${encodeURIComponent(scanId)}/pdf`)
    if (!response.ok) throw new Error('PDF report is not available for this scan')
    return response.blob()
  },
}

import apiClient, { apiRequest, downloadReport, unwrapApiResponse } from './axios'

export { apiClient, apiRequest, downloadReport, unwrapApiResponse }

export const dashboardApi = {
  listScans: async () => apiRequest({ url: '/scan' }) || [],
  scanDocker: async (payload) => apiRequest({ method: 'POST', url: '/scan/docker', data: payload }),
  scanKubernetes: async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    return apiRequest({ method: 'POST', url: '/scan/k8s', data: formData })
  },
  explainCve: async (vulnerability) => apiRequest({
    method: 'POST',
    url: '/ai/explain-cve',
    data: {
      vulnerabilityId: vulnerability.vulnerabilityId || vulnerability.id || 'Unknown vulnerability',
      packageName: vulnerability.packageName || vulnerability.pkgName || 'Unknown package',
      installedVersion: vulnerability.installedVersion || '',
      fixedVersion: vulnerability.fixedVersion || '',
      severity: vulnerability.severity || 'UNKNOWN',
      description: vulnerability.description || '',
      context: 'VigiDock security dashboard',
    },
  }),
  explainKubernetes: async (payload) => apiRequest({ method: 'POST', url: '/ai/explain-k8s', data: payload }),
  generatePatch: async (payload) => apiRequest({ method: 'POST', url: '/fix/generate-patch', data: payload }),
  reportJson: async (scanId) => apiRequest({ url: `/reports/${encodeURIComponent(scanId)}/json` }),
  downloadReport,
}

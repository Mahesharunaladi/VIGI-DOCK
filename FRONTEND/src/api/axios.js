import axios from 'axios'

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8080/api',
  headers: { Accept: 'application/json' },
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const payload = error.response?.data
    const message = payload?.message || payload?.error || error.message || 'Request failed'
    return Promise.reject(new Error(message))
  },
)

export function unwrapApiResponse(response) {
  const body = response?.data ?? response
  return body?.data ?? body
}

export async function apiRequest(config) {
  const response = await apiClient.request(config)
  return unwrapApiResponse(response)
}

export async function downloadReport(scanId) {
  const response = await apiClient.get(`/reports/download/${encodeURIComponent(scanId)}`, { responseType: 'blob' })
  return response.data
}

export default apiClient

import { useCallback, useState } from 'react'

export function useApiResponse(request) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const execute = useCallback(async (...args) => {
    setLoading(true)
    setError('')
    try {
      const result = await request(...args)
      setData(result)
      return result
    } catch (requestError) {
      const message = requestError?.message || 'Something went wrong'
      setError(message)
      throw requestError
    } finally {
      setLoading(false)
    }
  }, [request])

  return { data, loading, error, execute, setData }
}

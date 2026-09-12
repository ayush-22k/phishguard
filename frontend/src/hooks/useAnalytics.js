import { useState, useEffect, useCallback } from 'react';
import { scanService } from '../services/scanService';

export function useAnalytics(initialParams = {}) {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAnalytics = useCallback(async (params = {}) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await scanService.getAnalytics(params);
      setData(response.data);
    } catch (err) {
      setError(
        err.response?.data?.error?.message ||
        err.message ||
        'Failed to fetch analytics'
      );
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics(initialParams);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    data,
    isLoading,
    error,
    refetch: fetchAnalytics,
  };
}


import { useState, useCallback, useRef } from 'react';
import { scanService } from '../services/scanService';

/**
 * Custom React hook for scan history retrieval, pagination, filtering, and deletion.
 * Maintains local synchronization when items are deleted.
 */
export function useScanHistory(initialParams = {}) {
  const [scans, setScans] = useState([]);
  const [pagination, setPagination] = useState({
    total: 0,
    page: 1,
    limit: 20,
    totalPages: 1,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Preserve the latest query parameters for refetching
  const lastParamsRef = useRef(initialParams);

  const fetchHistory = useCallback(async (params = {}) => {
    setIsLoading(true);
    setError(null);

    const mergedParams = { ...lastParamsRef.current, ...params };
    lastParamsRef.current = mergedParams;

    try {
      const response = await scanService.getHistory(mergedParams);
      if (response?.success && response.data) {
        setScans(response.data.scans || []);
        if (response.data.pagination) {
          setPagination(response.data.pagination);
        }
        return { success: true, data: response.data };
      }
      const message = 'Failed to load scan history.';
      setError(message);
      return { success: false, error: message };
    } catch (err) {
      const message = err.response?.data?.error?.message || err.message || 'An error occurred while loading history.';
      setError(message);
      return { success: false, error: message };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const refetch = useCallback(() => {
    return fetchHistory(lastParamsRef.current);
  }, [fetchHistory]);

  const deleteScan = useCallback(async (id) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await scanService.deleteScan(id);
      if (response?.success) {
        // Optimistically remove from local state
        setScans((prev) => prev.filter((scan) => scan.id !== id && scan.scanId !== id));
        setPagination((prev) => ({
          ...prev,
          total: Math.max(0, prev.total - 1),
        }));
        return { success: true };
      }
      const message = 'Failed to delete scan.';
      setError(message);
      return { success: false, error: message };
    } catch (err) {
      const message = err.response?.data?.error?.message || err.message || 'An error occurred while deleting scan.';
      setError(message);
      return { success: false, error: message };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearHistory = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await scanService.clearHistory();
      if (response?.success) {
        setScans([]);
        setPagination({ total: 0, page: 1, limit: 20, totalPages: 1 });
        return { success: true };
      }
      const message = 'Failed to clear scan history.';
      setError(message);
      return { success: false, error: message };
    } catch (err) {
      const message = err.response?.data?.error?.message || err.message || 'An error occurred while clearing scan history.';
      setError(message);
      return { success: false, error: message };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setScans([]);
    setPagination({ total: 0, page: 1, limit: 20, totalPages: 1 });
    setError(null);
    setIsLoading(false);
  }, []);

  return {
    scans,
    pagination,
    isLoading,
    error,
    fetchHistory,
    refetch,
    deleteScan,
    clearHistory,
    reset,
  };
}


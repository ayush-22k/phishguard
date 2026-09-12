import { useState, useCallback } from 'react';
import { scanService } from '../services/scanService';

/**
 * Unified custom React hook for scan operations.
 * Provides submitUrlScan, submitEmailScan, fetchHistory, getScanDetails, and removeScan.
 */
export function useScans() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [errorCode, setErrorCode] = useState(null);

  const execute = async (apiCall) => {
    setIsLoading(true);
    setError(null);
    setErrorCode(null);

    try {
      const result = await apiCall();
      return { success: true, data: result.data };
    } catch (err) {
      const apiError = err.response?.data?.error;
      const message = apiError?.message || err.message || 'An error occurred during the scan operation.';
      const code = apiError?.code || 'OPERATION_FAILED';
      setError(message);
      setErrorCode(code);
      return { success: false, error: message, code };
    } finally {
      setIsLoading(false);
    }
  };

  const submitUrlScan = useCallback((url) => {
    return execute(() => scanService.scanUrl(url));
  }, []);

  const submitEmailScan = useCallback((subjectOrInput, maybeBody) => {
    return execute(() => scanService.scanEmail(subjectOrInput, maybeBody));
  }, []);

  const fetchHistory = useCallback((params) => {
    return execute(() => scanService.getHistory(params));
  }, []);

  const getScanDetails = useCallback((id) => {
    return execute(() => scanService.getScanById(id));
  }, []);

  const removeScan = useCallback((id) => {
    return execute(() => scanService.deleteScan(id));
  }, []);

  const reset = useCallback(() => {
    setError(null);
    setErrorCode(null);
    setIsLoading(false);
  }, []);

  return {
    submitUrlScan,
    submitEmailScan,
    fetchHistory,
    getScanDetails,
    removeScan,
    reset,
    isLoading,
    error,
    errorCode,
  };
}

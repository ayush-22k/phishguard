import { useState, useCallback } from 'react';
import { scanService } from '../services/scanService';

/**
 * Custom React hook for email phishing scans.
 * Supports passing either { subject, body } or (subject, body).
 * Provides isolated loading, error, result states and submission handler.
 */
export function useEmailScan() {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [errorCode, setErrorCode] = useState(null);

  const scanEmail = useCallback(async (subjectOrInput, maybeBody) => {
    setIsLoading(true);
    setError(null);
    setErrorCode(null);

    try {
      const response = await scanService.scanEmail(subjectOrInput, maybeBody);
      if (response?.success && response.data) {
        setData(response.data);
        return { success: true, data: response.data };
      }
      const message = 'Failed to analyze email.';
      setError(message);
      return { success: false, error: message };
    } catch (err) {
      const apiError = err.response?.data?.error;
      const message = apiError?.message || err.message || 'An unexpected error occurred during email scan.';
      const code = apiError?.code || 'SCAN_FAILED';
      setError(message);
      setErrorCode(code);
      return { success: false, error: message, code };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setErrorCode(null);
    setIsLoading(false);
  }, []);

  return {
    scanEmail,
    data,
    isLoading,
    error,
    errorCode,
    reset,
  };
}


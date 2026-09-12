import { api } from './api';

export const scanService = {
  /**
   * Submit a URL for heuristic phishing analysis.
   * @param {string} url - Raw URL to analyze
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async scanUrl(url) {
    const trimmedUrl = typeof url === 'string' ? url.trim() : '';
    const response = await api.post('/scans/url', { url: trimmedUrl });
    return response.data;
  },

  /**
   * Submit email content for semantic phishing analysis and embedded URL extraction.
   * Supports either (subject, body) or ({ subject, body }) signature.
   * @param {string|{ subject?: string, body?: string }} subjectOrInput
   * @param {string} [maybeBody]
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async scanEmail(subjectOrInput, maybeBody) {
    let payload;
    if (typeof subjectOrInput === 'object' && subjectOrInput !== null) {
      payload = {
        subject: typeof subjectOrInput.subject === 'string' ? subjectOrInput.subject : '',
        body: typeof subjectOrInput.body === 'string' ? subjectOrInput.body : '',
      };
    } else {
      payload = {
        subject: typeof subjectOrInput === 'string' ? subjectOrInput : '',
        body: typeof maybeBody === 'string' ? maybeBody : '',
      };
    }

    const response = await api.post('/scans/email', payload);
    return response.data;
  },

  /**
   * Retrieve scan history with optional pagination and filtering parameters.
   * @param {Object} [params] - Query options: { page, limit, type, classification, sortBy, sortOrder }
   * @returns {Promise<{ success: boolean, data: { scans: Array, pagination: Object } }>}
   */
  async getHistory(params = {}) {
    const response = await api.get('/scans', { params });
    return response.data;
  },

  /**
   * Retrieve a specific scan result by its ID.
   * @param {string} id - UUID of the scan
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async getScanById(id) {
    const response = await api.get(`/scans/${id}`);
    return response.data;
  },

  /**
   * Delete a scan record by its ID.
   * @param {string} id - UUID of the scan
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async deleteScan(id) {
    const response = await api.delete(`/scans/${id}`);
    return response.data;
  },

  /**
   * Delete all scan records for the authenticated user.
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async clearHistory() {
    const response = await api.delete('/scans');
    return response.data;
  },

  /**
   * Get analytics dashboard statistics for the authenticated user.
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async getAnalytics(params = {}) {
    const response = await api.get('/scans/analytics', { params });
    return response.data;
  },

  /**
   * Request an AI explanation for a URL scan.
   * @param {string} scanId - UUID of the scan
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async explainUrlWithAI(scanId) {
    const response = await api.post('/ai/explain-url', { scanId });
    return response.data;
  },

  /**
   * Request an AI explanation for an email scan.
   * @param {string} scanId - UUID of the scan
   * @returns {Promise<{ success: boolean, data: Object }>}
   */
  async explainEmailWithAI(scanId) {
    const response = await api.post('/ai/explain-email', { scanId });
    return response.data;
  },
};


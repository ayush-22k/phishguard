import { query } from '../database/index.js';

export async function getHealth(_request, response) {
  let dbStatus = 'disconnected';
  try {
    await query('SELECT 1 AS health');
    dbStatus = 'connected';
  } catch (error) {
    dbStatus = 'error';
    // Deliberately not logging the specific DB connection error to the response
  }

  const isHealthy = dbStatus === 'connected';
  
  response.status(isHealthy ? 200 : 503).json({
    success: isHealthy,
    message: isHealthy ? 'PhishGuard API is running' : 'PhishGuard API is degraded',
    data: {
      database: dbStatus,
      timestamp: new Date().toISOString()
    }
  });
}

import axios from 'axios';

let currentAccessToken = null;

export const setAccessToken = (token) => {
  currentAccessToken = token;
};

export const getAccessToken = () => currentAccessToken;

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  withCredentials: true, // Crucial for sending/receiving HttpOnly cookies
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercept requests to attach the access token
api.interceptors.request.use(
  (config) => {
    if (currentAccessToken && !config._skipAuth) {
      config.headers['Authorization'] = `Bearer ${currentAccessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// We need a mechanism to tell the AuthContext that a session has expired completely
let logoutHandler = null;
export const setLogoutHandler = (handler) => {
  logoutHandler = handler;
};

// Intercept responses to handle 401 Unauthorized (token refresh logic)
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If error is 401 and we haven't retried yet, and it's not the refresh endpoint itself
    if (error.response?.status === 401 && !originalRequest._retry && !originalRequest._skipAuth) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh the token using the HttpOnly cookie
        const refreshResponse = await api.post(
          '/auth/refresh',
          {},
          { _skipAuth: true, _retry: true } // Prevents infinite loop if refresh 401s
        );

        if (refreshResponse.data?.success && refreshResponse.data?.data?.accessToken) {
          const newToken = refreshResponse.data.data.accessToken;
          setAccessToken(newToken);
          
          // Retry the original request
          originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, meaning the session is truly dead.
        setAccessToken(null);
        if (logoutHandler) {
          logoutHandler();
        }
        return Promise.reject(refreshError);
      }
    }

    // Check for Network Error / Offline backend
    if (!error.response && error.message === 'Network Error') {
      return Promise.reject({
        ...error,
        response: {
          data: {
            error: {
              code: 'NETWORK_ERROR',
              message: 'Unable to connect to PhishGuard. The security service is currently unavailable. Please try again.',
            }
          }
        }
      });
    }

    // Timeout
    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return Promise.reject({
        ...error,
        response: {
          data: {
            error: {
              code: 'TIMEOUT',
              message: 'The request took too long. Please check your connection and try again.',
            }
          }
        }
      });
    }

    return Promise.reject(error);
  }
);


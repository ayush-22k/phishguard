import { api, setAccessToken } from './api';

export const authService = {
  async register(name, email, password) {
    const response = await api.post('/auth/register', { name, email, password });
    return response.data;
  },

  async login(email, password) {
    const response = await api.post('/auth/login', { email, password });
    if (response.data?.success) {
      setAccessToken(response.data.data.accessToken);
    }
    return response.data;
  },

  async logout() {
    try {
      await api.post('/auth/logout');
    } finally {
      setAccessToken(null);
    }
  },

  async getMe() {
    const response = await api.get('/auth/me');
    return response.data;
  },

  async refresh() {
    // Called explicitly on page load. _skipAuth prevents the request interceptor
    // from adding an (empty) Authorization header, and _retry prevents the
    // response interceptor from looping if this call itself returns 401.
    const response = await api.post('/auth/refresh', {}, { _skipAuth: true, _retry: true });
    if (response.data?.success) {
      setAccessToken(response.data.data.accessToken);
    }
    return response.data;
  }
};


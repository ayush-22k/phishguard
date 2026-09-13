import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { authService } from '../services/authService';
import { setLogoutHandler } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  // Guard against React Strict Mode's double-invocation of effects.
  // Token rotation means calling /refresh twice invalidates the session.
  const initialized = useRef(false);

  // Provide a way for the Axios interceptor to trigger a logout
  // if the refresh token expires.
  const handleSessionExpired = useCallback(() => {
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  useEffect(() => {
    setLogoutHandler(handleSessionExpired);
  }, [handleSessionExpired]);

  const checkAuth = async () => {
    try {
      setIsLoading(true);
      // The /auth/refresh response already includes the user object, so we
      // don't need a separate getMe() call. This avoids a second round-trip
      // and prevents the response interceptor from triggering another refresh
      // attempt when getMe() lands before the new session is fully active.
      const refreshRes = await authService.refresh();
      if (refreshRes?.success && refreshRes.data?.user) {
        setUser(refreshRes.data.user);
        setIsAuthenticated(true);
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch (err) {
      // Refresh failed (cookie expired or no session) — user is unauthenticated.
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // The ref persists across React Strict Mode's mount/unmount/remount cycle.
    // This ensures /auth/refresh is only called once, preventing the second
    // call from consuming the rotated session that the first call just created.
    if (initialized.current) return;
    initialized.current = true;
    checkAuth();
  }, []);

  const login = async (email, password) => {
    const res = await authService.login(email, password);
    if (res.success) {
      setUser(res.data.user);
      setIsAuthenticated(true);
    }
    return res;
  };

  const register = async (name, email, password) => {
    const res = await authService.register(name, email, password);
    if (res?.success) {
      await login(email, password);
    }
    return res;
  };

  const logout = async () => {
    try {
      await authService.logout();
    } finally {
      handleSessionExpired();
    }
  };

  return (
    <AuthContext.Provider value={{
      user,
      isAuthenticated,
      isLoading,
      login,
      register,
      logout,
      checkAuth
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};


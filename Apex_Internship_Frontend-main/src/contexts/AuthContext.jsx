import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useToast } from '../components/common/Toast';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api";

// --- SECURE STORAGE ---
const secureStorage = {
  setToken: (token) => {
    try {
      sessionStorage.setItem('auth_token', token);
      sessionStorage.setItem('auth_timestamp', Date.now().toString());
    } catch (error) {
      console.error('Failed to store token:', error);
    }
  },
  getToken: () => {
    try {
      return sessionStorage.getItem('auth_token');
    } catch (error) {
      return null;
    }
  },
  clearAuth: () => {
    try {
      sessionStorage.removeItem('auth_token');
      sessionStorage.removeItem('auth_timestamp');
      localStorage.removeItem('auth_token');
      localStorage.removeItem('auth_timestamp');
    } catch (error) {
      console.error('Failed to clear auth:', error);
    }
  },
  isTokenExpired: () => {
    const timestamp = sessionStorage.getItem('auth_timestamp');
    if (!timestamp) return true;
    // Check if token is older than 24 hours
    return Date.now() - parseInt(timestamp) > 24 * 60 * 60 * 1000;
  }
};

// --- AUTH CONTEXT ---
const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { showSuccess, showError, showLoading, dismissToast } = useToast();
  
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // --- API REQUEST WITH INTERCEPTOR ---
  const apiRequest = useCallback(async (endpoint, options = {}) => {
    const token = secureStorage.getToken();
    // Don't send Authorization header for auth endpoints except verify
    const isAuthEndpoint = endpoint.startsWith('/auth/') && endpoint !== '/auth/verify';
    const headers = {
      ...(token && !isAuthEndpoint && { Authorization: `Bearer ${token}` }),
      ...options.headers,
      // Only set default JSON content-type if not already specified
      ...(!options.headers?.['Content-Type'] && { 'Content-Type': 'application/json' })
    };

    // Add request timestamp for debugging
    const requestId = Math.random().toString(36).substr(2, 9);
    console.debug(`[API Request ${requestId}] ${options.method || 'GET'} ${endpoint}`);

    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers
      });

      console.debug(`[API Response ${requestId}] ${response.status} ${response.statusText}`);

      // Handle 401 - Unauthorized
      if (response.status === 401) {
        console.warn(`[Auth] Token expired or invalid for ${endpoint}`);
        
        // Only show error if not already refreshing
        if (!isRefreshing) {
          await logout();
          navigate('/', { 
            state: { 
              from: location,
              message: 'Your session has expired. Please login again.'
            }, 
            replace: true 
          });
        }
        
        throw new Error('Session expired. Please login again.');
      }

      // Handle 403 - Forbidden
      if (response.status === 403) {
        const errorData = await response.json().catch(() => ({}));
        const message = errorData.detail?.reason || errorData.detail || 'Access denied';
        
        // Show upgrade required UI if specified
        if (errorData.detail?.upgrade_required) {
          throw new Error('Upgrade Required');
        }
        
        throw new Error(message);
      }

      // Handle 429 - Rate Limited
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 5000;
        
        showError('Rate Limited', `Too many requests. Please wait ${Math.ceil(waitTime/1000)} seconds.`);
        throw new Error(`Rate limited. Retry after ${waitTime}ms`);
      }

      // Handle other errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        // Handle different error response structures
        let message;
        if (Array.isArray(errorData.detail)) {
          // Pydantic validation error array
          message = errorData.detail.map(err => err.msg).join(', ');
        } else if (typeof errorData.detail === 'string') {
          // Simple string error
          message = errorData.detail;
        } else if (errorData.message) {
          // Direct message field
          message = errorData.message;
        } else {
          // Fallback
          message = `HTTP ${response.status}`;
        }
        
        // Don't show error for validation errors (422)
        if (response.status !== 422) {
          showError('Request Failed', message);
        }
        
        throw new Error(message);
      }

      // Handle successful responses
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return response.json();
      } else if (contentType && contentType.includes('application/pdf')) {
        return response.blob();
      } else {
        return response.text();
      }

    } catch (error) {
      console.error(`[API Error ${requestId}]`, error);
      
      // Re-throw network errors and other exceptions
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        showError('Network Error', 'Unable to connect to the server. Please check your connection.');
        throw new Error('Network error');
      }
      
      throw error;
    }
  }, [navigate, location, isRefreshing, showError]);

  // --- AUTHENTICATION METHODS ---
  const login = useCallback(async (username, password) => {
    try {
      setIsLoading(true);
      
      console.log('[Auth] Sending traditional login with JSON:', { username, password });
      
      const data = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ 
          username: username, 
          password: password 
        })
      });

      if (data.access_token) {
        secureStorage.setToken(data.access_token);
        setUser({ 
          username: data.wallet_address || username,
          role: data.role || 'student',
          access_level: data.access_level || 'basic'
        });
        setIsAuthenticated(true);
        showSuccess('Access Granted', 'Welcome to Dashboard.');
        return true;
      }
      
      throw new Error('Invalid token response');
    } catch (error) {
      if (error.message === 'Upgrade Required') {
        showError('Access Denied', 'Your account requires an upgraded subscription to access this content.');
      } else {
        showError('Login Failed', error.message);
      }
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [apiRequest, showSuccess, showError]);

  const loginWithWeb3 = useCallback(async (walletAddress, signature) => {
    try {
      setIsLoading(true);
      
      console.log('[Auth] Sending Web3 login with:', { walletAddress });
      
      const data = await apiRequest('/auth/login/web3', {
        method: 'POST',
        body: JSON.stringify({ 
          wallet_address: walletAddress, 
          signature: signature 
        })
      });

      if (data.access_token) {
        secureStorage.setToken(data.access_token);
        setUser({ 
          username: data.username || walletAddress,
          wallet_address: walletAddress,
          role: data.role || 'student',
          access_level: data.access_level || 'basic'
        });
        setIsAuthenticated(true);
        showSuccess('Access Granted', 'Welcome to Dashboard.');
        return true;
      }
      
      throw new Error('Invalid token response');
    } catch (error) {
      if (error.message === 'Upgrade Required') {
        showError('Access Denied', 'Your account requires an upgraded subscription to access this content.');
      } else {
        showError('Login Failed', error.message);
      }
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [apiRequest, showSuccess, showError]);

  const logout = useCallback(async () => {
    console.log('AuthContext - Logout function called');
    
    try {
      // Call backend logout to invalidate session
      console.log('AuthContext - Calling backend logout endpoint');
      await apiRequest('/auth/logout', { method: 'POST' });
      console.log('AuthContext - Backend logout successful');
    } catch (error) {
      // Continue with local logout even if backend call fails
      console.warn('AuthContext - Backend logout failed:', error.message);
    }
    
    // Clear auth state IMMEDIATELY (outside try-catch to ensure it always runs)
    console.log('AuthContext - Clearing local auth data');
    
    // Clear tokens from storage first
    secureStorage.clearAuth();
    console.log('AuthContext - Tokens cleared from storage');
    
    // Clear all possible localStorage items (fallback)
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_timestamp');
    localStorage.removeItem('user');
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('auth_timestamp');
    console.log('AuthContext - All storage cleared');
    
    // Update context state immediately and synchronously
    setUser(null);
    setIsAuthenticated(false);
    setIsLoading(false);
    console.log('AuthContext - User state cleared: user=null, isAuthenticated=false, isLoading=false');
    
    // Force a re-render by updating the state again
    setTimeout(() => {
      setUser(null);
      setIsAuthenticated(false);
      setIsLoading(false);
      console.log('AuthContext - State update forced');
    }, 0);
    
    // Navigate to login
    console.log('AuthContext - Navigating to login page');
    navigate('/', { replace: true });
    console.log('AuthContext - Logout completed');
    
  }, [apiRequest, navigate]);

  const verifyAuth = useCallback(async () => {
    const token = secureStorage.getToken();
    if (!token) {
      // No token at all, clear any partial auth state
      secureStorage.clearAuth();
      setUser(null);
      setIsAuthenticated(false);
      return false;
    }
    
    if (secureStorage.isTokenExpired()) {
      // Token expired, clear it
      secureStorage.clearAuth();
      setUser(null);
      setIsAuthenticated(false);
      return false;
    }

    try {
      const data = await apiRequest('/auth/verify');
      setUser({ 
        username: data.username || data.wallet_address,
        wallet_address: data.wallet_address || data.username,
        role: data.role,
        access_level: data.access_level
      });
      setIsAuthenticated(true);
      return true;
    } catch (error) {
      console.warn('Auth verification failed:', error.message);
      // Clear invalid token
      secureStorage.clearAuth();
      setUser(null);
      setIsAuthenticated(false);
      return false;
    }
  }, [apiRequest]);

  // --- TOKEN REFRESH ---
  const refreshToken = useCallback(async () => {
    if (isRefreshing) return false;
    
    try {
      setIsRefreshing(true);
      const success = await verifyAuth();
      if (success) {
        showSuccess('Session Refreshed', 'Your session has been extended.');
      }
      return success;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    } finally {
      setIsRefreshing(false);
    }
  }, [isRefreshing, verifyAuth, showSuccess]);

  // --- AUTO-REFRESH TOKEN ---
  useEffect(() => {
    if (!isAuthenticated) return;

    // Set up token refresh every 30 minutes
    const refreshInterval = setInterval(async () => {
      const token = secureStorage.getToken();
      if (token && !secureStorage.isTokenExpired()) {
        await refreshToken();
      }
    }, 30 * 60 * 1000); // 30 minutes

    return () => clearInterval(refreshInterval);
  }, [isAuthenticated, refreshToken]);

  // --- INITIAL AUTH CHECK ---
  useEffect(() => {
    const initAuth = async () => {
      setIsLoading(true);
      
      // Check if user was redirected from login with a message
      const state = location.state;
      if (state?.message) {
        showError('Authentication', state.message);
        // Clear state to prevent showing the message again
        navigate(location.pathname, { replace: true, state: null });
      }
      
      await verifyAuth();
      setIsLoading(false);
    };
    
    initAuth();
  }, [verifyAuth, location.pathname, location.state, navigate, showError]);

  // --- HANDLE VISIBILITY CHANGE (TAB SWITCHING) ---
  useEffect(() => {
    const handleVisibilityChange = async () => {
      if (!document.hidden && isAuthenticated) {
        // Verify token when user returns to the tab
        const token = secureStorage.getToken();
        if (token && !secureStorage.isTokenExpired()) {
          await verifyAuth();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [isAuthenticated, verifyAuth]);

  const value = {
    user,
    isAuthenticated,
    isLoading,
    isRefreshing,
    login,
    loginWithWeb3,
    logout,
    verifyAuth,
    refreshToken,
    apiRequest
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;

import React, { createContext, useContext, useState, useEffect } from 'react';

const AdminAuthContext = createContext();

export const useAdminAuth = () => {
  const context = useContext(AdminAuthContext);
  if (!context) {
    throw new Error('useAdminAuth must be used within an AdminAuthProvider');
  }
  return context;
};

export const AdminAuthProvider = ({ children }) => {
  const [isAdminAuthenticated, setIsAdminAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Check admin auth on mount and when localStorage changes
  useEffect(() => {
    const checkAdminAuth = () => {
      try {
        const adminAuth = localStorage.getItem('adminAuth');
        const isAuthenticated = adminAuth === 'true';
        
        console.log('AdminAuthContext - Checking auth:', { adminAuth, isAuthenticated });
        
        setIsAdminAuthenticated(isAuthenticated);
      } catch (error) {
        console.error('AdminAuthContext - Error checking auth:', error);
        setIsAdminAuthenticated(false);
      } finally {
        setIsLoading(false);
      }
    };

    // Check on initial mount
    checkAdminAuth();

    // Listen for storage changes (for cross-tab sync)
    const handleStorageChange = (e) => {
      if (e.key === 'adminAuth') {
        console.log('AdminAuthContext - Storage changed:', e.newValue);
        checkAdminAuth();
      }
    };

    window.addEventListener('storage', handleStorageChange);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const adminLogin = (username, password) => {
    console.log('AdminAuthContext - Login attempt:', username);
    
    // Temporary frontend validation
    if (username === 'admin' && password === 'admin123') {
      localStorage.setItem('adminAuth', 'true');
      setIsAdminAuthenticated(true);
      console.log('AdminAuthContext - Login successful');
      return { success: true };
    } else {
      console.log('AdminAuthContext - Login failed');
      return { success: false, message: 'Invalid credentials' };
    }
  };

  const adminLogout = () => {
    console.log('AdminAuthContext - adminLogout function called');
    
    try {
      // Clear admin session from localStorage
      localStorage.removeItem('adminAuth');
      console.log('AdminAuthContext - adminAuth removed from localStorage');
      
      // Update state
      setIsAdminAuthenticated(false);
      console.log('AdminAuthContext - adminAuth state set to false');
      
      // Verify it's removed
      const checkAuth = localStorage.getItem('adminAuth');
      console.log('AdminAuthContext - Verification - adminAuth after removal:', checkAuth);
      
      console.log('AdminAuthContext - adminLogout completed successfully');
      return { success: true };
    } catch (error) {
      console.error('AdminAuthContext - adminLogout error:', error);
      // Still try to update state even if localStorage fails
      setIsAdminAuthenticated(false);
      return { success: false, message: error.message };
    }
  };

  const value = {
    isAdminAuthenticated,
    isLoading,
    adminLogin,
    adminLogout
  };

  return (
    <AdminAuthContext.Provider value={value}>
      {children}
    </AdminAuthContext.Provider>
  );
};

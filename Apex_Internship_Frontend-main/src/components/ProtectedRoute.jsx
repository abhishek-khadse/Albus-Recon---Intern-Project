import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

/**
 * ProtectedRoute Wrapper
 * Uses AuthContext to check authentication status
 */
const ProtectedRoute = ({ 
  redirectPath = '/', 
  requiredRoles = [] 
}) => {
  const location = useLocation();
  const { isAuthenticated, isLoading, user } = useAuth();

  console.log('[ProtectedRoute] Auth state:', { isAuthenticated, isLoading, user });

  // Show loading while checking authentication
  if (isLoading) {
    console.log('[ProtectedRoute] Showing loading state');
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  // 1. Check Authentication
  if (!isAuthenticated) {
    console.log('[ProtectedRoute] Not authenticated, redirecting to:', redirectPath);
    // Redirect to login, saving the location they tried to access
    return <Navigate to={redirectPath} state={{ from: location }} replace />;
  }

  console.log('[ProtectedRoute] Authenticated, rendering Outlet');
  // 2. Check Roles (Optional - simplistic implementation)
  if (requiredRoles.length > 0 && user) {
    const hasRequiredRole = requiredRoles.some(role => 
      user.roles?.includes(role) || user.role === role
    );
    
    if (!hasRequiredRole) {
      // User is logged in but doesn't have permission. 
      // Redirect to home or a "403 Unauthorized" page.
      return <Navigate to="/" replace />;
    }
  }

  // 3. Render Outlet for nested routes
  return <Outlet />;
};

export default ProtectedRoute;
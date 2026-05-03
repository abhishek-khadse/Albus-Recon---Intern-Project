import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAdminAuth } from '../../contexts/AdminAuthContext';

const AdminRoute = ({ children }) => {
  const { isAdminAuthenticated, isLoading } = useAdminAuth();

  console.log('AdminRoute - Auth state:', { isAdminAuthenticated, isLoading });

  if (isLoading) {
    console.log('AdminRoute - Loading auth state...');
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  if (!isAdminAuthenticated) {
    console.log('AdminRoute - Not authenticated, redirecting to login');
    return <Navigate to="/admin/login" replace />;
  }

  console.log('AdminRoute - Authenticated, rendering children');
  return children;
};

export default AdminRoute;

import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react';

// Toast context for managing notifications
const ToastContext = createContext();

// Toast types
export const TOAST_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
  LOADING: 'loading'
};

// Toast component
const Toast = ({ toast, onRemove }) => {
  const getIcon = () => {
   
    switch (toast.type) {
   
      case TOAST_TYPES.SUCCESS:
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case TOAST_TYPES.ERROR:
        return <XCircle className="w-5 h-5 text-red-500" />;
      case TOAST_TYPES.WARNING:
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case TOAST_TYPES.INFO:
        return <Info className="w-5 h-5 text-blue-500" />;
      case TOAST_TYPES.LOADING:
        return <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />;
      default:
        return <Info className="w-5 h-5 text-blue-500" />;
    }
  };

  const getStyles = () => {
    switch (toast.type) {
      case TOAST_TYPES.SUCCESS:
        return 'bg-green-50 border-green-200 text-green-800';
      case TOAST_TYPES.ERROR:
        return 'bg-red-50 border-red-200 text-red-800';
      case TOAST_TYPES.WARNING:
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      case TOAST_TYPES.INFO:
        return 'bg-blue-50 border-blue-200 text-blue-800';
      case TOAST_TYPES.LOADING:
        return 'bg-blue-50 border-blue-200 text-blue-800';
      default:
        return 'bg-gray-50 border-gray-200 text-gray-800';
    }
  };

  return (
    <div
      className={`
        flex items-center gap-3 p-4 rounded-lg border shadow-lg
        animate-in slide-in-from-right-full duration-300
        max-w-md w-full
        ${getStyles()}
      `}
      role="alert"
      aria-live={toast.type === TOAST_TYPES.ERROR ? 'assertive' : 'polite'}
    >
      {getIcon()}
      <div className="flex-1 min-w-0">
        <p className="font-medium text-sm">{toast.title}</p>
        {toast.description && (
          <p className="text-xs opacity-75 mt-1">{toast.description}</p>
        )}
      </div>
      {toast.type !== TOAST_TYPES.LOADING && (
        <button
          onClick={() => onRemove(toast.id)}
          className="p-1 hover:bg-black/10 rounded-md transition-colors"
          aria-label="Close notification"
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};

// Toast container component
export const ToastContainer = () => {
  const { toasts, removeToast } = useContext(ToastContext);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none">
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <Toast toast={toast} onRemove={removeToast} />
        </div>
      ))}
    </div>
  );
};

// Toast provider component
export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const addToast = useCallback((toast) => {
    const id = Date.now() + Math.random();
    const newToast = { ...toast, id };

    setToasts((prev) => [...prev, newToast]);

    // Auto-remove after duration (except for loading toasts)
    if (toast.type !== TOAST_TYPES.LOADING && toast.duration !== 0) {
      const duration = toast.duration || 5000;
      setTimeout(() => removeToast(id), duration);
    }

    return id;
  }, [removeToast]);

  const updateToast = useCallback((id, updates) => {
    setToasts((prev) =>
      prev.map((toast) =>
        toast.id === id ? { ...toast, ...updates } : toast
      )
    );
  }, []);

  const contextValue = {
    toasts,
    addToast,
    removeToast,
    updateToast
  };

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <ToastContainer />
    </ToastContext.Provider>
  );
};

// Hook for using toasts
export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }

  const showSuccess = useCallback((title, description, options = {}) => {
    return context.addToast({ type: TOAST_TYPES.SUCCESS, title, description, ...options });
  }, [context]);

  const showError = useCallback((title, description, options = {}) => {
    return context.addToast({ type: TOAST_TYPES.ERROR, title, description, ...options });
  }, [context]);

  const showWarning = useCallback((title, description, options = {}) => {
    return context.addToast({ type: TOAST_TYPES.WARNING, title, description, ...options });
  }, [context]);

  const showInfo = useCallback((title, description, options = {}) => {
    return context.addToast({ type: TOAST_TYPES.INFO, title, description, ...options });
  }, [context]);

  const showLoading = useCallback((title, description, options = {}) => {
    return context.addToast({ type: TOAST_TYPES.LOADING, title, description, duration: 0, ...options });
  }, [context]);

  const dismissToast = useCallback((id) => {
    context.removeToast(id);
  }, [context]);

  return {
    ...context,
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showLoading,
    dismissToast
  };
};

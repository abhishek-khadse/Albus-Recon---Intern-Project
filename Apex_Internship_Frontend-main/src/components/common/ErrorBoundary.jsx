import React from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null, 
      errorInfo: null,
      errorId: null
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Generate unique error ID for tracking
    const errorId = `ERR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Log error to console with details
    console.error(`[ErrorBoundary ${errorId}] Caught an error:`, error, errorInfo);
    
    // Log error to service (if available)
    this.logErrorToService(error, errorInfo, errorId);
    
    // Update state with error details
    this.setState({
      error,
      errorInfo,
      errorId
    });
  }

  logErrorToService = (error, errorInfo, errorId) => {
    try {
      // In production, you would send this to your error tracking service
      // like Sentry, LogRocket, or your own API endpoint
      const errorData = {
        errorId,
        message: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href,
        userId: this.props.userId || 'anonymous'
      };

      // Example: Send to your error logging API
      // fetch('/api/errors', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(errorData)
      // }).catch(err => console.warn('Failed to log error to service:', err));

      // For now, just store in sessionStorage for debugging
      sessionStorage.setItem(`error_${errorId}`, JSON.stringify(errorData));
    } catch (err) {
      console.warn('Failed to log error:', err);
    }
  };

  handleRetry = () => {
    // Clear the error state and retry
    this.setState({ 
      hasError: false, 
      error: null, 
      errorInfo: null,
      errorId: null 
    });
  };

  handleGoHome = () => {
    // Navigate to home and clear error
    this.setState({ 
      hasError: false, 
      error: null, 
      errorInfo: null,
      errorId: null 
    });
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <ErrorFallback 
          error={this.state.error}
          errorId={this.state.errorId}
          onRetry={this.handleRetry}
          onGoHome={this.handleGoHome}
        />
      );
    }

    return this.props.children;
  }
}

// Error Fallback Component
const ErrorFallback = ({ error, errorId, onRetry, onGoHome }) => {
  const isDevelopment = import.meta.env.DEV;
  
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-rose-50/30 to-slate-100 p-4 md:p-8">
      <div className="max-w-3xl mx-auto">
        <div className="bg-white border border-rose-200/60 rounded-3xl shadow-lg shadow-rose-100/50 overflow-hidden">
          
          {/* Header */}
          <div className="px-6 md:px-8 py-6 border-b border-rose-100 bg-gradient-to-r from-rose-50 to-transparent">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-gradient-to-br from-rose-100 to-rose-200 rounded-xl flex items-center justify-center">
                <AlertTriangle className="text-rose-600" size={24} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-900">Something went wrong</h1>
                <p className="text-sm text-slate-600 mt-1">
                  {isDevelopment ? 'An error occurred in development' : 'An unexpected error occurred'}
                </p>
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="p-6 md:p-8 space-y-6">
            
            {/* Error Message */}
            <div className="bg-rose-50 border border-rose-200 rounded-xl p-4">
              <p className="text-sm font-medium text-rose-900">
                {error?.message || 'An unexpected error occurred while rendering this page.'}
              </p>
              {errorId && (
                <p className="text-xs text-rose-600 mt-2">
                  Error ID: <code className="bg-rose-100 px-2 py-1 rounded font-mono">{errorId}</code>
                </p>
              )}
            </div>

            {/* Development Details */}
            {isDevelopment && error && (
              <details className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                <summary className="text-sm font-medium text-slate-900 cursor-pointer hover:text-slate-700">
                  Error Details (Development Only)
                </summary>
                <div className="mt-4 space-y-3">
                  <div>
                    <h4 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">Stack Trace</h4>
                    <pre className="text-xs bg-slate-900 text-slate-100 p-3 rounded-lg overflow-x-auto">
                      {error.stack}
                    </pre>
                  </div>
                </div>
              </details>
            )}

            {/* Actions */}
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={onRetry}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-bold transition-colors"
              >
                <RefreshCw size={16} />
                Try Again
              </button>
              <button
                onClick={onGoHome}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 border border-slate-200 text-slate-700 hover:bg-slate-50 rounded-xl text-sm font-bold transition-colors"
              >
                <Home size={16} />
                Go Home
              </button>
            </div>

            {/* Help Text */}
            <div className="text-center space-y-2">
              <p className="text-sm text-slate-600">
                If this problem persists, please contact support.
              </p>
              {errorId && (
                <p className="text-xs text-slate-500">
                  Please include the Error ID above when reporting this issue.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Hook for functional components
export const useErrorBoundary = () => {
  const navigate = useNavigate();
  
  const handleError = (error, errorInfo) => {
    console.error('Error caught by error boundary:', error, errorInfo);
    
    // In a real app, you might want to log this to an error service
    const errorId = `ERR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Navigate to error page or show error state
    navigate('/error', { 
      state: { 
        error: error.message,
        errorId 
      } 
    });
  };
  
  return { handleError };
};

export default ErrorBoundary;

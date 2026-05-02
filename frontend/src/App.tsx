import React, { useState, useEffect } from 'react';
import { reconApi, ReconResult } from './services/api';
import AdvancedTools from './components/AdvancedTools';
import Login from './components/Login';
import Register from './components/Register';
import { useAuth } from './contexts/AuthContext';

function App() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<ReconResult[]>([]);
  interface ErrorDetails {
    message: string;
    details: string;
    type: string;
    recommendation: string;
  }

  const [error, setError] = useState<ErrorDetails | null>(null);
  const [darkMode, setDarkMode] = useState(true);
  const [activeTab, setActiveTab] = useState('scanner');
  
  // Auth state
  const { isAuthenticated, isLoading: authLoading, logout, user } = useAuth();
  const [authView, setAuthView] = useState<'login' | 'register'>('login');

  const fetchResults = async () => {
    try {
      const data = await reconApi.getResults();
      setResults(data);
    } catch (err) {
      setError({
        message: 'Failed to fetch results',
        details: err instanceof Error ? err.message : 'Unknown error occurred',
        type: 'API_ERROR',
        recommendation: 'Please check your network connection and try again.'
      });
      console.error(err);
    }
  };

  useEffect(() => {
    document.documentElement.classList.add('dark');
    if (isAuthenticated) {
      fetchResults();
    }
  }, [isAuthenticated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsLoading(true);
    setError(null);

    try {
      let processedUrl = url;
      try {
        new URL(processedUrl);
      } catch (e) {
        if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
          processedUrl = 'https://' + processedUrl;
        } else {
          throw new Error('Please enter a valid URL (e.g., example.com or https://example.com)');
        }
      }

      const response = await reconApi.scanUrl(processedUrl);
      
      if (response && response.error) {
        setError({
          message: response.error,
          details: response.details || 'An unknown error occurred',
          type: response.type || 'unknown_error',
          recommendation: response.recommendation || 'Please try again later.'
        });
        return;
      }
      
      setUrl('');
      await fetchResults();
    } catch (err: any) {
      if (err.response?.data) {
        const { error, details, type, recommendation } = err.response.data;
        setError({
          message: error || 'Failed to scan URL',
          details: details || err.message,
          type: type || 'api_error',
          recommendation: recommendation || 'Please try again later.'
        });
      } else if (err.request) {
        setError({
          message: 'No response from server',
          details: 'The server did not respond to our request.',
          type: 'connection_error',
          recommendation: 'Please check your internet connection and try again.'
        });
      } else if (err.message) {
        setError({
          message: 'Error',
          details: err.message,
          type: 'validation_error',
          recommendation: 'Please check the URL and try again.'
        });
      } else {
        setError({
          message: 'An unknown error occurred',
          details: 'Please try again later.',
          type: 'unknown_error',
          recommendation: 'If the problem persists, please contact support.'
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Bypass signin
  /*
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return authView === 'login' ? (
      <Login onNavigateToRegister={() => setAuthView('register')} />
    ) : (
      <Register onNavigateToLogin={() => setAuthView('login')} />
    );
  }
  */

  return (
    <div className="min-h-screen flex flex-col bg-gray-900 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-gray-900 via-gray-900 to-black text-gray-100 font-sans selection:bg-blue-500/30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full z-10">
        
        {/* Header */}
        <div className="flex justify-between items-center mb-10 mt-4 backdrop-blur-md bg-white/5 border border-white/10 p-4 rounded-2xl shadow-xl">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400 tracking-tight">
              Albus Recon
            </h1>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10">
              <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
              <span className="text-sm font-medium text-gray-300">
                {user?.username || 'Analyst'}
              </span>
            </div>
            <button
              onClick={logout}
              className="px-4 py-2 rounded-xl text-sm font-medium text-white bg-white/10 hover:bg-white/20 border border-white/10 transition-all duration-200"
            >
              Sign out
            </button>
          </div>
        </div>
        
        {/* Tabs */}
        <div className="flex space-x-1 mb-8 p-1 bg-white/5 backdrop-blur-md rounded-2xl w-fit border border-white/10">
          <button
            className={`py-2.5 px-6 rounded-xl font-medium text-sm transition-all duration-300 ${activeTab === 'scanner' ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/25' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}
            onClick={() => setActiveTab('scanner')}
          >
            URL Scanner
          </button>
          <button
            className={`py-2.5 px-6 rounded-xl font-medium text-sm transition-all duration-300 ${activeTab === 'tools' ? 'bg-gradient-to-r from-purple-600 to-purple-500 text-white shadow-lg shadow-purple-500/25' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}
            onClick={() => setActiveTab('tools')}
          >
            Advanced Tools
          </button>
        </div>

        {/* Content Area */}
        <div className="animate-fade-in-up">
          {activeTab === 'scanner' && (
            <>
              {/* Scanner Form */}
              <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-3xl p-8 mb-8 shadow-2xl relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 to-purple-500/10 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
                
                <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-4 relative z-10">
                  <div className="relative flex-1">
                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                      <svg className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                      </svg>
                    </div>
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com"
                      className="block w-full pl-11 pr-4 py-4 bg-black/40 border border-white/10 rounded-2xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={!url || isLoading}
                    className="px-8 py-4 bg-blue-600 text-white font-bold rounded-2xl hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg shadow-blue-500/25 flex items-center justify-center min-w-[140px]"
                  >
                    {isLoading ? (
                      <span className="flex items-center gap-2">
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Scanning
                      </span>
                    ) : (
                      'Initialize Scan'
                    )}
                  </button>
                </form>
                
                {error && (
                  <div className={`mt-6 rounded-2xl p-5 backdrop-blur-md border ${error.type === 'warning' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-red-500/10 border-red-500/30'} animate-fade-in`}>
                    <div className="flex">
                      <div className="flex-shrink-0">
                        {error.type === 'warning' ? (
                          <svg className="h-6 w-6 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <svg className="h-6 w-6 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                          </svg>
                        )}
                      </div>
                      <div className="ml-4">
                        <h3 className={`text-sm font-bold ${error.type === 'warning' ? 'text-yellow-400' : 'text-red-400'}`}>
                          {error.type === 'http_error' ? 'HTTP Error' : 
                           error.type === 'validation_error' ? 'Validation Error' : 
                           error.type === 'connection_error' ? 'Connection Error' : 
                           error.type === 'api_error' ? 'API Error' : 'Unknown Error'}
                        </h3>
                        <div className="mt-1 text-sm text-gray-300">
                          <p>{error.message}</p>
                        </div>
                        {error.recommendation && (
                          <div className="mt-3 bg-black/20 p-3 rounded-xl border border-white/5">
                            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Suggestion</p>
                            <p className="text-sm text-gray-300">{error.recommendation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Results Table */}
              <div className="bg-white/5 backdrop-blur-xl shadow-2xl rounded-3xl border border-white/10 overflow-hidden">
                <div className="px-6 py-5 border-b border-white/10 flex justify-between items-center bg-black/20">
                  <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                    <svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    Recent Scans
                  </h3>
                  <span className="text-xs font-medium bg-white/10 px-3 py-1 rounded-full text-gray-300">
                    {results.length} targets
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-white/10">
                    <thead className="bg-black/40">
                      <tr>
                        <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Target URL</th>
                        <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Status Code</th>
                        <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Page Title</th>
                        <th scope="col" className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {results.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="px-6 py-12 text-sm text-gray-500 text-center">
                            <div className="flex flex-col items-center gap-3">
                              <svg className="w-12 h-12 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                              </svg>
                              <p>No scans found. Initialize your first scan above.</p>
                            </div>
                          </td>
                        </tr>
                      ) : (
                        results.map((result) => (
                          <tr key={result.id} className="hover:bg-white/5 transition-colors duration-200 group">
                            <td className="px-6 py-4 whitespace-nowrap">
                              <a 
                                href={result.url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="text-sm font-medium text-blue-400 group-hover:text-blue-300 transition-colors flex items-center gap-2"
                              >
                                {result.url}
                                <svg className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                </svg>
                              </a>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`px-3 py-1 inline-flex text-xs font-bold rounded-full border ${
                                result.status_code >= 200 && result.status_code < 300 
                                  ? 'bg-green-500/10 text-green-400 border-green-500/20' 
                                  : result.status_code >= 400 
                                    ? 'bg-red-500/10 text-red-400 border-red-500/20' 
                                    : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                              }`}>
                                <div className={`w-1.5 h-1.5 rounded-full mr-1.5 self-center ${
                                  result.status_code >= 200 && result.status_code < 300 ? 'bg-green-400' :
                                  result.status_code >= 400 ? 'bg-red-400' : 'bg-yellow-400'
                                }`}></div>
                                {result.status_code || 'N/A'}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 max-w-xs truncate">
                              {result.title || 'No title found'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                              {new Date(result.fetched_at).toLocaleString(undefined, {
                                year: 'numeric',
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit'
                              })}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
          
          {activeTab === 'tools' && (
            <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-3xl p-6 shadow-2xl relative">
              <AdvancedTools />
            </div>
          )}
        </div>
      </div>
      
      {/* Footer */}
      <footer className="mt-auto border-t border-white/10 bg-black/40 backdrop-blur-md py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-sm text-gray-500 font-medium">
            © {new Date().getFullYear()} Albus Recon - Security Research Platform
          </p>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-600 bg-white/5 px-2.5 py-1 rounded-md border border-white/5">
              Code: AKg5pEk1P
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;

import React, { useState, useEffect } from 'react';
import { reconApi, ReconResult } from './services/api';
import AdvancedTools from './components/AdvancedTools';

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
  const [darkMode, setDarkMode] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner');

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
    // Check for saved theme preference
    const isDark = localStorage.getItem('darkMode') === 'true';
    setDarkMode(isDark);
    document.documentElement.classList.toggle('dark', isDark);
    
    // Initial data fetch
    fetchResults();
  }, []);

  const toggleDarkMode = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    localStorage.setItem('darkMode', newMode.toString());
    if (newMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsLoading(true);
    setError(null);

    try {
      // Process URL and ensure it has a protocol
      let processedUrl = url;
      try {
        new URL(processedUrl);
      } catch (e) {
        // If URL is invalid, try adding https://
        if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
          processedUrl = 'https://' + processedUrl;
        } else {
          throw new Error('Please enter a valid URL (e.g., example.com or https://example.com)');
        }
      }

      const response = await reconApi.scanUrl(processedUrl);
      
      // If we get a response with an error field but no exception was thrown
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
      // Handle different types of errors
      if (err.response?.data) {
        // Error from the API
        const { error, details, type, recommendation } = err.response.data;
        setError({
          message: error || 'Failed to scan URL',
          details: details || err.message,
          type: type || 'api_error',
          recommendation: recommendation || 'Please try again later.'
        });
      } else if (err.request) {
        // The request was made but no response was received
        setError({
          message: 'No response from server',
          details: 'The server did not respond to our request.',
          type: 'connection_error',
          recommendation: 'Please check your internet connection and try again.'
        });
      } else if (err.message) {
        // Other errors (like invalid URL)
        setError({
          message: 'Error',
          details: err.message,
          type: 'validation_error',
          recommendation: 'Please check the URL and try again.'
        });
      } else {
        // Unknown error
        setError({
          message: 'An unknown error occurred',
          details: 'Please try again later.',
          type: 'unknown_error',
          recommendation: 'If the problem persists, please contact support.'
        });
      }
      console.error('Scan error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`min-h-screen flex flex-col ${darkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Albus Recon</h1>
          <button
            onClick={toggleDarkMode}
            className="p-2 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700"
            aria-label="Toggle dark mode"
          >
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>
        
        {/* Tabs */}
        <div className="flex border-b border-gray-200 dark:border-gray-700 mb-6">
          <button
            className={`py-2 px-4 font-medium text-sm ${activeTab === 'scanner' ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('scanner')}
          >
            URL Scanner
          </button>
          <button
            className={`py-2 px-4 font-medium text-sm ${activeTab === 'tools' ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('tools')}
          >
            Advanced Tools
          </button>
        </div>

        {activeTab === 'scanner' && (
          <>
            <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6 mb-8">
              <form onSubmit={handleSubmit} className="flex gap-4">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter URL to scan"
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
                />
                <button
                  type="submit"
                  disabled={!url || isLoading}
                  className="px-6 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-blue-700 dark:hover:bg-blue-600 dark:focus:ring-blue-500 dark:focus:ring-offset-gray-800"
                >
                  {isLoading ? (
                    <span className="animate-pulse">Scanning...</span>
                  ) : (
                    'Scan'
                  )}
                </button>
              </form>
              
              {error && (
                <div className={`mt-4 rounded-md p-4 ${error.type === 'warning' ? 'bg-yellow-50 dark:bg-yellow-900/30 border-l-4 border-yellow-400 dark:border-yellow-600' : 'bg-red-50 dark:bg-red-900/30 border-l-4 border-red-400 dark:border-red-600'}`}>
                  <div className="flex">
                    {error.type === 'warning' ? (
                      <svg className="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    ) : (
                      <svg className="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    )}
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
                        {error.type === 'http_error' ? 'HTTP Error' : 
                         error.type === 'validation_error' ? 'Validation Error' : 
                         error.type === 'connection_error' ? 'Connection Error' : 
                         error.type === 'api_error' ? 'API Error' : 'Unknown Error'}
                      </h3>
                      <div className="mt-2 text-sm text-red-700 dark:text-red-300">
                        <p>{error.message}</p>
                      </div>
                      {error.recommendation && (
                        <div className="mt-2">
                          <p className="text-sm font-medium">Suggestion:</p>
                          <p className="text-sm text-red-700 dark:text-red-300">{error.recommendation}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg transition-colors duration-200">
              <div className="px-4 py-5 sm:px-6 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">Scan Results</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-700">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">URL</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Title</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Scanned At</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {results.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 text-center">
                          No scan results yet. Enter a URL above to get started.
                        </td>
                      </tr>
                    ) : (
                      results.map((result) => (
                        <tr key={result.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors duration-150">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <a 
                              href={result.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-sm font-medium text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition-colors"
                            >
                              {result.url}
                            </a>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                              result.status_code >= 200 && result.status_code < 300 
                                ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' 
                                : result.status_code >= 400 
                                  ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' 
                                  : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                            }`}>
                              {result.status_code || 'N/A'}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                            {result.title || 'No title found'}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {new Date(result.fetched_at).toLocaleString()}
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
        
        {activeTab === 'tools' && <AdvancedTools />}
      </div>
      
      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 py-4">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-center">
            <p className="text-center text-sm text-gray-500 dark:text-gray-400">
              © {new Date().getFullYear()} Albus Recon - Intern Project AKg5pEk1P
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;

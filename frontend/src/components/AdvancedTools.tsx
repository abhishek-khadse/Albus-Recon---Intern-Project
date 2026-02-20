import React, { useState } from 'react';
import { reconApi } from '../services/api';
import './AdvancedTools.css';

const AdvancedTools: React.FC = () => {
  const [activeTab, setActiveTab] = useState('subdomains');
  const [domain, setDomain] = useState('');
  const [subdomains, setSubdomains] = useState<string[]>([]);
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState<any[]>([]);
  const [techUrl, setTechUrl] = useState('');
  const [technologies, setTechnologies] = useState<Record<string, any>>({
    content_type: '',
    server: '',
    status_code: 0,
    url: '',
    'x-powered-by': '',
    cms: [],
    javascript_frameworks: [],
    css_frameworks: [],
    analytics: [],
    languages: [],
    web_servers: []
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const findSubdomains = async () => {
    if (!domain) return;
    setLoading(true);
    setError('');
    try {
      const result = await reconApi.findSubdomains(domain);
      setSubdomains(result);
    } catch (err) {
      setError('Failed to fetch subdomains');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const scanPorts = async () => {
    if (!target) return;
    setLoading(true);
    setError('');
    try {
      const result = await reconApi.scanPorts(target);
      setPorts(result);
    } catch (err) {
      setError('Failed to scan ports');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const detectTech = async () => {
    if (!techUrl) return;
    setLoading(true);
    setError('');
    try {
      const result = await reconApi.detectTech(techUrl);
      console.log('Detected technologies:', result);
      setTechnologies(result);
    } catch (err) {
      console.error('Error detecting technologies:', err);
      setError('Failed to detect technologies. Please check the console for details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="advanced-tools p-4 max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Advanced Reconnaissance Tools</h1>
      
      <div className="flex border-b mb-6">
        <button
          className={`px-4 py-2 ${activeTab === 'subdomains' ? 'border-b-2 border-blue-500' : ''}`}
          onClick={() => setActiveTab('subdomains')}
        >
          Subdomains
        </button>
        <button
          className={`px-4 py-2 ${activeTab === 'ports' ? 'border-b-2 border-blue-500' : ''}`}
          onClick={() => setActiveTab('ports')}
        >
          Port Scanner
        </button>
        <button
          className={`px-4 py-2 ${activeTab === 'tech' ? 'border-b-2 border-blue-500' : ''}`}
          onClick={() => setActiveTab('tech')}
        >
          Tech Detection
        </button>
      </div>

      {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">{error}</div>}

      {/* Subdomains Tab */}
      {activeTab === 'subdomains' && (
        <div>
          <div className="mb-6">
            <h2 className="section-header">Subdomain Enumeration</h2>
            <div className="flex gap-2">
              <input
                type="text"
                className="flex-1 p-2 border rounded"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && findSubdomains()}
              />
              <button
                className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded"
                onClick={findSubdomains}
                disabled={loading || !domain.trim()}
              >
                {loading ? 'Searching...' : 'Find Subdomains'}
              </button>
            </div>
          </div>
          
          {subdomains.length > 0 && (
            <div className="results-container">
              <div className="p-4">
                <h3 className="font-semibold text-lg mb-3">Found {subdomains.length} Subdomains</h3>
                <ul className="space-y-2">
                  {subdomains.map((subdomain, i) => (
                    <li key={i} className="py-2 px-3 bg-gray-50 dark:bg-gray-800 rounded break-all">
                      <code className="text-blue-600 dark:text-blue-400">{subdomain}</code>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Port Scanner Tab */}
      {activeTab === 'ports' && (
        <div>
          <div className="mb-6">
            <h2 className="section-header">Port Scanner</h2>
            <div className="flex gap-2">
              <input
                type="text"
                className="flex-1 p-2 border rounded"
                placeholder="example.com or 192.168.1.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && scanPorts()}
              />
              <button
                className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded"
                onClick={scanPorts}
                disabled={loading || !target.trim()}
              >
                {loading ? 'Scanning...' : 'Scan Ports'}
              </button>
            </div>
          </div>
          
          {ports.length > 0 && (
            <div className="results-container">
              <div className="p-4">
                <h3 className="font-semibold text-lg mb-3">Scan Results for {target}</h3>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                      {ports.map((port, i) => (
                        <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                          <td className="py-3 px-4">{port.host}</td>
                          <td className="py-3 px-4 font-mono">{port.port}</td>
                          <td className="py-3 px-4">{port.protocol}</td>
                          <td className="py-3 px-4">
                            <span className={`port-status ${port.state.toLowerCase()}`}>
                              {port.state}
                            </span>
                          </td>
                          <td className="py-3 px-4">{port.service}</td>
                          <td className="py-3 px-4 text-sm text-gray-600 dark:text-gray-300">
                            {port.version || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technology Detection Tab */}
      {activeTab === 'tech' && (
        <div>
          <div className="mb-6">
            <h2 className="section-header">Technology Detection</h2>
            <div className="flex gap-2">
              <input
                type="text"
                className="flex-1 p-2 border rounded"
                placeholder="https://example.com"
                value={techUrl}
                onChange={(e) => setTechUrl(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && detectTech()}
              />
              <button
                className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded"
                onClick={detectTech}
                disabled={loading || !techUrl.trim()}
              >
                {loading ? 'Detecting...' : 'Detect Technologies'}
              </button>
            </div>
          </div>
          
          <div className="mt-4 p-4 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
            <div className="flex justify-between items-center mb-3">
              <h3 className="text-lg font-semibold">Technology Detection</h3>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {technologies.status_code && `Status: ${technologies.status_code}`}
              </span>
            </div>
            
            {/* Server Info */}
            <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-700/50 rounded">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                <div className="flex items-start">
                  <span className="text-gray-500 dark:text-gray-400 w-20 flex-shrink-0">URL</span>
                  <span className="break-all">{technologies.url || 'N/A'}</span>
                </div>
                {technologies.server && (
                  <div className="flex items-start">
                    <span className="text-gray-500 dark:text-gray-400 w-20 flex-shrink-0">Server</span>
                    <span className="flex items-center">
                      <svg className="w-3.5 h-3.5 text-green-500 mr-1" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                      </svg>
                      {technologies.server}
                    </span>
                  </div>
                )}
                {technologies['x-powered-by'] && (
                  <div className="flex items-start">
                    <span className="text-gray-500 dark:text-gray-400 w-20 flex-shrink-0">Powered By</span>
                    <span>{technologies['x-powered-by']}</span>
                  </div>
                )}
              </div>
            </div>
            
            {/* Detected Technologies */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-medium">Detected Technologies</h4>
                <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                  <svg className="w-3.5 h-3.5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>Automatically detected</span>
                </div>
              </div>
              
              <div className="space-y-3">
                {[
                  { key: 'cms', title: 'CMS', icon: '📋' },
                  { key: 'javascript_frameworks', title: 'JavaScript', icon: '⚡' },
                  { key: 'web_servers', title: 'Web Server', icon: '🖥️' },
                  { key: 'analytics', title: 'Analytics', icon: '📊' },
                  { key: 'languages', title: 'Languages', icon: '🌐' },
                  { key: 'css_frameworks', title: 'CSS', icon: '🎨' }
                ].map(({ key, title, icon }) => {
                  const items = technologies[key] || [];
                  const hasItems = items.length > 0;
                  
                  return (
                    <div key={key} className="flex items-start">
                      <div className="w-6 h-6 flex items-center justify-center text-sm mr-2">
                        {icon}
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center">
                          <span className="text-sm font-medium">{title}</span>
                          {!hasItems && (
                            <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded-full">
                              Not detected
                            </span>
                          )}
                        </div>
                        {hasItems && (
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            {items.map((item: string, i: number) => (
                              <span 
                                key={i}
                                className="text-xs px-2 py-0.5 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded border border-blue-100 dark:border-blue-800/50"
                              >
                                {item}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              
              {!Object.values(technologies).some(v => Array.isArray(v) && v.length > 0) && (
                <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-100 dark:border-amber-800/50 rounded text-sm text-amber-800 dark:text-amber-200">
                  <div className="flex">
                    <svg className="w-4 h-4 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                      <p className="font-medium">No technologies detected</p>
                      <p className="text-xs mt-0.5">This is common for well-secured sites or when the server is configured to hide its technology stack.</p>
                    </div>
                  </div>
                </div>
              )}
              
              {/* Demo Sites Suggestion */}
              <div className="mt-4 text-xs text-gray-500 dark:text-gray-400">
                <p className="font-medium mb-1">Try these demo sites:</p>
                <div className="flex flex-wrap gap-2">
                  {['wordpress.org', 'reactjs.org', 'tailwindcss.com'].map(site => (
                    <button
                      key={site}
                      onClick={() => setTechUrl(`https://${site}`)}
                      className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded text-xs"
                    >
                      {site}
                    </button>
                  ))}
                </div>
              </div>
              
              {/* Raw Headers Toggle */}
              <details className="mt-4 text-sm">
                <summary className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 cursor-pointer select-none">
                  View Raw Response Headers
                </summary>
                <pre className="mt-2 p-2 bg-gray-50 dark:bg-gray-800/50 text-xs overflow-auto rounded border border-gray-200 dark:border-gray-700">
                  {JSON.stringify(technologies, null, 2)}
                </pre>
              </details>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default AdvancedTools;

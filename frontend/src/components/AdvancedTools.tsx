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
    <div className="w-full">
      <div className="flex flex-wrap gap-2 mb-8 border-b border-white/10 pb-4">
        <button
          className={`px-5 py-2.5 rounded-xl font-medium text-sm transition-all duration-300 ${activeTab === 'subdomains' ? 'bg-white/10 text-white border border-white/20 shadow-lg' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'}`}
          onClick={() => setActiveTab('subdomains')}
        >
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z" />
            </svg>
            Subdomains
          </div>
        </button>
        <button
          className={`px-5 py-2.5 rounded-xl font-medium text-sm transition-all duration-300 ${activeTab === 'ports' ? 'bg-white/10 text-white border border-white/20 shadow-lg' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'}`}
          onClick={() => setActiveTab('ports')}
        >
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-pink-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
            Port Scanner
          </div>
        </button>
        <button
          className={`px-5 py-2.5 rounded-xl font-medium text-sm transition-all duration-300 ${activeTab === 'tech' ? 'bg-white/10 text-white border border-white/20 shadow-lg' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'}`}
          onClick={() => setActiveTab('tech')}
        >
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
            Tech Detection
          </div>
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border-l-4 border-red-500 p-4 rounded-xl mb-6 animate-fade-in flex items-start gap-3">
          <svg className="w-5 h-5 text-red-400 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-red-400 text-sm font-medium">{error}</p>
        </div>
      )}

      {/* Subdomains Tab */}
      {activeTab === 'subdomains' && (
        <div className="animate-fade-in-up">
          <div className="mb-8">
            <h2 className="text-xl font-bold text-white mb-4">Subdomain Enumeration</h2>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                className="flex-1 px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all duration-200"
                placeholder="Enter domain (e.g., example.com)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && findSubdomains()}
              />
              <button
                className="bg-purple-600 hover:bg-purple-500 text-white px-6 py-3 rounded-xl font-medium transition-colors shadow-lg shadow-purple-500/25 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[160px]"
                onClick={findSubdomains}
                disabled={loading || !domain.trim()}
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    Searching...
                  </span>
                ) : 'Find Subdomains'}
              </button>
            </div>
          </div>
          
          {subdomains.length > 0 && (
            <div className="bg-black/30 border border-white/10 rounded-2xl overflow-hidden shadow-xl animate-fade-in">
              <div className="p-5 border-b border-white/5 bg-white/5 flex justify-between items-center">
                <h3 className="font-semibold text-lg text-white">Found {subdomains.length} Subdomains</h3>
                <span className="flex h-3 w-3 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-purple-500"></span>
                </span>
              </div>
              <ul className="divide-y divide-white/5 max-h-[500px] overflow-y-auto custom-scrollbar">
                {subdomains.map((subdomain, i) => (
                  <li key={i} className="px-6 py-4 hover:bg-white/5 transition-colors flex items-center gap-3">
                    <div className="w-1.5 h-1.5 rounded-full bg-purple-500"></div>
                    <code className="text-purple-300 text-sm">{subdomain}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Port Scanner Tab */}
      {activeTab === 'ports' && (
        <div className="animate-fade-in-up">
          <div className="mb-8">
            <h2 className="text-xl font-bold text-white mb-4">Port Scanner</h2>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                className="flex-1 px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-pink-500 transition-all duration-200"
                placeholder="Enter IP or domain (e.g., example.com or 192.168.1.1)"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && scanPorts()}
              />
              <button
                className="bg-pink-600 hover:bg-pink-500 text-white px-6 py-3 rounded-xl font-medium transition-colors shadow-lg shadow-pink-500/25 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[160px]"
                onClick={scanPorts}
                disabled={loading || !target.trim()}
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    Scanning...
                  </span>
                ) : 'Scan Ports'}
              </button>
            </div>
          </div>
          
          {ports.length > 0 && (
            <div className="bg-black/30 border border-white/10 rounded-2xl overflow-hidden shadow-xl animate-fade-in">
              <div className="p-5 border-b border-white/5 bg-white/5 flex justify-between items-center">
                <h3 className="font-semibold text-lg text-white">Scan Results for <span className="text-pink-400">{target}</span></h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-white/10">
                  <thead className="bg-black/40">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Host</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Port</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Protocol</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">State</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Service</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider">Version</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {ports.map((port, i) => (
                      <tr key={i} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{port.host}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-pink-400">{port.port}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400 uppercase">{port.protocol}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2.5 py-1 text-xs font-bold rounded-full ${port.state.toLowerCase() === 'open' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                            {port.state}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{port.service}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{port.version || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technology Detection Tab */}
      {activeTab === 'tech' && (
        <div className="animate-fade-in-up">
          <div className="mb-8">
            <h2 className="text-xl font-bold text-white mb-4">Technology Detection</h2>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                className="flex-1 px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all duration-200"
                placeholder="Enter URL (e.g., https://example.com)"
                value={techUrl}
                onChange={(e) => setTechUrl(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && detectTech()}
              />
              <button
                className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-xl font-medium transition-colors shadow-lg shadow-blue-500/25 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[180px]"
                onClick={detectTech}
                disabled={loading || !techUrl.trim()}
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    Detecting...
                  </span>
                ) : 'Detect Technologies'}
              </button>
            </div>
          </div>
          
          {technologies.url && (
            <div className="bg-black/30 border border-white/10 rounded-2xl p-6 shadow-xl animate-fade-in">
              <div className="flex justify-between items-center mb-6 border-b border-white/10 pb-4">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                  </svg>
                  Analysis for {technologies.url}
                </h3>
                {technologies.status_code && (
                  <span className={`px-3 py-1 rounded-full text-xs font-bold border ${technologies.status_code < 400 ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}`}>
                    Status: {technologies.status_code}
                  </span>
                )}
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Server Info */}
                <div className="bg-white/5 rounded-xl p-5 border border-white/5">
                  <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-4 border-b border-white/5 pb-2">Server Information</h4>
                  <div className="space-y-3 text-sm">
                    {technologies.server && (
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <span className="text-gray-500">Server</span>
                        <span className="font-medium text-blue-300 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">{technologies.server}</span>
                      </div>
                    )}
                    {technologies['x-powered-by'] && (
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <span className="text-gray-500">Powered By</span>
                        <span className="font-medium text-gray-300">{technologies['x-powered-by']}</span>
                      </div>
                    )}
                    {technologies.content_type && (
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <span className="text-gray-500">Content Type</span>
                        <span className="font-medium text-gray-300">{technologies.content_type}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Stack */}
                <div className="bg-white/5 rounded-xl p-5 border border-white/5 md:row-span-2">
                  <h4 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-4 border-b border-white/5 pb-2">Technology Stack</h4>
                  <div className="space-y-5">
                    {[
                      { key: 'cms', title: 'CMS', color: 'text-pink-400', bg: 'bg-pink-500/10', border: 'border-pink-500/20' },
                      { key: 'javascript_frameworks', title: 'JavaScript', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
                      { key: 'web_servers', title: 'Web Server', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
                      { key: 'languages', title: 'Languages', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20' },
                      { key: 'css_frameworks', title: 'CSS', color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' }
                    ].map(({ key, title, color, bg, border }) => {
                      const items = technologies[key] || [];
                      if (items.length === 0) return null;
                      return (
                        <div key={key}>
                          <h5 className="text-xs font-semibold text-gray-400 mb-2">{title}</h5>
                          <div className="flex flex-wrap gap-2">
                            {items.map((item: string, i: number) => (
                              <span key={i} className={`text-xs px-2.5 py-1 ${bg} ${color} ${border} border rounded-md font-medium`}>
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                    
                    {!Object.values(technologies).some(v => Array.isArray(v) && v.length > 0) && (
                      <div className="text-center py-6 text-gray-500">
                        <p>No technologies detected.</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
export default AdvancedTools;

import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';

const API_URL = 'https://albus-recon-intern-project.onrender.com/api';

// API response types
export interface SubdomainResult {
  subdomains: string[];
}

export interface PortScanResult {
  host: string;
  port: number;
  protocol: string;
  state: string;
  service: string;
  version?: string;
}

export interface TechnologyInfo {
  content_type: string;
  server: string;
  status_code: number;
  url: string;
  'x-powered-by'?: string;
  cms?: string[];
  javascript_frameworks?: string[];
  css_frameworks?: string[];
  analytics?: string[];
  languages?: string[];
  web_servers?: string[];
  operating_systems?: string[];
}

export interface ReconResult {
  id: number;
  url: string;
  status_code: number;
  title: string;
  fetched_at: string;
  error?: string;
  details?: string;
  type?: string;
  recommendation?: string;
}

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  withCredentials: true,
  timeout: 30000, // 30 seconds timeout
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`Request: ${config.method?.toUpperCase()} ${config.url}`, config.params || '');
    return config;
  },
  (error) => {
    console.error('Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log('Response:', response.status, response.config.url);
    return response;
  },
  (error) => {
    if (error.response) {
      // The request was made and the server responded with a status code
      console.error('Response Error:', error.response.status, error.response.data);
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No Response:', error.request);
    } else {
      // Something happened in setting up the request
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

export const reconApi = {
  // Submit a URL for scanning
  scanUrl: async (url: string): Promise<ReconResult> => {
    const response = await api.post('/recon', { url });
    return response.data;
  },

  // Get all scan results
  getResults: async (): Promise<ReconResult[]> => {
    const response = await api.get<ReconResult[]>('/recon');
    return response.data;
  },

  // Find subdomains
  findSubdomains: async (domain: string): Promise<string[]> => {
    try {
      const response = await api.get<{ subdomains: string[] }>(`/tools/subdomains?domain=${encodeURIComponent(domain)}`);
      return response.data.subdomains || [];
    } catch (error) {
      console.error('Error fetching subdomains:', error);
      return [];
    }
  },

  // Detect technologies
  detectTech: async (url: string): Promise<Record<string, any>> => {
    try {
      const response = await api.get(`/tech-detect?url=${encodeURIComponent(url)}`);
      // Transform the response to match the expected format
      const data = response.data;
      return {
        content_type: data.content_type || '',
        server: data.server || '',
        status_code: data.status_code || 0,
        url: data.url || url,
        'x-powered-by': data.x_powered_by || '',
        cms: data.detected_technologies?.cms || [],
        javascript_frameworks: data.detected_technologies?.javascript_frameworks || [],
        css_frameworks: data.detected_technologies?.css_frameworks || [],
        analytics: data.detected_technologies?.analytics || [],
        languages: data.detected_technologies?.languages || [],
        web_servers: data.detected_technologies?.web_servers || []
      };
    } catch (error) {
      console.error('Error detecting technologies:', error);
      // Return empty result structure on error
      return {
        content_type: '',
        server: '',
        status_code: 0,
        url,
        'x-powered-by': '',
        cms: [],
        javascript_frameworks: [],
        css_frameworks: [],
        analytics: [],
        languages: [],
        web_servers: []
      };
    }
  },

  // Scan ports on a target
  scanPorts: async (target: string): Promise<PortScanResult[]> => {
    try {
      const response = await api.post<{
        target: string;
        scan_type: string;
        results: Array<{
          port: number;
          status: string;
          service: string;
          banner?: string;
        }>;
      }>('/tools/port-scan', { 
        target,
        scan_type: 'tcp' 
      });
      
      // Transform the response to match PortScanResult interface
      return (response.data.results || []).map(result => ({
        host: response.data.target,
        port: result.port,
        protocol: 'tcp',
        state: result.status,
        service: result.service,
        version: result.banner || ''
      }));
    } catch (error) {
      console.error('Error scanning ports:', error);
      return [];
    }
  },

  // Export to CSV
  exportToCsv: async (): Promise<Blob> => {
    const response = await api.get('/export/csv', { 
      responseType: 'blob',
      headers: {
        'Accept': 'text/csv',
      }
    });
    return response.data;
  },
};

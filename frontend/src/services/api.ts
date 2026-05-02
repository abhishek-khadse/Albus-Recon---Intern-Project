import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_BASE = `${API_URL}/api`;

console.log('Using API base URL:', API_BASE);

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

export interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  role: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

// Create axios instance
const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  timeout: 30000, // 30 seconds timeout
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
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
      if (error.response.status === 401) {
        // Handle unauthorized access globally
        if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
          localStorage.removeItem('token');
          window.location.href = '/login';
        }
      }
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
  }
};

export const authApi = {
  login: async (credentials: any): Promise<LoginResponse> => {
    const formData = new FormData();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);
    
    // FastAPI OAuth2PasswordRequestForm expects form data, not JSON
    const response = await api.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  
  register: async (userData: any): Promise<User> => {
    const response = await api.post('/auth/register', userData);
    return response.data;
  },
  
  getMe: async (token: string): Promise<User> => {
    const response = await api.get('/auth/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  }
};

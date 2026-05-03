// --- SECURITY UTILITIES ---

// Rate limiting for client-side requests
export class RateLimiter {
  constructor(maxRequests = 10, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
  }

  canMakeRequest() {
    const now = Date.now();
    // Remove old requests outside the window
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    
    if (this.requests.length >= this.maxRequests) {
      return false;
    }
    
    this.requests.push(now);
    return true;
  }

  getRemainingRequests() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    return Math.max(0, this.maxRequests - this.requests.length);
  }

  getResetTime() {
    if (this.requests.length === 0) return 0;
    const oldestRequest = Math.min(...this.requests);
    return oldestRequest + this.windowMs;
  }
}

// Input sanitization utilities
export const sanitizeInput = {
  // Basic HTML sanitization
  html: (input) => {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  },

  // Remove script tags and dangerous attributes
  removeScripts: (input) => {
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+="[^"]*"/gi, '')
      .replace(/javascript:/gi, '');
  },

  // Sanitize for URLs
  url: (input) => {
    try {
      const url = new URL(input);
      // Only allow http, https protocols
      if (!['http:', 'https:'].includes(url.protocol)) {
        return '#';
      }
      return url.toString();
    } catch {
      return '#';
    }
  },

  // Sanitize email addresses
  email: (input) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(input) ? input.toLowerCase() : '';
  }
};

// XSS Protection utilities
export const xssProtection = {
  // Set CSP headers (for server-side)
  getCSPHeaders: () => ({
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  }),

  // Validate and sanitize user-generated content
  validateContent: (content) => {
    const dangerousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe\b[^>]*>/gi,
      /<object\b[^>]*>/gi,
      /<embed\b[^>]*>/gi
    ];

    return !dangerousPatterns.some(pattern => pattern.test(content));
  }
};

// Session security utilities
export const sessionSecurity = {
  // Check if session is valid
  isValidSession: (sessionData) => {
    if (!sessionData || !sessionData.token || !sessionData.expiresAt) {
      return false;
    }

    const now = Date.now();
    const expiresAt = new Date(sessionData.expiresAt).getTime();
    
    return now < expiresAt;
  },

  // Get session time remaining
  getTimeRemaining: (sessionData) => {
    if (!sessionData || !sessionData.expiresAt) {
      return 0;
    }

    const now = Date.now();
    const expiresAt = new Date(sessionData.expiresAt).getTime();
    
    return Math.max(0, expiresAt - now);
  },

  // Check if session should be refreshed
  shouldRefresh: (sessionData, refreshThreshold = 5 * 60 * 1000) => {
    const timeRemaining = sessionSecurity.getTimeRemaining(sessionData);
    return timeRemaining <= refreshThreshold;
  }
};

// Crypto utilities for client-side operations
export const cryptoUtils = {
  // Generate random string
  generateRandomString: (length = 32) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  },

  // Generate UUID v4
  generateUUID: () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  },

  // Simple hash function (for non-security critical uses)
  simpleHash: (str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }
};

// Security monitoring utilities
export const securityMonitor = {
  // Detect suspicious activity patterns
  detectSuspiciousActivity: (events) => {
    const suspiciousPatterns = [
      // Multiple failed login attempts
      {
        name: 'multiple_failed_logins',
        check: (events) => {
          const failedLogins = events.filter(e => e.type === 'login_failed');
          return failedLogins.length >= 5;
        }
      },
      // Rapid API calls
      {
        name: 'rapid_api_calls',
        check: (events) => {
          const apiCalls = events.filter(e => e.type === 'api_call');
          const recentCalls = apiCalls.filter(e => Date.now() - e.timestamp < 60000);
          return recentCalls.length >= 100;
        }
      }
    ];

    return suspiciousPatterns.map(pattern => ({
      type: pattern.name,
      detected: pattern.check(events)
    }));
  },

  // Log security events
  logEvent: (type, details = {}) => {
    const event = {
      type,
      timestamp: Date.now(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      ...details
    };

    // Store in sessionStorage for debugging
    const existingEvents = JSON.parse(sessionStorage.getItem('security_events') || '[]');
    existingEvents.push(event);
    
    // Keep only last 100 events
    const trimmedEvents = existingEvents.slice(-100);
    sessionStorage.setItem('security_events', JSON.stringify(trimmedEvents));

    // In production, send to security monitoring service
    if (import.meta.env.PROD) {
      // sendToSecurityService(event);
    }
  }
};

// Create global rate limiter instance
export const globalRateLimiter = new RateLimiter(50, 60000); // 50 requests per minute

export default {
  RateLimiter,
  sanitizeInput,
  xssProtection,
  sessionSecurity,
  cryptoUtils,
  securityMonitor,
  globalRateLimiter
};

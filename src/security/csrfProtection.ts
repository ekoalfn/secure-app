// Enhanced CSRF Protection Module
import React from 'react';

// CSRF Token storage and helper functions
interface CSRFState {
  token: string;
  timestamp: number;
  rotationInterval: number; // in milliseconds
  lastRotated: number;
  tokenHistory: {
    token: string;
    created: number;
  }[];
  originAllowlist: string[];
  rotationEnabled: boolean;
}

class CSRFProtection {
  private state: CSRFState;
  private static instance: CSRFProtection;
  private tokenKey: string = 'XSRF-TOKEN';
  private headerName: string = 'X-XSRF-TOKEN';
  private stateChangeCallbacks: Function[] = [];

  // Private constructor for singleton pattern
  private constructor() {
    // Initial CSRF state
    this.state = {
      token: this.generateToken(),
      timestamp: Date.now(),
      rotationInterval: 15 * 60 * 1000, // 15 minutes
      lastRotated: Date.now(),
      tokenHistory: [],
      originAllowlist: [window.location.origin, 'https://localhost:5001'],
      rotationEnabled: true
    };

    // Keep history of tokens (for a short time) to allow for in-flight requests
    this.state.tokenHistory.push({
      token: this.state.token,
      created: this.state.timestamp
    });

    // Set up automatic token rotation
    if (this.state.rotationEnabled) {
      this.setupTokenRotation();
    }

    // Initialize by setting token in cookie
    this.setTokenCookie();
  }

  // Singleton accessor
  public static getInstance(): CSRFProtection {
    if (!CSRFProtection.instance) {
      CSRFProtection.instance = new CSRFProtection();
    }
    return CSRFProtection.instance;
  }

  // Generate a cryptographically strong random token
  private generateToken(): string {
    // Create a secure random token
    const buffer = new Uint8Array(32);
    if (typeof window.crypto !== 'undefined' && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(buffer);
    } else {
      // Fallback for older browsers (less secure)
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = Math.floor(Math.random() * 256);
      }
    }
    
    // Convert to base64 and make URL safe
    // Use Array.from to properly convert Uint8Array for older TypeScript targets
    return btoa(String.fromCharCode.apply(null, Array.from(buffer)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  // Set up token rotation
  private setupTokenRotation(): void {
    setInterval(() => {
      if (Date.now() - this.state.lastRotated >= this.state.rotationInterval) {
        this.rotateToken();
      }
    }, 60 * 1000); // Check every minute
  }

  // Rotate the CSRF token
  public rotateToken(): void {
    const oldToken = this.state.token;
    
    // Generate new token
    const newToken = this.generateToken();
    this.state.token = newToken;
    this.state.lastRotated = Date.now();
    
    // Add to history for validation of in-flight requests
    this.state.tokenHistory.push({
      token: newToken,
      created: Date.now()
    });
    
    // Limit history size (keep last 5 tokens)
    if (this.state.tokenHistory.length > 5) {
      this.state.tokenHistory.shift();
    }
    
    // Update cookie
    this.setTokenCookie();
    
    // Notify subscribers of token change
    this.notifyStateChange();
    
    console.log('CSRF token rotated');
  }

  // Set CSRF token in cookie
  private setTokenCookie(): void {
    document.cookie = `${this.tokenKey}=${this.state.token}; secure; samesite=strict; path=/`;
  }

  // Get current CSRF token
  public getToken(): string {
    // Store token in localStorage for persistence
    localStorage.setItem('csrf_token', this.state.token);
    return this.state.token;
  }

  // Validate a CSRF token against current and recent tokens
  public validateToken(token: string): boolean {
    if (!token) return false;
    
    // Check if it matches current token
    if (token === this.state.token) return true;
    
    // Check against token history for recently rotated tokens
    // This helps prevent issues with in-flight requests during token rotation
    const validHistoryToken = this.state.tokenHistory.some(
      historyItem => historyItem.token === token && 
                     Date.now() - historyItem.created < 30 * 60 * 1000 // 30 minutes
    );
    
    return validHistoryToken;
  }

  // Validate request origin
  public validateOrigin(origin: string): boolean {
    return this.state.originAllowlist.includes(origin);
  }

  // Multi-layer CSRF validation (token + origin)
  public validateRequest(request: {
    token?: string;
    origin?: string;
    body?: any;
  }): { valid: boolean; reason?: string } {
    // Check for token in request
    if (!request.token) {
      return { valid: false, reason: 'Missing CSRF token' };
    }
    
    // Validate the token
    if (!this.validateToken(request.token)) {
      return { valid: false, reason: 'Invalid CSRF token' };
    }
    
    // Validate origin if provided
    if (request.origin && !this.validateOrigin(request.origin)) {
      return { valid: false, reason: 'Invalid origin' };
    }
    
    // Check if token in body matches (triple check)
    if (request.body && request.body._csrf && request.body._csrf !== request.token) {
      return { valid: false, reason: 'Token mismatch between header and body' };
    }
    
    return { valid: true };
  }

  // Update CSRF protection configuration
  public updateConfig(config: {
    rotationInterval?: number;
    rotationEnabled?: boolean;
    originAllowlist?: string[];
  }): void {
    if (config.rotationInterval) {
      this.state.rotationInterval = config.rotationInterval;
    }
    
    if (config.originAllowlist) {
      this.state.originAllowlist = config.originAllowlist;
    }
    
    if (typeof config.rotationEnabled !== 'undefined') {
      this.state.rotationEnabled = config.rotationEnabled;
    }
    
    this.notifyStateChange();
  }

  // Subscribe to state changes
  public subscribe(callback: Function): () => void {
    this.stateChangeCallbacks.push(callback);
    return () => {
      this.stateChangeCallbacks = this.stateChangeCallbacks.filter(cb => cb !== callback);
    };
  }

  // Notify subscribers of state change
  private notifyStateChange(): void {
    this.stateChangeCallbacks.forEach(callback => {
      try {
        callback(this.getState());
      } catch (e) {
        console.error('Error in CSRF state change callback:', e);
      }
    });
  }

  // Get current state (for debugging, excluding token)
  public getState(): Omit<CSRFState, 'token' | 'tokenHistory'> {
    const { token, tokenHistory, ...rest } = this.state;
    return rest;
  }

  // Configure axios interceptors for CSRF protection
  public setupAxiosInterceptors(axios: any): void {
    // Request interceptor to add CSRF token to headers
    axios.interceptors.request.use((config: any) => {
      // Add CSRF token to all state-changing requests
      if (['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase())) {
        const token = this.getToken();
        config.headers['X-CSRF-Token'] = token;
        
        // Add token to request body for additional validation
        if (config.data && typeof config.data === 'object') {
          config.data._csrf = token;
        } else if (config.data && typeof config.data === 'string') {
          try {
            const data = JSON.parse(config.data);
            data._csrf = token;
            config.data = JSON.stringify(data);
          } catch (e) {
            // Not JSON, don't modify
          }
        }
      }
      
      return config;
    });

    // Response interceptor to handle CSRF errors
    axios.interceptors.response.use(
      (response: any) => response,
      (error: any) => {
        // Check if error is CSRF related
        if (error.response?.status === 403 && 
            error.response?.data?.reason?.includes('CSRF')) {
          console.error('CSRF validation failed:', error.response.data.reason);
          
          // Force token rotation on CSRF failure
          this.rotateToken();
        }
        return Promise.reject(error);
      }
    );
  }
}

// Export singleton instance
export const csrfProtection = CSRFProtection.getInstance();

// React hook for CSRF protection
export const useCSRFToken = () => {
  const getCSRFToken = () => csrfProtection.getToken();
  
  // Get token from cookie (fallback)
  const getTokenFromCookie = (): string => {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith('XSRF-TOKEN='))
      ?.split('=')[1] || '';
  };
  
  return {
    getCSRFToken,
    getTokenFromCookie,
    rotateToken: () => csrfProtection.rotateToken()
  };
};

// Form protection hook with React component
export const useCSRFProtectedForm = () => {
  const { getCSRFToken } = useCSRFToken();
  const token = getCSRFToken();
  
  const CSRFField = React.createElement('input', {
    type: 'hidden',
    name: '_csrf',
    value: token
  });
  
  return {
    csrfToken: token,
    CSRFField
  };
}; 
import { setupTrustedTypes, sanitizers } from './trustedTypes';
import { xssAuditor, scanDOMForXSS } from './xssAuditor';
import { csrfProtection } from './csrfProtection';
import { securityMonitor, securityEvents } from './securityMonitoring';
import { securityHeaders } from './securityHeaders';
import axios from 'axios';
import DOMPurify from 'dompurify';

// Define TrustedTypes interface
declare global {
  interface Window {
    trustedTypes?: {
      createPolicy: (policyName: string, policyOptions: any) => any;
      getPolicy?: (policyName: string) => {
        createHTML: (input: string) => any;
      };
    };
  }
}

// Integration between security modules
const setupSecurityIntegration = () => {
  // Link XSS auditor to security monitoring by using separate event handler
  xssAuditor.onAlert = (event: { payload: string; element?: string }) => {
    // Log to security monitor
    securityEvents.logXssAttempt(event.payload, event.element);
  };
  
  // Set up reporting endpoint for security events
  securityMonitor.setReportingEndpoint('/api/security-events');
  
  // Link CSRF protection to axios
  csrfProtection.setupAxiosInterceptors(axios);
};

// Initialize all security features
export const initializeSecurity = () => {
  console.log('Initializing comprehensive security features...');
  
  // Initialize Trusted Types
  setupTrustedTypes();
  
  // Initialize XSS Auditor
  xssAuditor.init({
    enabled: true,
    reportEndpoint: '/api/xss-report'
  });
  
  // Scan DOM for existing XSS
  scanDOMForXSS();
  
  // Apply security headers
  securityHeaders.applyHeaders();
  
  // Set up integration between security modules
  setupSecurityIntegration();
  
  // Register security event handlers
  securityMonitor.onAlert((event) => {
    console.warn('SECURITY ALERT:', event);
    
    // Optional: Display security notification to user for critical events
    if (event.severity === 'critical') {
      // Show notification
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Security Alert', {
          body: 'A security issue has been detected. Please contact support if you notice unusual behavior.',
          icon: '/security-icon.png'
        });
      }
    }
  });
  
  console.log('Security features initialized successfully');
};

// Security utility functions
export const security = {
  // Token utilities
  csrf: {
    getToken: () => csrfProtection.getToken(),
    rotateToken: () => csrfProtection.rotateToken()
  },
  
  // Nonce utilities
  nonce: {
    get: (type: 'script' | 'style') => securityHeaders.getNonce(type)
  },
  
  // Sanitization utilities
  sanitize: {
    html: (content: string) => {
      if (window.trustedTypes && typeof window.trustedTypes.getPolicy === 'function') {
        try {
          const policy = window.trustedTypes.getPolicy('dompurify');
          return policy.createHTML(content) as unknown as string;
        } catch (e) {
          return DOMPurify.sanitize(content);
        }
      }
      return DOMPurify.sanitize(content);
    },
    url: sanitizers.urlSanitizer
  },
  
  // Security monitoring
  monitor: {
    logEvent: securityMonitor.logEvent.bind(securityMonitor)
  }
};

// Export individual security modules for direct access
export { xssAuditor } from './xssAuditor';
export { csrfProtection } from './csrfProtection';
export { securityMonitor } from './securityMonitoring';
export { securityHeaders } from './securityHeaders';
export { createSanitizedContent } from './trustedTypes';

// Export React hooks
export { useXSSDetection } from './xssAuditor';
export { useCSRFToken, useCSRFProtectedForm } from './csrfProtection';
export { useSecurityMonitoring } from './securityMonitoring';
export { useSecurityNonce } from './securityHeaders'; 
import DOMPurify from 'dompurify';

// Define TrustedTypes interface more clearly
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

// Setup Trusted Types policy
export const setupTrustedTypes = () => {
  if (window.trustedTypes && typeof window.trustedTypes.createPolicy === 'function') {
    try {
      // Create a policy for DOMPurify sanitized HTML
      window.trustedTypes.createPolicy('dompurify', {
        createHTML: (string: string) => DOMPurify.sanitize(string, {
          RETURN_TRUSTED_TYPE: true
        })
      });

      // Policy for script URLs
      window.trustedTypes.createPolicy('script-url', {
        createScriptURL: (url: string) => {
          // Only allow specific origins
          const allowedOrigins = [
            window.location.origin,
            'https://localhost:5001'
          ];
          
          try {
            const parsedUrl = new URL(url, window.location.origin);
            if (allowedOrigins.includes(parsedUrl.origin)) {
              return url;
            }
          } catch (e) {
            console.error('Invalid URL in script-url policy:', e);
          }
          
          throw new Error(`URL ${url} violates script-url policy`);
        }
      });

      console.log('Trusted Types policies have been initialized');
    } catch (e) {
      console.error('Error initializing Trusted Types policies:', e);
    }
  } else {
    console.warn('Trusted Types not supported in this browser');
  }
};

// Context-specific sanitizers that leverage Trusted Types
export const sanitizers = {
  // HTML sanitization
  htmlSanitizer: (html: string): string => {
    try {
      if (window.trustedTypes && typeof window.trustedTypes.getPolicy === 'function') {
        const policy = window.trustedTypes.getPolicy('dompurify');
        if (policy && typeof policy.createHTML === 'function') {
          return policy.createHTML(html) as unknown as string;
        }
      }
      return DOMPurify.sanitize(html);
    } catch (e) {
      console.warn('Error in htmlSanitizer, falling back to regular DOMPurify:', e);
      return DOMPurify.sanitize(html);
    }
  },
  
  // URL sanitization
  urlSanitizer: (url: string): string => {
    // Simple URL validation
    if (!url) return '';
    
    try {
      const parsedUrl = new URL(url, window.location.origin);
      // Allow only http and https protocols
      if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
        return url;
      }
      return '';
    } catch {
      return '';
    }
  },
  
  // JS sanitization for inline script content
  scriptSanitizer: (script: string): string => {
    // Very restrictive - typically you'd want to avoid inline JS entirely
    return DOMPurify.sanitize(script, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: []
    });
  },
  
  // CSS sanitization
  cssSanitizer: (css: string): string => {
    // Simple CSS sanitization to prevent CSS-based attacks
    return DOMPurify.sanitize(css, {
      ALLOWED_TAGS: ['style'],
      ALLOWED_ATTR: ['type']
    });
  }
};

// Custom React hook for sanitization
export const createSanitizedContent = (content: string, type: 'html' | 'url' | 'script' | 'css' = 'html') => {
  switch (type) {
    case 'html':
      return { __html: sanitizers.htmlSanitizer(content) };
    case 'url':
      return sanitizers.urlSanitizer(content);
    case 'script':
      return sanitizers.scriptSanitizer(content);
    case 'css':
      return sanitizers.cssSanitizer(content);
    default:
      return { __html: sanitizers.htmlSanitizer(content) };
  }
}; 
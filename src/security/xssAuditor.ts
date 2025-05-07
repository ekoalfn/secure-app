// Client-side XSS Auditor

// Suspicious patterns for detecting XSS attempts
const suspiciousPatterns = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=\s*["']?[^"']*["']?/gi,
  /data\s*:\s*text\/html/gi,
  /expression\s*\([^)]*\)/gi,
  /url\s*\([^)]*script:/gi
];

// Store for detected XSS attempts
interface XSSAttempt {
  timestamp: Date;
  payload: string;
  element?: string;
  severity: 'low' | 'medium' | 'high';
  action: 'blocked' | 'logged';
}

// XSS Alert callback type
type XSSAlertCallback = (event: { payload: string; element?: string; severity?: 'low' | 'medium' | 'high' }) => void;

class XSSAuditor {
  private attempts: XSSAttempt[] = [];
  private enabled: boolean = true;
  private reportEndpoint: string | null = null;
  private mutationObserver: MutationObserver | null = null;
  public onAlert: XSSAlertCallback | null = null;

  constructor() {
    this.setupMutationObserver();
  }

  // Initialize the XSS auditor
  public init(options: { 
    enabled?: boolean; 
    reportEndpoint?: string;
  } = {}) {
    this.enabled = options.enabled ?? true;
    this.reportEndpoint = options.reportEndpoint ?? null;
    
    if (this.enabled) {
      this.patchDOMFunctions();
      this.startMutationObserver();
      console.log('XSS Auditor initialized');
    }
  }

  // Enable or disable the auditor
  public setEnabled(enabled: boolean) {
    this.enabled = enabled;
    if (enabled && !this.mutationObserver) {
      this.startMutationObserver();
    } else if (!enabled && this.mutationObserver) {
      this.stopMutationObserver();
    }
  }

  // Check for XSS patterns in a string
  public checkForXSS(content: string): boolean {
    if (!this.enabled || !content) return false;
    
    return suspiciousPatterns.some(pattern => pattern.test(content));
  }

  // Record an XSS attempt
  public recordAttempt(payload: string, element?: string, severity: 'low' | 'medium' | 'high' = 'medium'): void {
    const attempt: XSSAttempt = {
      timestamp: new Date(),
      payload,
      element,
      severity,
      action: 'logged'
    };
    
    this.attempts.push(attempt);
    console.warn('Potential XSS attempt detected:', attempt);
    
    // Trigger alert callback if set
    if (this.onAlert) {
      try {
        this.onAlert({ 
          payload, 
          element, 
          severity 
        });
      } catch (e) {
        console.error('Error in XSS alert callback:', e);
      }
    }
    
    // Send to reporting endpoint if configured
    if (this.reportEndpoint) {
      this.reportXSSAttempt(attempt);
    }
  }

  // Get all recorded XSS attempts
  public getAttempts(): XSSAttempt[] {
    return [...this.attempts];
  }

  // Clear recorded attempts
  public clearAttempts(): void {
    this.attempts = [];
  }

  // Set up the MutationObserver to detect DOM changes
  private setupMutationObserver(): void {
    if (typeof MutationObserver !== 'undefined') {
      this.mutationObserver = new MutationObserver(mutations => {
        for (const mutation of mutations) {
          if (mutation.type === 'childList') {
            mutation.addedNodes.forEach(node => {
              if (node.nodeType === Node.ELEMENT_NODE) {
                this.scanElement(node as Element);
              } else if (node.nodeType === Node.TEXT_NODE && node.textContent) {
                if (this.checkForXSS(node.textContent)) {
                  this.recordAttempt(node.textContent, 'text-node');
                }
              }
            });
          } else if (mutation.type === 'attributes') {
            const element = mutation.target as Element;
            const attrName = mutation.attributeName as string;
            const attrValue = element.getAttribute(attrName);
            
            if (attrValue && this.checkForXSS(attrValue)) {
              this.recordAttempt(attrValue, `${element.tagName}[${attrName}]`);
            }
          }
        }
      });
    }
  }

  // Start observing DOM mutations
  private startMutationObserver(): void {
    if (this.mutationObserver && document.body) {
      this.mutationObserver.observe(document.body, {
        childList: true,
        attributes: true,
        characterData: true,
        subtree: true,
        attributeOldValue: true,
        characterDataOldValue: true
      });
    }
  }

  // Stop observing DOM mutations
  private stopMutationObserver(): void {
    if (this.mutationObserver) {
      this.mutationObserver.disconnect();
    }
  }

  // Scan an element for potential XSS
  public scanElement(element: Element): void {
    // Check attributes
    for (let i = 0; i < element.attributes.length; i++) {
      const attr = element.attributes[i];
      if (this.checkForXSS(attr.value)) {
        this.recordAttempt(attr.value, `${element.tagName}[${attr.name}]`);
      }
    }
    
    // Check for inline event handlers
    const tagName = element.tagName.toLowerCase();
    if (tagName === 'script' && element.textContent) {
      if (this.checkForXSS(element.textContent)) {
        this.recordAttempt(element.textContent, 'script', 'high');
      }
    }
    
    // Check children recursively
    element.childNodes.forEach(child => {
      if (child.nodeType === Node.ELEMENT_NODE) {
        this.scanElement(child as Element);
      }
    });
  }

  // Patch DOM methods to monitor for XSS attempts
  private patchDOMFunctions(): void {
    // Patch Element.innerHTML setter
    const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
      const self = this;
      const originalSet = originalInnerHTMLDescriptor.set;
      
      Object.defineProperty(Element.prototype, 'innerHTML', {
        set(value: string) {
          if (self.checkForXSS(value)) {
            self.recordAttempt(value, `${this.tagName}.innerHTML`, 'high');
          }
          originalSet.call(this, value);
          return value;
        },
        get: originalInnerHTMLDescriptor.get,
        configurable: true
      });
    }

    // Patch document.write
    const originalWrite = document.write;
    const self = this;
    document.write = function(...args: string[]) {
      const content = args.join('');
      if (self.checkForXSS(content)) {
        self.recordAttempt(content, 'document.write', 'high');
      }
      return originalWrite.apply(this, args);
    };
  }

  // Report XSS attempt to a configured endpoint
  private reportXSSAttempt(attempt: XSSAttempt): void {
    if (!this.reportEndpoint) return;
    
    try {
      const data = JSON.stringify({
        type: 'xss-attempt',
        timestamp: attempt.timestamp.toISOString(),
        payload: attempt.payload.substring(0, 500), // Limit payload size
        element: attempt.element,
        severity: attempt.severity,
        url: window.location.href,
        userAgent: navigator.userAgent
      });
      
      // Use beacon API for reliable delivery even during page unload
      if (navigator.sendBeacon) {
        navigator.sendBeacon(this.reportEndpoint, data);
      } else {
        // Fallback to fetch API
        fetch(this.reportEndpoint, {
          method: 'POST',
          body: data,
          headers: {
            'Content-Type': 'application/json'
          },
          keepalive: true
        }).catch(e => console.error('XSS report sending failed:', e));
      }
    } catch (e) {
      console.error('Error reporting XSS attempt:', e);
    }
  }
}

// Export singleton instance
export const xssAuditor = new XSSAuditor();

// Helper function to scan existing DOM
export const scanDOMForXSS = (): void => {
  if (document.body) {
    xssAuditor.scanElement(document.body);
  }
};

// Create React hook for XSS detection in user inputs
export const useXSSDetection = (initialValue: string = '') => {
  let isXSS = false;
  
  const checkValue = (value: string) => {
    isXSS = xssAuditor.checkForXSS(value);
    if (isXSS) {
      xssAuditor.recordAttempt(value, 'user-input');
    }
    return isXSS;
  };
  
  // Initial check
  checkValue(initialValue);
  
  return {
    isXSS,
    checkValue
  };
}; 
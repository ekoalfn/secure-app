"use strict";
// Client-side XSS Auditor
Object.defineProperty(exports, "__esModule", { value: true });
exports.useXSSDetection = exports.scanDOMForXSS = exports.xssAuditor = void 0;
// Suspicious patterns for detecting XSS attempts
const suspiciousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript\s*:/gi,
    /on\w+\s*=\s*["']?[^"']*["']?/gi,
    /data\s*:\s*text\/html/gi,
    /expression\s*\([^)]*\)/gi,
    /url\s*\([^)]*script:/gi
];
class XSSAuditor {
    constructor() {
        this.attempts = [];
        this.enabled = true;
        this.reportEndpoint = null;
        this.mutationObserver = null;
        this.onAlert = null;
        this.setupMutationObserver();
    }
    // Initialize the XSS auditor
    init(options = {}) {
        var _a, _b;
        this.enabled = (_a = options.enabled) !== null && _a !== void 0 ? _a : true;
        this.reportEndpoint = (_b = options.reportEndpoint) !== null && _b !== void 0 ? _b : null;
        if (this.enabled) {
            this.patchDOMFunctions();
            this.startMutationObserver();
            console.log('XSS Auditor initialized');
        }
    }
    // Enable or disable the auditor
    setEnabled(enabled) {
        this.enabled = enabled;
        if (enabled && !this.mutationObserver) {
            this.startMutationObserver();
        }
        else if (!enabled && this.mutationObserver) {
            this.stopMutationObserver();
        }
    }
    // Check for XSS patterns in a string
    checkForXSS(content) {
        if (!this.enabled || !content)
            return false;
        return suspiciousPatterns.some(pattern => pattern.test(content));
    }
    // Record an XSS attempt
    recordAttempt(payload, element, severity = 'medium') {
        const attempt = {
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
            }
            catch (e) {
                console.error('Error in XSS alert callback:', e);
            }
        }
        // Send to reporting endpoint if configured
        if (this.reportEndpoint) {
            this.reportXSSAttempt(attempt);
        }
    }
    // Get all recorded XSS attempts
    getAttempts() {
        return [...this.attempts];
    }
    // Clear recorded attempts
    clearAttempts() {
        this.attempts = [];
    }
    // Set up the MutationObserver to detect DOM changes
    setupMutationObserver() {
        if (typeof MutationObserver !== 'undefined') {
            this.mutationObserver = new MutationObserver(mutations => {
                for (const mutation of mutations) {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(node => {
                            if (node.nodeType === Node.ELEMENT_NODE) {
                                this.scanElement(node);
                            }
                            else if (node.nodeType === Node.TEXT_NODE && node.textContent) {
                                if (this.checkForXSS(node.textContent)) {
                                    this.recordAttempt(node.textContent, 'text-node');
                                }
                            }
                        });
                    }
                    else if (mutation.type === 'attributes') {
                        const element = mutation.target;
                        const attrName = mutation.attributeName;
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
    startMutationObserver() {
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
    stopMutationObserver() {
        if (this.mutationObserver) {
            this.mutationObserver.disconnect();
        }
    }
    // Scan an element for potential XSS
    scanElement(element) {
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
                this.scanElement(child);
            }
        });
    }
    // Patch DOM methods to monitor for XSS attempts
    patchDOMFunctions() {
        // Patch Element.innerHTML setter
        const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
            const self = this;
            const originalSet = originalInnerHTMLDescriptor.set;
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set(value) {
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
        document.write = function (...args) {
            const content = args.join('');
            if (self.checkForXSS(content)) {
                self.recordAttempt(content, 'document.write', 'high');
            }
            return originalWrite.apply(this, args);
        };
    }
    // Report XSS attempt to a configured endpoint
    reportXSSAttempt(attempt) {
        if (!this.reportEndpoint)
            return;
        try {
            const data = JSON.stringify({
                type: 'xss-attempt',
                timestamp: attempt.timestamp.toISOString(),
                payload: attempt.payload.substring(0, 500),
                element: attempt.element,
                severity: attempt.severity,
                url: window.location.href,
                userAgent: navigator.userAgent
            });
            // Use beacon API for reliable delivery even during page unload
            if (navigator.sendBeacon) {
                navigator.sendBeacon(this.reportEndpoint, data);
            }
            else {
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
        }
        catch (e) {
            console.error('Error reporting XSS attempt:', e);
        }
    }
}
// Export singleton instance
exports.xssAuditor = new XSSAuditor();
// Helper function to scan existing DOM
const scanDOMForXSS = () => {
    if (document.body) {
        exports.xssAuditor.scanElement(document.body);
    }
};
exports.scanDOMForXSS = scanDOMForXSS;
// Create React hook for XSS detection in user inputs
const useXSSDetection = (initialValue = '') => {
    let isXSS = false;
    const checkValue = (value) => {
        isXSS = exports.xssAuditor.checkForXSS(value);
        if (isXSS) {
            exports.xssAuditor.recordAttempt(value, 'user-input');
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
exports.useXSSDetection = useXSSDetection;

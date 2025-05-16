"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSecurityNonce = exports.useSecurityMonitoring = exports.useCSRFProtectedForm = exports.useCSRFToken = exports.useXSSDetection = exports.createSanitizedContent = exports.securityHeaders = exports.securityMonitor = exports.csrfProtection = exports.xssAuditor = exports.security = exports.initializeSecurity = void 0;
const trustedTypes_1 = require("./trustedTypes");
const xssAuditor_1 = require("./xssAuditor");
const csrfProtection_1 = require("./csrfProtection");
const securityMonitoring_1 = require("./securityMonitoring");
const securityHeaders_1 = require("./securityHeaders");
const axios_1 = __importDefault(require("axios"));
const dompurify_1 = __importDefault(require("dompurify"));
// Integration between security modules
const setupSecurityIntegration = () => {
    // Link XSS auditor to security monitoring by using separate event handler
    xssAuditor_1.xssAuditor.onAlert = (event) => {
        // Log to security monitor
        securityMonitoring_1.securityEvents.logXssAttempt(event.payload, event.element);
    };
    // Set up reporting endpoint for security events
    securityMonitoring_1.securityMonitor.setReportingEndpoint('/api/security-events');
    // Link CSRF protection to axios
    csrfProtection_1.csrfProtection.setupAxiosInterceptors(axios_1.default);
};
// Initialize all security features
const initializeSecurity = () => {
    console.log('Initializing comprehensive security features...');
    // Initialize Trusted Types
    (0, trustedTypes_1.setupTrustedTypes)();
    // Initialize XSS Auditor
    xssAuditor_1.xssAuditor.init({
        enabled: true,
        reportEndpoint: '/api/xss-report'
    });
    // Scan DOM for existing XSS
    (0, xssAuditor_1.scanDOMForXSS)();
    // Apply security headers
    securityHeaders_1.securityHeaders.applyHeaders();
    // Set up integration between security modules
    setupSecurityIntegration();
    // Register security event handlers
    securityMonitoring_1.securityMonitor.onAlert((event) => {
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
exports.initializeSecurity = initializeSecurity;
// Security utility functions
exports.security = {
    // Token utilities
    csrf: {
        getToken: () => csrfProtection_1.csrfProtection.getToken(),
        rotateToken: () => csrfProtection_1.csrfProtection.rotateToken()
    },
    // Nonce utilities
    nonce: {
        get: (type) => securityHeaders_1.securityHeaders.getNonce(type)
    },
    // Sanitization utilities
    sanitize: {
        html: (content) => {
            if (window.trustedTypes && typeof window.trustedTypes.getPolicy === 'function') {
                try {
                    const policy = window.trustedTypes.getPolicy('dompurify');
                    return policy.createHTML(content);
                }
                catch (e) {
                    return dompurify_1.default.sanitize(content);
                }
            }
            return dompurify_1.default.sanitize(content);
        },
        url: trustedTypes_1.sanitizers.urlSanitizer
    },
    // Security monitoring
    monitor: {
        logEvent: securityMonitoring_1.securityMonitor.logEvent.bind(securityMonitoring_1.securityMonitor)
    }
};
// Export individual security modules for direct access
var xssAuditor_2 = require("./xssAuditor");
Object.defineProperty(exports, "xssAuditor", { enumerable: true, get: function () { return xssAuditor_2.xssAuditor; } });
var csrfProtection_2 = require("./csrfProtection");
Object.defineProperty(exports, "csrfProtection", { enumerable: true, get: function () { return csrfProtection_2.csrfProtection; } });
var securityMonitoring_2 = require("./securityMonitoring");
Object.defineProperty(exports, "securityMonitor", { enumerable: true, get: function () { return securityMonitoring_2.securityMonitor; } });
var securityHeaders_2 = require("./securityHeaders");
Object.defineProperty(exports, "securityHeaders", { enumerable: true, get: function () { return securityHeaders_2.securityHeaders; } });
var trustedTypes_2 = require("./trustedTypes");
Object.defineProperty(exports, "createSanitizedContent", { enumerable: true, get: function () { return trustedTypes_2.createSanitizedContent; } });
// Export React hooks
var xssAuditor_3 = require("./xssAuditor");
Object.defineProperty(exports, "useXSSDetection", { enumerable: true, get: function () { return xssAuditor_3.useXSSDetection; } });
var csrfProtection_3 = require("./csrfProtection");
Object.defineProperty(exports, "useCSRFToken", { enumerable: true, get: function () { return csrfProtection_3.useCSRFToken; } });
Object.defineProperty(exports, "useCSRFProtectedForm", { enumerable: true, get: function () { return csrfProtection_3.useCSRFProtectedForm; } });
var securityMonitoring_3 = require("./securityMonitoring");
Object.defineProperty(exports, "useSecurityMonitoring", { enumerable: true, get: function () { return securityMonitoring_3.useSecurityMonitoring; } });
var securityHeaders_3 = require("./securityHeaders");
Object.defineProperty(exports, "useSecurityNonce", { enumerable: true, get: function () { return securityHeaders_3.useSecurityNonce; } });

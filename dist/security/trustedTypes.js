"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSanitizedContent = exports.sanitizers = exports.setupTrustedTypes = void 0;
const dompurify_1 = __importDefault(require("dompurify"));
// Setup Trusted Types policy
const setupTrustedTypes = () => {
    if (window.trustedTypes && typeof window.trustedTypes.createPolicy === 'function') {
        try {
            // Create a policy for DOMPurify sanitized HTML
            window.trustedTypes.createPolicy('dompurify', {
                createHTML: (string) => dompurify_1.default.sanitize(string, {
                    RETURN_TRUSTED_TYPE: true
                })
            });
            // Policy for script URLs
            window.trustedTypes.createPolicy('script-url', {
                createScriptURL: (url) => {
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
                    }
                    catch (e) {
                        console.error('Invalid URL in script-url policy:', e);
                    }
                    throw new Error(`URL ${url} violates script-url policy`);
                }
            });
            console.log('Trusted Types policies have been initialized');
        }
        catch (e) {
            console.error('Error initializing Trusted Types policies:', e);
        }
    }
    else {
        console.warn('Trusted Types not supported in this browser');
    }
};
exports.setupTrustedTypes = setupTrustedTypes;
// Context-specific sanitizers that leverage Trusted Types
exports.sanitizers = {
    // HTML sanitization
    htmlSanitizer: (html) => {
        try {
            if (window.trustedTypes && typeof window.trustedTypes.getPolicy === 'function') {
                const policy = window.trustedTypes.getPolicy('dompurify');
                if (policy && typeof policy.createHTML === 'function') {
                    return policy.createHTML(html);
                }
            }
            return dompurify_1.default.sanitize(html);
        }
        catch (e) {
            console.warn('Error in htmlSanitizer, falling back to regular DOMPurify:', e);
            return dompurify_1.default.sanitize(html);
        }
    },
    // URL sanitization
    urlSanitizer: (url) => {
        // Simple URL validation
        if (!url)
            return '';
        try {
            const parsedUrl = new URL(url, window.location.origin);
            // Allow only http and https protocols
            if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
                return url;
            }
            return '';
        }
        catch (_a) {
            return '';
        }
    },
    // JS sanitization for inline script content
    scriptSanitizer: (script) => {
        // Very restrictive - typically you'd want to avoid inline JS entirely
        return dompurify_1.default.sanitize(script, {
            ALLOWED_TAGS: [],
            ALLOWED_ATTR: []
        });
    },
    // CSS sanitization
    cssSanitizer: (css) => {
        // Simple CSS sanitization to prevent CSS-based attacks
        return dompurify_1.default.sanitize(css, {
            ALLOWED_TAGS: ['style'],
            ALLOWED_ATTR: ['type']
        });
    }
};
// Custom React hook for sanitization
const createSanitizedContent = (content, type = 'html') => {
    switch (type) {
        case 'html':
            return { __html: exports.sanitizers.htmlSanitizer(content) };
        case 'url':
            return exports.sanitizers.urlSanitizer(content);
        case 'script':
            return exports.sanitizers.scriptSanitizer(content);
        case 'css':
            return exports.sanitizers.cssSanitizer(content);
        default:
            return { __html: exports.sanitizers.htmlSanitizer(content) };
    }
};
exports.createSanitizedContent = createSanitizedContent;

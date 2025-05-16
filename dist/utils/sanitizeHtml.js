"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeHtml = void 0;
/**
 * HTML Sanitizer Utility
 * Uses DOMPurify to sanitize HTML and prevent XSS attacks
 */
const dompurify_1 = __importDefault(require("dompurify"));
/**
 * Sanitizes HTML string to prevent XSS attacks
 * @param html - The input HTML string to sanitize
 * @param options - DOMPurify configuration options
 * @returns Sanitized HTML string
 */
const sanitizeHtml = (html, options = {}) => {
    // Default configuration for DOMPurify
    const defaultOptions = {
        USE_PROFILES: { html: true },
        ALLOWED_TAGS: [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'span', 'strong', 'em', 'b', 'i',
            'ul', 'ol', 'li', 'br', 'a', 'img'
        ],
        ALLOWED_ATTR: [
            'href', 'target', 'rel', 'src', 'alt', 'title', 'class'
        ],
        FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
        ADD_ATTR: ['nonce'],
        ALLOW_DATA_ATTR: false, // Block data-* attributes
    };
    // Merge default options with custom options
    const mergedOptions = { ...defaultOptions, ...options };
    // Apply DOMPurify sanitization
    return dompurify_1.default.sanitize(html || '', mergedOptions);
};
exports.sanitizeHtml = sanitizeHtml;
exports.default = exports.sanitizeHtml;

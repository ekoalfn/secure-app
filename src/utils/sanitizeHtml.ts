/**
 * HTML Sanitizer Utility
 * Uses DOMPurify to sanitize HTML and prevent XSS attacks
 */
import DOMPurify from 'dompurify';

interface SanitizeOptions {
  USE_PROFILES?: { html: boolean };
  ALLOWED_TAGS?: string[];
  ALLOWED_ATTR?: string[];
  FORBID_TAGS?: string[];
  FORBID_ATTR?: string[];
  ADD_ATTR?: string[];
  ALLOW_DATA_ATTR?: boolean;
  [key: string]: any;
}

/**
 * Sanitizes HTML string to prevent XSS attacks
 * @param html - The input HTML string to sanitize
 * @param options - DOMPurify configuration options
 * @returns Sanitized HTML string
 */
export const sanitizeHtml = (html: string, options: SanitizeOptions = {}): string => {
  // Default configuration for DOMPurify
  const defaultOptions: SanitizeOptions = {
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
    ADD_ATTR: ['nonce'], // Allow nonce attribute
    ALLOW_DATA_ATTR: false, // Block data-* attributes
  };

  // Merge default options with custom options
  const mergedOptions = { ...defaultOptions, ...options };

  // Apply DOMPurify sanitization
  return DOMPurify.sanitize(html || '', mergedOptions);
};

export default sanitizeHtml; 
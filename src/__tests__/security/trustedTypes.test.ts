import { sanitizers, createSanitizedContent } from '../../security/trustedTypes';
import DOMPurify from 'dompurify';

// Mock DOMPurify
jest.mock('dompurify', () => ({
  sanitize: jest.fn((content) => `sanitized-${content}`),
}));

// Mock window.trustedTypes
const mockCreatePolicy = jest.fn();
const mockGetPolicy = jest.fn();
Object.defineProperty(window, 'trustedTypes', {
  value: {
    createPolicy: mockCreatePolicy,
    getPolicy: mockGetPolicy,
  },
  writable: true,
});

describe('trustedTypes module', () => {
  describe('sanitizers', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('htmlSanitizer should use DOMPurify.sanitize when trustedTypes not available', () => {
      // Remove trustedTypes temporarily for this test
      const originalTrustedTypes = window.trustedTypes;
      delete (window as any).trustedTypes;
      
      const html = '<script>alert("XSS")</script>';
      sanitizers.htmlSanitizer(html);
      
      expect(DOMPurify.sanitize).toHaveBeenCalledWith(html);
      
      // Restore trustedTypes
      (window as any).trustedTypes = originalTrustedTypes;
    });

    test('urlSanitizer should allow valid URLs', () => {
      const validUrl = 'https://example.com/page';
      const result = sanitizers.urlSanitizer(validUrl);
      expect(result).toBe(validUrl);
    });

    test('urlSanitizer should reject javascript: URLs', () => {
      const maliciousUrl = 'javascript:alert("XSS")';
      const result = sanitizers.urlSanitizer(maliciousUrl);
      expect(result).toBe('');
    });

    test('urlSanitizer should reject data: URLs', () => {
      const maliciousUrl = 'data:text/html,<script>alert("XSS")</script>';
      const result = sanitizers.urlSanitizer(maliciousUrl);
      expect(result).toBe('');
    });
  });

  describe('createSanitizedContent', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      (DOMPurify.sanitize as jest.Mock).mockImplementation((content) => `sanitized-${content}`);
    });

    test('should sanitize HTML content correctly', () => {
      const html = '<script>alert("XSS")</script>';
      const result = createSanitizedContent(html, 'html');
      expect(result).toEqual({ __html: `sanitized-${html}` });
    });

    test('should sanitize URL content correctly', () => {
      const url = 'https://example.com';
      const result = createSanitizedContent(url, 'url');
      // URL sanitizer doesn't use DOMPurify directly, it uses the urlSanitizer function
      expect(result).toBe(url);
    });

    test('should sanitize script content correctly', () => {
      const script = 'console.log("test")';
      createSanitizedContent(script, 'script');
      // Script sanitizer calls DOMPurify with specific options
      expect(DOMPurify.sanitize).toHaveBeenCalledWith(script, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
      });
    });
  });
}); 
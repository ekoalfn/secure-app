import { securityHeaders } from '../../security/securityHeaders';

// Mock document methods
const mockAppendChild = jest.fn();
const mockRemove = jest.fn();
const mockQuerySelector = jest.fn();

// Mock necessary DOM elements and methods
beforeEach(() => {
  // Reset mocks
  jest.clearAllMocks();
  
  // Mock document.head
  Object.defineProperty(document, 'head', {
    value: {
      appendChild: mockAppendChild
    },
    writable: true
  });
  
  // Mock document.querySelector
  document.querySelector = mockQuerySelector;
  
  // Mock meta element
  mockQuerySelector.mockImplementation(() => ({
    remove: mockRemove
  }));
  
  // Mock createElement
  document.createElement = jest.fn().mockImplementation((tag) => {
    if (tag === 'meta') {
      return {
        httpEquiv: '',
        content: ''
      };
    }
    return {};
  });
});

describe('Security Headers Module', () => {
  test('should apply Content-Security-Policy header', () => {
    // Call the method to apply headers
    securityHeaders.applyHeaders();
    
    // Check meta tag creation
    expect(document.createElement).toHaveBeenCalledWith('meta');
    
    // Check that CSP was set
    const createdElements = (document.createElement as jest.Mock).mock.results.map(
      result => result.value
    );
    
    const cspElement = createdElements.find(el => el.httpEquiv === 'Content-Security-Policy');
    expect(cspElement).toBeTruthy();
    expect(cspElement.content).toContain('default-src');
    expect(cspElement.content).toContain('script-src');
    
    // Check that it was appended to document head
    expect(mockAppendChild).toHaveBeenCalled();
  });
  
  test('should generate nonces for scripts and styles', () => {
    // Get nonces
    const scriptNonce = securityHeaders.getNonce('script');
    const styleNonce = securityHeaders.getNonce('style');
    
    // Verify they are valid strings
    expect(typeof scriptNonce).toBe('string');
    expect(scriptNonce.length).toBeGreaterThan(0);
    
    expect(typeof styleNonce).toBe('string');
    expect(styleNonce.length).toBeGreaterThan(0);
    
    // Verify they are different
    expect(scriptNonce).not.toBe(styleNonce);
  });
  
  test('should return consistent nonce for the same type', () => {
    // Get nonce for script twice
    const scriptNonce1 = securityHeaders.getNonce('script');
    const scriptNonce2 = securityHeaders.getNonce('script');
    
    // Should be the same
    expect(scriptNonce1).toBe(scriptNonce2);
  });
  
  test('should allow config updates', () => {
    // Update config with partial configuration
    securityHeaders.updateConfig({
      csp: {
        // We only need to specify what we're changing
        scriptSrc: ["'self'", "https://example.com"]
      } as any // Use type assertion to bypass the type checking
    });
    
    // Apply headers
    securityHeaders.applyHeaders();
    
    // Get the current config
    const config = securityHeaders.getConfig();
    
    // Verify changes were applied
    expect(config.csp.scriptSrc).toContain('https://example.com');
  });
  
  test('should apply X-XSS-Protection header', () => {
    // Apply headers
    securityHeaders.applyHeaders();
    
    // Check meta tag creation
    const createdElements = (document.createElement as jest.Mock).mock.results.map(
      result => result.value
    );
    
    // Find X-XSS-Protection meta
    const xssProtectionElement = createdElements.find(el => el.httpEquiv === 'X-XSS-Protection');
    expect(xssProtectionElement).toBeTruthy();
    expect(xssProtectionElement.content).toContain('1');
  });
  
  test('should apply X-Content-Type-Options header', () => {
    // Apply headers
    securityHeaders.applyHeaders();
    
    // Check meta tag creation
    const createdElements = (document.createElement as jest.Mock).mock.results.map(
      result => result.value
    );
    
    // Find X-Content-Type-Options meta
    const contentTypeOptionsElement = createdElements.find(
      el => el.httpEquiv === 'X-Content-Type-Options'
    );
    expect(contentTypeOptionsElement).toBeTruthy();
    expect(contentTypeOptionsElement.content).toBe('nosniff');
  });
}); 
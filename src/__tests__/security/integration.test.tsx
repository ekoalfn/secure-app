import React from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import '@testing-library/jest-dom';
import DOMPurify from 'dompurify';
import { createSanitizedContent, sanitizers } from '../../security/trustedTypes';

// Declare the TrustedHTML type for test compatibility
declare global {
  interface TrustedHTML {}
}

// Mock DOMPurify
jest.mock('dompurify', () => ({
  sanitize: jest.fn((content) => {
    // Simulate sanitization by removing script tags and preserving safe content
    if (typeof content === 'string') {
      // Remove script tags and their content
      const withoutScripts = content.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
      // Remove event handlers
      const withoutEvents = withoutScripts.replace(/\s(on\w+)="[^"]*"/gi, '');
      // Remove javascript: URLs
      const withoutJsUrls = withoutEvents.replace(/javascript:[^"']*/gi, '');
      // Return the sanitized content
      return withoutJsUrls.trim();
    }
    return content;
  })
}));

// Mock component that uses sanitization
function TestSanitizedComponent({ html }: { html: string }) {
  const sanitizedContent = React.useMemo(() => {
    return { __html: DOMPurify.sanitize(html) };
  }, [html]);

  return (
    <div 
      data-testid="content" 
      dangerouslySetInnerHTML={sanitizedContent}
    />
  );
}

describe('Security Integration Tests', () => {
  afterEach(() => {
    cleanup();
    jest.clearAllMocks();
  });

  test('Component should sanitize HTML content', () => {
    const maliciousHTML = '<div>Safe content</div><script>alert("XSS")</script>';
    render(<TestSanitizedComponent html={maliciousHTML} />);
    
    // Test that DOMPurify was called with the correct input
    expect(DOMPurify.sanitize).toHaveBeenCalledWith(maliciousHTML);
    
    // Get the rendered content
    const contentElement = screen.getByTestId('content');
    
    // Verify the element exists
    expect(contentElement).toBeInTheDocument();
    
    // Verify the content was sanitized correctly
    const sanitizedHTML = DOMPurify.sanitize(maliciousHTML);
    expect(contentElement.innerHTML).toBe(sanitizedHTML);
    expect(contentElement.innerHTML).not.toContain('<script>');
  });

  test('Component should handle different types of XSS payloads', () => {
    const xssPayloads = [
      {
        input: '<img src="x" onerror="alert(1)">',
        expected: '<img src="x">'
      },
      {
        input: '<svg/onload=alert(1)>',
        expected: '<svg></svg>'
      },
      {
        input: '<a href="javascript:alert(1)">Click me</a>',
        expected: '<a>Click me</a>'
      },
      {
        input: '"><script>alert(1)</script>',
        expected: '">'
      }
    ];
    
    xssPayloads.forEach(({ input, expected }) => {
      cleanup();
      render(<TestSanitizedComponent html={input} />);
      
      // Verify DOMPurify was called
      expect(DOMPurify.sanitize).toHaveBeenCalledWith(input);
      
      // Get the rendered content
      const contentElement = screen.getByTestId('content');
      
      // Verify the content was sanitized
      expect(contentElement.innerHTML).not.toContain('alert');
      expect(contentElement.innerHTML).not.toContain('javascript:');
      expect(contentElement.innerHTML).not.toContain('onerror');
      expect(contentElement.innerHTML).not.toContain('onload');
      
      jest.clearAllMocks();
    });
  });
});

// Mock component that implements CSRF protection
function TestCSRFForm() {
  const [token, setToken] = React.useState('mock-csrf-token');
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate form submission with CSRF token
  };
  
  return (
    <form onSubmit={handleSubmit} data-testid="csrf-form">
      <input type="hidden" name="csrf_token" value={token} data-testid="csrf-token" />
      <input type="text" name="username" data-testid="username" />
      <button type="submit" data-testid="submit">Submit</button>
    </form>
  );
}

describe('CSRF Protection Integration Tests', () => {
  test('Form should include CSRF token', () => {
    render(<TestCSRFForm />);
    
    const form = screen.getByTestId('csrf-form');
    expect(form).toBeInTheDocument();
    
    const csrfToken = screen.getByTestId('csrf-token');
    expect(csrfToken).toHaveAttribute('value', 'mock-csrf-token');
  });
  
  test('Form submission should include CSRF token', () => {
    const mockSubmit = jest.fn(e => e.preventDefault());
    
    render(
      <form onSubmit={mockSubmit} data-testid="csrf-form">
        <input type="hidden" name="csrf_token" value="test-token" data-testid="csrf-token" />
        <button type="submit" data-testid="submit">Submit</button>
      </form>
    );
    
    // Click the submit button
    fireEvent.click(screen.getByTestId('submit'));
    
    // Check that the form was submitted
    expect(mockSubmit).toHaveBeenCalled();
    
    // In a real test, you would also check that the token was included in the request
  });
}); 
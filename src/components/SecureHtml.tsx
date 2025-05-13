import React, { useEffect, useRef } from 'react';
import sanitizeHtml from '../utils/sanitizeHtml';

interface SecureHtmlProps {
  content: string;
  sanitizeOptions?: Record<string, any>;
  className?: string;
}

/**
 * SecureHtml component for safely rendering sanitized HTML content
 * @param props - Component props
 * @returns React element
 */
const SecureHtml: React.FC<SecureHtmlProps> = ({ 
  content, 
  sanitizeOptions = {}, 
  className = '' 
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  // Sanitize and render the content
  useEffect(() => {
    if (containerRef.current) {
      // First sanitize the HTML
      const sanitizedContent = sanitizeHtml(content, sanitizeOptions);
      
      // Then render it to the DOM
      containerRef.current.innerHTML = sanitizedContent;
    }
  }, [content, sanitizeOptions]);

  return <div ref={containerRef} className={className} />;
};

export default SecureHtml; 
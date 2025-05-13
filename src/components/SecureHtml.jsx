import React, { useEffect, useRef } from 'react';
import sanitizeHtml from '../utils/sanitizeHtml';

/**
 * SecureHtml component for safely rendering sanitized HTML content
 * @param {Object} props - Component props
 * @param {string} props.content - The HTML content to sanitize and render
 * @param {Object} props.sanitizeOptions - Optional custom sanitization options
 * @param {string} props.className - Optional CSS class name for the container
 * @returns {JSX.Element}
 */
const SecureHtml = ({ content, sanitizeOptions = {}, className = '' }) => {
  const containerRef = useRef(null);

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
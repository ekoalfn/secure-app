import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { setupMockBackend } from './mockBackend';
import { initializeSecurity } from './security';

/**
 * Security Improvements Implemented:
 * 
 * 1. Content Security Policy (CSP)
 *    - Restricts sources of executable scripts
 *    - Prevents XSS attacks
 * 
 * 2. HttpOnly Cookies
 *    - Authentication tokens stored in HttpOnly cookies
 *    - Prevents JavaScript access to sensitive cookies
 * 
 * 3. CSRF Protection
 *    - All state-changing requests require a valid CSRF token
 *    - Token validation uses cryptographically secure comparison
 * 
 * 4. Secure Headers
 *    - X-Frame-Options to prevent clickjacking
 *    - X-Content-Type-Options to prevent MIME sniffing
 *    - X-XSS-Protection to enable browser XSS filters
 * 
 * 5. Input Validation and Sanitization
 *    - All user input is validated and sanitized
 *    - Uses DOMPurify to sanitize HTML
 * 
 * 6. HTTPS Enforcement
 *    - All connections redirected to HTTPS
 *    - Secure cookie attributes
 */

// Initialize the mock backend
setupMockBackend();

// Initialize all security features
initializeSecurity();

// Create root and render app
const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();

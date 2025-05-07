import React from 'react';
import Navbar from '../components/Navbar';

const Home: React.FC = () => {
  return (
    <div className="page">
      <Navbar />
      <div className="container">
        <h1>Welcome to Secure App</h1>
        <p>This application demonstrates security best practices for React.js applications against XSS and CSRF attacks.</p>
        <p>Here are some features you can explore:</p>
        <ul>
          <li>Register and login to access protected resources</li>
          <li>Update your profile information</li>
          <li>Change your password</li>
        </ul>
        <div className="security-info">
          <h3>Security Features</h3>
          <p>This application includes the following security measures:</p>
          <ul>
            <li><strong>HttpOnly Cookies</strong> - Authentication tokens are stored in HttpOnly cookies to prevent theft via XSS</li>
            <li><strong>Content Security Policy (CSP)</strong> - Restricts the sources of executable scripts</li>
            <li><strong>Input Sanitization</strong> - All user input is sanitized before rendering using DOMPurify</li>
            <li><strong>CSRF Tokens</strong> - All state-changing operations require a valid CSRF token</li>
            <li><strong>SameSite Cookie Attributes</strong> - Cookies are restricted to same-site requests</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Home; 
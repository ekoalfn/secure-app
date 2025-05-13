import React from 'react';

/**
 * SecureScript component for adding inline scripts with CSP nonces
 * @param {Object} props - Component props
 * @param {string} props.content - The JavaScript content to inject
 * @param {string} props.nonce - The CSP nonce value
 * @returns {JSX.Element}
 */
const SecureScript = ({ content, nonce }) => {
  // Using dangerouslySetInnerHTML with a nonce to make it CSP compliant
  return (
    <script 
      nonce={nonce} 
      dangerouslySetInnerHTML={{ __html: content }} 
    />
  );
};

export default SecureScript; 
import React from 'react';

/**
 * SecureStyle component for adding inline styles with CSP nonces
 * @param {Object} props - Component props
 * @param {string} props.content - The CSS content to inject
 * @param {string} props.nonce - The CSP nonce value
 * @returns {JSX.Element}
 */
const SecureStyle = ({ content, nonce }) => {
  return (
    <style 
      nonce={nonce} 
      dangerouslySetInnerHTML={{ __html: content }} 
    />
  );
};

export default SecureStyle; 
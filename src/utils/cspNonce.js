/**
 * Utility for generating CSP nonces
 */
const crypto = require('crypto');

// Generate a cryptographically secure random nonce
function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

// Export the nonce generation function
module.exports = {
  generateNonce
}; 
const { createProxyMiddleware } = require('http-proxy-middleware');
const { generateNonce } = require('./utils/cspNonce');

// CSP configuration
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: [],
  }
};

// Convert CSP config to header string
const getCspString = (config) => {
  return Object.entries(config.directives)
    .filter(([, sources]) => sources && sources.length)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
};

module.exports = function(app) {
  // Add security headers to all responses
  app.use((req, res, next) => {
    // Generate a unique nonce for this request
    const nonce = generateNonce();
    req.cspNonce = nonce;
    
    // CSP configuration with nonce
    const cspDirectives = {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", `'nonce-${nonce}'`],
      styleSrc: ["'self'", `'nonce-${nonce}'`],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    };
    
    // Convert CSP config to header string
    const cspString = Object.entries(cspDirectives)
      .filter(([, sources]) => sources && sources.length)
      .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
      .join('; ');
    
    // Set the CSP header
    res.setHeader('Content-Security-Policy', cspString);
    
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Enable XSS protection in browsers
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Set referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions policy
    res.setHeader('Permissions-Policy', 
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
    
    next();
  });

  // Optional API proxy if needed
  app.use('/api', 
    createProxyMiddleware({
      target: 'http://localhost:3000',
      changeOrigin: true,
    })
  );
}; 
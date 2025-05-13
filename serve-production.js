const express = require('express');
const path = require('path');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// Parse JSON for CSP reports
app.use(bodyParser.json({
  type: ['json', 'application/csp-report']
}));

// Generate a CSP nonce
const generateNonce = () => {
  return crypto.randomBytes(16).toString('base64');
};

// Security middleware
app.use((req, res, next) => {
  // Generate a unique nonce for this request
  const nonce = generateNonce();
  req.cspNonce = nonce;
  
  // Apply Helmet with CSP
  helmet({
    contentSecurityPolicy: {
      directives: {
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
        upgradeInsecureRequests: [],
        reportUri: '/api/security/csp-report'
      }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    frameguard: { action: 'deny' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    noSniff: true,
    xssFilter: true
  })(req, res, next);
});

// Add additional security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
  next();
});

// Serve static files from the build directory
app.use(express.static(path.join(__dirname, 'build')));

// Endpoint for CSP violation reports
app.post('/api/security/csp-report', (req, res) => {
  console.log('CSP Violation:', req.body);
  res.status(204).end();
});

// Send all requests to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Production server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to view the application`);
}); 
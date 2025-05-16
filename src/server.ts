import express from 'express';
import path from 'path';
import session from 'express-session';
import helmet from 'helmet';
import cors from 'cors';
import crypto from 'crypto';
import { setupMockBackend } from './mockBackend';
import { errorHandler, notFoundHandler } from './security/error';
import https from 'https';
import fs from 'fs';

const app = express();
const PORT = process.env.PORT || 5000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

// Generate CSP nonce
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  (req as any).cspNonce = nonce;
  next();
});

// Security headers with Helmet
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  const nonce = (req as any).cspNonce;
  
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", `'nonce-${nonce}'`],
        styleSrc: ["'self'", `'nonce-${nonce}'`, "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })(req, res, next);
});

// CORS configuration - Restricted to specific origins
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5000'],
  methods: ['GET', 'POST'],
  credentials: true,
  optionsSuccessStatus: 204
}));

// Setup mock backend
setupMockBackend();

// Session configuration
app.use(session({
  secret: 'your-secure-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  }
}));

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Expose nonce to templates
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.locals.nonce = (req as any).cspNonce || '';
  next();
});

// API routes
app.use('/api', require('./routes'));

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// Not found handler
app.use(notFoundHandler);

// Error handler
app.use(errorHandler);

// Redirect HTTP to HTTPS (always, not just in production)
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect(`https://${req.hostname}:${HTTPS_PORT}${req.url}`);
  }
  next();
});

// Start HTTP server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Note: For better security, use HTTPS in production.');
});

// Start HTTPS server if certificates exist
try {
  const privateKey = fs.readFileSync(path.join(__dirname, '../ca.key'), 'utf8');
  const certificate = fs.readFileSync(path.join(__dirname, '../ca.crt'), 'utf8');
  const credentials = { key: privateKey, cert: certificate };
  
  const httpsServer = https.createServer(credentials, app);
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`HTTPS server running on port ${HTTPS_PORT}`);
  });
} catch (err) {
  console.warn('No SSL certificates found, HTTPS server not started');
  console.warn('For production, you should use HTTPS');
} 
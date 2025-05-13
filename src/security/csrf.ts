import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import csrf from 'csurf';
import { AppError } from './errorHandler';

// Simpan CSRF token dalam memory (dalam production gunakan Redis/database)
const csrfTokens = new Map<string, { token: string; expires: number }>();

// Cleanup expired tokens regularly
setInterval(() => {
  const now = Date.now();
  for (const [userId, data] of csrfTokens.entries()) {
    if (now > data.expires) {
      csrfTokens.delete(userId);
    }
  }
}, 60 * 60 * 1000); // Clean up every hour

// Generate CSRF token with improved entropy
export const generateCSRFToken = (userId: string): string => {
  const token = crypto.randomBytes(64).toString('hex');
  const expires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour expiration (shorter is better)

  csrfTokens.set(userId, { token, expires });
  return token;
};

// Validasi CSRF token with constant-time comparison
export const validateCSRFToken = (userId: string, token: string): boolean => {
  const stored = csrfTokens.get(userId);
  if (!stored) return false;

  // Cek expired
  if (Date.now() > stored.expires) {
    csrfTokens.delete(userId);
    return false;
  }

  // Use constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(stored.token, 'utf-8'),
      Buffer.from(token, 'utf-8')
    );
  } catch (e) {
    return false;
  }
};

// Konfigurasi CSRF
const csrfOptions = {
  cookie: {
    httpOnly: true,
    secure: true, // Always use secure
    sameSite: 'strict' as const,
    path: '/',
    maxAge: 3600 // 1 hour expiration
  }
};

// Create a type-safe wrapper for csurf middleware
const csurfMiddleware = csrf(csrfOptions);

// Middleware untuk CSRF protection
export const csrfMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Skip CSRF check untuk GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Check for proper origin header to prevent CSRF
  const origin = req.headers.origin;
  const host = req.headers.host;

  if (origin && host) {
    // For production use a whitelist of allowed origins
    const allowedOrigins = ['https://localhost:3000']; // Add your domains
    try {
      const originHostname = new URL(origin).hostname;
      const requestHostname = host.split(':')[0];
      
      if (originHostname !== requestHostname && !allowedOrigins.includes(origin)) {
        return next(new AppError('Invalid origin', 403));
      }
    } catch (e) {
      return next(new AppError('Invalid origin format', 403));
    }
  }

  // Safely apply CSRF protection with error handling
  try {
    // Type cast to avoid TypeScript errors
    const typeSafeReq = req as any;
    const typeSafeRes = res as any;
    csurfMiddleware(typeSafeReq, typeSafeRes, (err: any) => {
      if (err) {
        return next(new AppError('Invalid CSRF token', 403));
      }
      next();
    });
  } catch (e) {
    return next(new AppError('CSRF validation error', 403));
  }
};

// Middleware untuk mengirim CSRF token ke client
export const sendCsrfToken = (req: Request, res: Response, next: NextFunction) => {
  // Set CSRF token di header if the function exists
  if (typeof req.csrfToken === 'function') {
    res.setHeader('X-CSRF-Token', req.csrfToken());
  }
  next();
};

// Middleware untuk validasi CSRF token
export const validateCsrfToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers['x-csrf-token'];
  const sessionToken = req.session?.csrfToken;

  if (!token || !sessionToken) {
    return next(new AppError('Missing CSRF token', 403));
  }
  
  try {
    // Use constant-time comparison to prevent timing attacks
    const isValid = crypto.timingSafeEqual(
      Buffer.from(token.toString(), 'utf-8'),
      Buffer.from(sessionToken, 'utf-8')
    );
    
    if (!isValid) {
      return next(new AppError('Invalid CSRF token', 403));
    }
  } catch (err) {
    return next(new AppError('Invalid CSRF token', 403));
  }

  next();
};

// CSRF token endpoint handler
export const getCSRFToken = (req: Request, res: Response) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  const token = generateCSRFToken(req.session.userId);
  if (req.session) {
    req.session.csrfToken = token;
  }
  
  res.json({ csrfToken: token });
};

// Middleware untuk refresh CSRF token
export const refreshCsrfToken = (req: Request, res: Response, next: NextFunction) => {
  // Generate token baru
  if (req.csrfToken) {
    const newToken = req.csrfToken();

    // Update token di session
    if (req.session) {
      req.session.csrfToken = newToken;
    }

    // Set token baru di header
    res.setHeader('X-CSRF-Token', newToken);
  }
  next();
};

// Middleware untuk double submit cookie pattern
export const doubleSubmitCookie = (req: Request, res: Response, next: NextFunction) => {
  // Generate random token
  const token = Math.random().toString(36).substring(2);

  // Set token di cookie
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false, // Cookie harus bisa diakses oleh JavaScript
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });

  // Set token di header
  res.setHeader('X-CSRF-Token', token);
  next();
};

// Middleware untuk synchronizer token pattern
export const synchronizerToken = (req: Request, res: Response, next: NextFunction) => {
  // Generate random token
  const token = Math.random().toString(36).substring(2);

  // Simpan token di session
  if (req.session) {
    req.session.csrfToken = token;
  }

  // Set token di header
  res.setHeader('X-CSRF-Token', token);
  next();
}; 
import session from 'express-session';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

// Extend Express Session type with added fields
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    role?: string;
    csrfToken?: string;
  }
}

// Generate a stronger secret key
const generateSecretKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Konfigurasi session
const sessionConfig = {
  secret: process.env.SESSION_SECRET || generateSecretKey(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production' || true, // Always require HTTPS
    httpOnly: true, // Mencegah akses JavaScript ke cookie
    sameSite: 'strict' as const, // Mencegah CSRF
    maxAge: 24 * 60 * 60 * 1000, // 24 jam
    path: '/',
  },
  name: 'secureSessionId', // Custom session name (not default)
};

// Middleware untuk mengecek session
export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  if (!req.session?.userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  next();
};

// Middleware untuk mengecek role
export const requireRole = (role: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session?.userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    // Type-safe role check
    const sessionWithRole = req.session as any;
    if (sessionWithRole.role !== role) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    next();
  };
};

// Setup session middleware
export const setupSession = (app: any) => {
  app.use(session(sessionConfig));
}; 
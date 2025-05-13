import 'express';
import 'express-session';

// Augment express-session with additional properties
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    role?: string;
    csrfToken?: string;
  }
}

// Augment express Request with additional properties
declare module 'express' {
  interface Request {
    csrfToken?: () => string;
  }
} 
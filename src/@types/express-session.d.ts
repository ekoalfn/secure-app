import 'express-session';

declare module 'express-session' {
  interface Session {
    userId?: string;
    role?: string;
    csrfToken?: string;
  }
} 
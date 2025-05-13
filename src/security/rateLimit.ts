import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';

// Configure rate limiter for general API requests
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: 'Too many requests, please try again later.' }
});

// Configure stricter rate limiter for authentication endpoints
export const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 login attempts per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: 'Too many login attempts, please try again later.' }
});

// Apply rate limiting to a specific route
export const applyRateLimit = (req: Request, res: Response, next: NextFunction) => {
  // Type cast to avoid TypeScript errors
  const typeSafeReq = req as any;
  const typeSafeRes = res as any;
  return apiLimiter(typeSafeReq, typeSafeRes, next);
};

// Export an empty object to make this file a module
export {}; 
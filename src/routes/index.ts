import express, { Request, Response } from 'express';
import { mockAPI, mockServices } from '../mockBackend';
import { validateLogin, validateRegister, validateUpdateProfile, validateChangePassword } from '../security/validation';
import { csrfMiddleware, getCSRFToken, validateCsrfToken } from '../security/csrf';
import { requireAuth } from '../security/session';

const router = express.Router();

// Rate limiting middleware with improved configuration
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: { status: 429, message: 'Too many requests, please try again later.' }
});

// Stricter rate limit for authentication attempts
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 login attempts per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, message: 'Too many login attempts, please try again later.' }
});

// Apply rate limiting to all routes
router.use(limiter);

// Auth routes
router.post('/auth/login', authLimiter, validateLogin, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    // Use mock service directly
    const result = await mockServices.auth.login(email, password);
    
    // Set secure headers
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    // Store user ID in session for authentication
    if (req.session) {
      req.session.userId = result.user.id;
    }
    
    res.json(result);
  } catch (error: any) {
    // Don't reveal whether email exists or not
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

router.post('/auth/register', authLimiter, validateRegister, async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    // Use mock service directly
    const result = await mockServices.auth.register(name, email, password);
    
    // Set secure headers
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    // Store user ID in session for authentication
    if (req.session) {
      req.session.userId = result.user.id;
    }
    
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ message: 'Registration failed' });
  }
});

// Add logout endpoint
router.post('/auth/logout', async (req: Request, res: Response) => {
  try {
    // Clear session
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          res.status(500).json({ message: 'Failed to logout' });
        } else {
          res.json({ success: true });
        }
      });
    } else {
      res.json({ success: true });
    }
  } catch (error: any) {
    res.status(500).json({ message: 'Failed to logout' });
  }
});

// User routes with CSRF protection and authentication
router.get('/users/me', requireAuth, async (req: Request, res: Response) => {
  try {
    // Use mock service directly
    const result = await mockServices.auth.getUser();
    res.json(result);
  } catch (error: any) {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

router.put('/users/profile', requireAuth, csrfMiddleware, validateUpdateProfile, async (req: Request, res: Response) => {
  try {
    const { data, csrfToken } = req.body;
    // Use mock service directly
    const result = await mockServices.users.updateProfile(data, csrfToken);
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ message: 'Update failed' });
  }
});

router.put('/users/change-password', requireAuth, csrfMiddleware, validateChangePassword, async (req: Request, res: Response) => {
  try {
    const { oldPassword, newPassword, csrfToken } = req.body;
    // Use mock service directly
    const result = await mockServices.users.changePassword(oldPassword, newPassword, csrfToken);
    
    // Set secure headers for sensitive operations
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ message: 'Password change failed' });
  }
});

// New change-password endpoint for CSRF simulation
router.post('/users/change-password', requireAuth, csrfMiddleware, validateChangePassword, async (req: Request, res: Response) => {
  try {
    const { oldPassword, newPassword, csrfToken } = req.body;
    // Use mock service directly
    const result = await mockServices.users.changePassword(oldPassword, newPassword, csrfToken);
    
    // Set secure headers for sensitive operations
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ message: 'Password change failed' });
  }
});

// New update profile endpoint
router.post('/users/profile', requireAuth, csrfMiddleware, validateUpdateProfile, async (req: Request, res: Response) => {
  try {
    const { data, csrfToken } = req.body;
    // Use mock service directly
    const result = await mockServices.users.updateProfile(data, csrfToken);
    res.json(result);
  } catch (error: any) {
    res.status(400).json({ message: 'Update failed' });
  }
});

// CSRF token endpoint
router.get('/auth/csrf-token', requireAuth, getCSRFToken);

export default router; 
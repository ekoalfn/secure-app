"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const mockBackend_1 = require("../mockBackend");
const validation_1 = require("../security/validation");
const csrf_1 = require("../security/csrf");
const session_1 = require("../security/session");
const router = express_1.default.Router();
// Rate limiting middleware with improved configuration
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 429, message: 'Too many requests, please try again later.' }
});
// Stricter rate limit for authentication attempts
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 429, message: 'Too many login attempts, please try again later.' }
});
// Apply rate limiting to all routes
router.use(limiter);
// Auth routes
router.post('/auth/login', authLimiter, validation_1.validateLogin, async (req, res) => {
    try {
        const { email, password } = req.body;
        // Use mock service directly
        const result = await mockBackend_1.mockServices.auth.login(email, password);
        // Set secure headers
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        // Store user ID in session for authentication
        if (req.session) {
            req.session.userId = result.user.id;
        }
        res.json(result);
    }
    catch (error) {
        // Don't reveal whether email exists or not
        res.status(401).json({ message: 'Invalid credentials' });
    }
});
router.post('/auth/register', authLimiter, validation_1.validateRegister, async (req, res) => {
    try {
        const { name, email, password } = req.body;
        // Use mock service directly
        const result = await mockBackend_1.mockServices.auth.register(name, email, password);
        // Set secure headers
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        // Store user ID in session for authentication
        if (req.session) {
            req.session.userId = result.user.id;
        }
        res.json(result);
    }
    catch (error) {
        res.status(400).json({ message: 'Registration failed' });
    }
});
// Add logout endpoint
router.post('/auth/logout', async (req, res) => {
    try {
        // Clear session
        if (req.session) {
            req.session.destroy((err) => {
                if (err) {
                    res.status(500).json({ message: 'Failed to logout' });
                }
                else {
                    res.json({ success: true });
                }
            });
        }
        else {
            res.json({ success: true });
        }
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to logout' });
    }
});
// User routes with CSRF protection and authentication
router.get('/users/me', session_1.requireAuth, async (req, res) => {
    try {
        // Use mock service directly
        const result = await mockBackend_1.mockServices.auth.getUser();
        res.json(result);
    }
    catch (error) {
        res.status(401).json({ message: 'Unauthorized' });
    }
});
router.put('/users/profile', session_1.requireAuth, csrf_1.csrfMiddleware, validation_1.validateUpdateProfile, async (req, res) => {
    try {
        const { data, csrfToken } = req.body;
        // Use mock service directly
        const result = await mockBackend_1.mockServices.users.updateProfile(data, csrfToken);
        res.json(result);
    }
    catch (error) {
        res.status(400).json({ message: 'Update failed' });
    }
});
router.put('/users/change-password', session_1.requireAuth, csrf_1.csrfMiddleware, validation_1.validateChangePassword, async (req, res) => {
    try {
        const { oldPassword, newPassword, csrfToken } = req.body;
        // Use mock service directly
        const result = await mockBackend_1.mockServices.users.changePassword(oldPassword, newPassword, csrfToken);
        // Set secure headers for sensitive operations
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.json(result);
    }
    catch (error) {
        res.status(400).json({ message: 'Password change failed' });
    }
});
// CSRF token endpoint
router.get('/auth/csrf-token', session_1.requireAuth, csrf_1.getCSRFToken);
exports.default = router;

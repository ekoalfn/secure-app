"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const express_session_1 = __importDefault(require("express-session"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const crypto_1 = __importDefault(require("crypto"));
const mockBackend_1 = require("./mockBackend");
const error_1 = require("./security/error");
const app = (0, express_1.default)();
const PORT = 5000; // Set to 5000 as requested
// Generate CSP nonce
app.use((req, res, next) => {
    const nonce = crypto_1.default.randomBytes(16).toString('base64');
    req.cspNonce = nonce;
    next();
});
// Security headers with Helmet
app.use((req, res, next) => {
    const nonce = req.cspNonce;
    (0, helmet_1.default)({
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
                frameAncestors: ["'none'"]
            }
        }
    })(req, res, next);
});
// CORS configuration - Restricted to specific origins
app.use((0, cors_1.default)({
    origin: ['http://localhost:3000', 'http://localhost:5000'],
    methods: ['GET', 'POST', 'PUT'],
    credentials: true,
    optionsSuccessStatus: 204
}));
// Setup mock backend
(0, mockBackend_1.setupMockBackend)();
// Session configuration
app.use((0, express_session_1.default)({
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
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: false }));
// Expose nonce to templates
app.use((req, res, next) => {
    res.locals.nonce = req.cspNonce || '';
    next();
});
// API routes
app.use('/api', require('./routes').default);
// Not found handler
app.use(error_1.notFoundHandler);
// Error handler
app.use(error_1.errorHandler);
// Start server
app.listen(PORT, () => {
    console.log(`Secure server running on port ${PORT}`);
});

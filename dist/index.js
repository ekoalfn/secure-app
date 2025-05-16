"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importDefault(require("react"));
const client_1 = __importDefault(require("react-dom/client"));
require("./index.css");
const App_1 = __importDefault(require("./App"));
const reportWebVitals_1 = __importDefault(require("./reportWebVitals"));
const mockBackend_1 = require("./mockBackend");
const security_1 = require("./security");
/**
 * Security Improvements Implemented:
 *
 * 1. Content Security Policy (CSP)
 *    - Restricts sources of executable scripts
 *    - Prevents XSS attacks
 *
 * 2. HttpOnly Cookies
 *    - Authentication tokens stored in HttpOnly cookies
 *    - Prevents JavaScript access to sensitive cookies
 *
 * 3. CSRF Protection
 *    - All state-changing requests require a valid CSRF token
 *    - Token validation uses cryptographically secure comparison
 *
 * 4. Secure Headers
 *    - X-Frame-Options to prevent clickjacking
 *    - X-Content-Type-Options to prevent MIME sniffing
 *    - X-XSS-Protection to enable browser XSS filters
 *
 * 5. Input Validation and Sanitization
 *    - All user input is validated and sanitized
 *    - Uses DOMPurify to sanitize HTML
 *
 * 6. HTTPS Enforcement
 *    - All connections redirected to HTTPS
 *    - Secure cookie attributes
 */
// Initialize the mock backend
(0, mockBackend_1.setupMockBackend)();
// Initialize all security features
(0, security_1.initializeSecurity)();
// Create root and render app
const root = client_1.default.createRoot(document.getElementById('root'));
root.render((0, jsx_runtime_1.jsx)(react_1.default.StrictMode, { children: (0, jsx_runtime_1.jsx)(App_1.default, {}) }));
// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
(0, reportWebVitals_1.default)();

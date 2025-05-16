"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useCSRFProtectedForm = exports.useCSRFToken = exports.csrfProtection = void 0;
// Enhanced CSRF Protection Module
const react_1 = __importDefault(require("react"));
class CSRFProtection {
    // Private constructor for singleton pattern
    constructor() {
        this.tokenKey = 'XSRF-TOKEN';
        this.headerName = 'X-XSRF-TOKEN';
        this.stateChangeCallbacks = [];
        // Initial CSRF state
        this.state = {
            token: this.generateToken(),
            timestamp: Date.now(),
            rotationInterval: 15 * 60 * 1000,
            lastRotated: Date.now(),
            tokenHistory: [],
            originAllowlist: [window.location.origin, 'https://localhost:5001'],
            rotationEnabled: true
        };
        // Keep history of tokens (for a short time) to allow for in-flight requests
        this.state.tokenHistory.push({
            token: this.state.token,
            created: this.state.timestamp
        });
        // Set up automatic token rotation
        if (this.state.rotationEnabled) {
            this.setupTokenRotation();
        }
        // Initialize by setting token in cookie
        this.setTokenCookie();
    }
    // Singleton accessor
    static getInstance() {
        if (!CSRFProtection.instance) {
            CSRFProtection.instance = new CSRFProtection();
        }
        return CSRFProtection.instance;
    }
    // Generate a cryptographically strong random token
    generateToken() {
        // Create a secure random token
        const buffer = new Uint8Array(32);
        if (typeof window.crypto !== 'undefined' && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(buffer);
        }
        else {
            // Fallback for older browsers (less secure)
            for (let i = 0; i < buffer.length; i++) {
                buffer[i] = Math.floor(Math.random() * 256);
            }
        }
        // Convert to base64 and make URL safe
        // Use Array.from to properly convert Uint8Array for older TypeScript targets
        return btoa(String.fromCharCode.apply(null, Array.from(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    // Set up token rotation
    setupTokenRotation() {
        setInterval(() => {
            if (Date.now() - this.state.lastRotated >= this.state.rotationInterval) {
                this.rotateToken();
            }
        }, 60 * 1000); // Check every minute
    }
    // Rotate the CSRF token
    rotateToken() {
        const oldToken = this.state.token;
        // Generate new token
        const newToken = this.generateToken();
        this.state.token = newToken;
        this.state.lastRotated = Date.now();
        // Add to history for validation of in-flight requests
        this.state.tokenHistory.push({
            token: newToken,
            created: Date.now()
        });
        // Limit history size (keep last 5 tokens)
        if (this.state.tokenHistory.length > 5) {
            this.state.tokenHistory.shift();
        }
        // Update cookie
        this.setTokenCookie();
        // Notify subscribers of token change
        this.notifyStateChange();
        console.log('CSRF token rotated');
    }
    // Set CSRF token in cookie
    setTokenCookie() {
        document.cookie = `${this.tokenKey}=${this.state.token}; secure; samesite=strict; path=/`;
    }
    // Get current CSRF token
    getToken() {
        // Store token in localStorage for persistence
        localStorage.setItem('csrf_token', this.state.token);
        return this.state.token;
    }
    // Validate a CSRF token against current and recent tokens
    validateToken(token) {
        if (!token)
            return false;
        // Check if it matches current token
        if (token === this.state.token)
            return true;
        // Check against token history for recently rotated tokens
        // This helps prevent issues with in-flight requests during token rotation
        const validHistoryToken = this.state.tokenHistory.some(historyItem => historyItem.token === token &&
            Date.now() - historyItem.created < 30 * 60 * 1000 // 30 minutes
        );
        return validHistoryToken;
    }
    // Validate request origin
    validateOrigin(origin) {
        return this.state.originAllowlist.includes(origin);
    }
    // Multi-layer CSRF validation (token + origin)
    validateRequest(request) {
        // Check for token in request
        if (!request.token) {
            return { valid: false, reason: 'Missing CSRF token' };
        }
        // Validate the token
        if (!this.validateToken(request.token)) {
            return { valid: false, reason: 'Invalid CSRF token' };
        }
        // Validate origin if provided
        if (request.origin && !this.validateOrigin(request.origin)) {
            return { valid: false, reason: 'Invalid origin' };
        }
        // Check if token in body matches (triple check)
        if (request.body && request.body._csrf && request.body._csrf !== request.token) {
            return { valid: false, reason: 'Token mismatch between header and body' };
        }
        return { valid: true };
    }
    // Update CSRF protection configuration
    updateConfig(config) {
        if (config.rotationInterval) {
            this.state.rotationInterval = config.rotationInterval;
        }
        if (config.originAllowlist) {
            this.state.originAllowlist = config.originAllowlist;
        }
        if (typeof config.rotationEnabled !== 'undefined') {
            this.state.rotationEnabled = config.rotationEnabled;
        }
        this.notifyStateChange();
    }
    // Subscribe to state changes
    subscribe(callback) {
        this.stateChangeCallbacks.push(callback);
        return () => {
            this.stateChangeCallbacks = this.stateChangeCallbacks.filter(cb => cb !== callback);
        };
    }
    // Notify subscribers of state change
    notifyStateChange() {
        this.stateChangeCallbacks.forEach(callback => {
            try {
                callback(this.getState());
            }
            catch (e) {
                console.error('Error in CSRF state change callback:', e);
            }
        });
    }
    // Get current state (for debugging, excluding token)
    getState() {
        const { token, tokenHistory, ...rest } = this.state;
        return rest;
    }
    // Configure axios interceptors for CSRF protection
    setupAxiosInterceptors(axios) {
        // Request interceptor to add CSRF token to headers
        axios.interceptors.request.use((config) => {
            var _a;
            // Add CSRF token to all state-changing requests
            if (['post', 'put', 'delete', 'patch'].includes((_a = config.method) === null || _a === void 0 ? void 0 : _a.toLowerCase())) {
                const token = this.getToken();
                config.headers['X-CSRF-Token'] = token;
                // Add token to request body for additional validation
                if (config.data && typeof config.data === 'object') {
                    config.data._csrf = token;
                }
                else if (config.data && typeof config.data === 'string') {
                    try {
                        const data = JSON.parse(config.data);
                        data._csrf = token;
                        config.data = JSON.stringify(data);
                    }
                    catch (e) {
                        // Not JSON, don't modify
                    }
                }
            }
            return config;
        });
        // Response interceptor to handle CSRF errors
        axios.interceptors.response.use((response) => response, (error) => {
            var _a, _b, _c, _d;
            // Check if error is CSRF related
            if (((_a = error.response) === null || _a === void 0 ? void 0 : _a.status) === 403 &&
                ((_d = (_c = (_b = error.response) === null || _b === void 0 ? void 0 : _b.data) === null || _c === void 0 ? void 0 : _c.reason) === null || _d === void 0 ? void 0 : _d.includes('CSRF'))) {
                console.error('CSRF validation failed:', error.response.data.reason);
                // Force token rotation on CSRF failure
                this.rotateToken();
            }
            return Promise.reject(error);
        });
    }
}
// Export singleton instance
exports.csrfProtection = CSRFProtection.getInstance();
// React hook for CSRF protection
const useCSRFToken = () => {
    const getCSRFToken = () => exports.csrfProtection.getToken();
    // Get token from cookie (fallback)
    const getTokenFromCookie = () => {
        var _a;
        return ((_a = document.cookie
            .split('; ')
            .find(row => row.startsWith('XSRF-TOKEN='))) === null || _a === void 0 ? void 0 : _a.split('=')[1]) || '';
    };
    return {
        getCSRFToken,
        getTokenFromCookie,
        rotateToken: () => exports.csrfProtection.rotateToken()
    };
};
exports.useCSRFToken = useCSRFToken;
// Form protection hook with React component
const useCSRFProtectedForm = () => {
    const { getCSRFToken } = (0, exports.useCSRFToken)();
    const token = getCSRFToken();
    const CSRFField = react_1.default.createElement('input', {
        type: 'hidden',
        name: '_csrf',
        value: token
    });
    return {
        csrfToken: token,
        CSRFField
    };
};
exports.useCSRFProtectedForm = useCSRFProtectedForm;

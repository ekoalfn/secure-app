"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const csrfProtection_1 = require("../../security/csrfProtection");
const axios_1 = __importDefault(require("axios"));
// Mock localStorage
const localStorageMock = (() => {
    let store = {};
    return {
        getItem: jest.fn((key) => store[key]),
        setItem: jest.fn((key, value) => {
            store[key] = value;
        }),
        removeItem: jest.fn((key) => {
            delete store[key];
        }),
        clear: jest.fn(() => {
            store = {};
        }),
    };
})();
Object.defineProperty(window, 'localStorage', { value: localStorageMock });
// Mock axios
jest.mock('axios', () => ({
    interceptors: {
        request: {
            use: jest.fn(),
        },
        response: {
            use: jest.fn(),
        },
    },
    defaults: {
        headers: {
            common: {},
        },
    },
}));
describe('CSRF Protection Module', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        localStorageMock.clear();
    });
    test('should generate a valid CSRF token', () => {
        const token = csrfProtection_1.csrfProtection.getToken();
        expect(token).toBeTruthy();
        expect(typeof token).toBe('string');
        expect(token.length).toBeGreaterThan(20); // Tokens should be reasonably long
    });
    test('should store token in localStorage', () => {
        csrfProtection_1.csrfProtection.getToken();
        expect(localStorageMock.setItem).toHaveBeenCalledWith('csrf_token', expect.any(String));
    });
    test('should return the same token on subsequent calls', () => {
        const token1 = csrfProtection_1.csrfProtection.getToken();
        const token2 = csrfProtection_1.csrfProtection.getToken();
        expect(token1).toBe(token2);
    });
    test('should generate a new token when rotating', () => {
        const token1 = csrfProtection_1.csrfProtection.getToken();
        const token2 = csrfProtection_1.csrfProtection.rotateToken();
        expect(token1).not.toBe(token2);
    });
    test('should setup axios interceptors correctly', () => {
        csrfProtection_1.csrfProtection.setupAxiosInterceptors(axios_1.default);
        expect(axios_1.default.interceptors.request.use).toHaveBeenCalled();
    });
    test('should add CSRF token to request headers', () => {
        // Setup a mock interceptor function
        let interceptorFn = () => ({});
        axios_1.default.interceptors.request.use.mockImplementation((fn) => {
            interceptorFn = fn;
            return fn;
        });
        // Setup interceptors
        csrfProtection_1.csrfProtection.setupAxiosInterceptors(axios_1.default);
        // Generate a token
        const token = csrfProtection_1.csrfProtection.getToken();
        // Create a mock request config
        const mockConfig = {
            headers: {},
            method: 'POST',
            url: '/api/user',
        };
        // Call the interceptor function
        const result = interceptorFn(mockConfig);
        // Verify the token was added to headers
        expect(result.headers['X-CSRF-Token']).toBe(token);
    });
    test('should not add CSRF token to GET requests', () => {
        // Setup a mock interceptor function
        let interceptorFn = () => ({});
        axios_1.default.interceptors.request.use.mockImplementation((fn) => {
            interceptorFn = fn;
            return fn;
        });
        // Setup interceptors
        csrfProtection_1.csrfProtection.setupAxiosInterceptors(axios_1.default);
        // Create a mock GET request config
        const mockConfig = {
            headers: {},
            method: 'GET',
            url: '/api/user',
        };
        // Call the interceptor function
        const result = interceptorFn(mockConfig);
        // Verify the token was not added to headers
        expect(result.headers['X-CSRF-Token']).toBeUndefined();
    });
});

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
// Konfigurasi axios untuk keamanan
const secureAxios = axios_1.default.create({
    baseURL: 'http://localhost:3000/api',
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
    }
});
// Interceptor untuk menangani CSRF token
secureAxios.interceptors.request.use(async (config) => {
    // Dapatkan CSRF token untuk setiap request
    try {
        const response = await axios_1.default.get('http://localhost:3000/api/auth/csrf-token', {
            withCredentials: true
        });
        config.headers['X-CSRF-Token'] = response.data.csrfToken;
    }
    catch (error) {
        console.error('Failed to get CSRF token:', error);
    }
    return config;
});
// Interceptor untuk menangani error
secureAxios.interceptors.response.use((response) => response, (error) => {
    if (error.response) {
        // Handle error responses
        switch (error.response.status) {
            case 401:
                // Unauthorized - redirect ke login
                window.location.href = '/login';
                break;
            case 403:
                // Forbidden - CSRF token invalid
                console.error('CSRF token invalid or expired');
                break;
            case 429:
                // Too many requests
                console.error('Rate limit exceeded');
                break;
            default:
                console.error('API Error:', error.response.data);
        }
    }
    return Promise.reject(error);
});
exports.default = secureAxios;

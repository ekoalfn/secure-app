"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.applyRateLimit = exports.authLimiter = exports.apiLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
// Configure rate limiter for general API requests
exports.apiLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 429, message: 'Too many requests, please try again later.' }
});
// Configure stricter rate limiter for authentication endpoints
exports.authLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 429, message: 'Too many login attempts, please try again later.' }
});
// Apply rate limiting to a specific route
const applyRateLimit = (req, res, next) => {
    // Type cast to avoid TypeScript errors
    const typeSafeReq = req;
    const typeSafeRes = res;
    return (0, exports.apiLimiter)(typeSafeReq, typeSafeRes, next);
};
exports.applyRateLimit = applyRateLimit;

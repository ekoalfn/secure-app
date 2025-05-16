"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authzErrorHandler = exports.authErrorHandler = exports.validationErrorHandler = exports.asyncHandler = exports.notFoundHandler = exports.errorHandler = exports.AppError = void 0;
const logging_1 = __importDefault(require("./logging"));
// Custom error class
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.AppError = AppError;
// Error handler middleware
const errorHandler = (err, req, res, next) => {
    // Default error
    let error = { ...err };
    error.message = err.message;
    // Log error
    logging_1.default.error('Error occurred', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    // Mongoose bad ObjectId
    if (err.name === 'CastError') {
        const message = 'Resource not found';
        error = new AppError(message, 404);
    }
    // Mongoose duplicate key
    if (err.name === 'MongoError' && err.code === 11000) {
        const message = 'Duplicate field value entered';
        error = new AppError(message, 400);
    }
    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const message = Object.values(err.errors).map((val) => val.message);
        error = new AppError(message.join('. '), 400);
    }
    // JWT error
    if (err.name === 'JsonWebTokenError') {
        const message = 'Invalid token. Please log in again!';
        error = new AppError(message, 401);
    }
    // JWT expired
    if (err.name === 'TokenExpiredError') {
        const message = 'Your token has expired! Please log in again.';
        error = new AppError(message, 401);
    }
    // Send error response
    if (error instanceof AppError) {
        return res.status(error.statusCode).json({
            status: error.status,
            message: error.message
        });
    }
    // Programming or other unknown error: don't leak error details
    return res.status(500).json({
        status: 'error',
        message: 'Something went wrong!'
    });
};
exports.errorHandler = errorHandler;
// Not found handler
const notFoundHandler = (req, res, next) => {
    const error = new AppError(`Not Found - ${req.originalUrl}`, 404);
    next(error);
};
exports.notFoundHandler = notFoundHandler;
// Async handler wrapper
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};
exports.asyncHandler = asyncHandler;
// Validation error handler
const validationErrorHandler = (err, req, res, next) => {
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            status: 'fail',
            message: err.message
        });
    }
    next(err);
};
exports.validationErrorHandler = validationErrorHandler;
// Authentication error handler
const authErrorHandler = (err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            status: 'fail',
            message: 'Invalid token'
        });
    }
    next(err);
};
exports.authErrorHandler = authErrorHandler;
// Authorization error handler
const authzErrorHandler = (err, req, res, next) => {
    if (err.name === 'ForbiddenError') {
        return res.status(403).json({
            status: 'fail',
            message: 'Not authorized'
        });
    }
    next(err);
};
exports.authzErrorHandler = authzErrorHandler;

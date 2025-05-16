"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.csrfErrorHandler = exports.errorHandler = exports.notFoundHandler = exports.AppError = void 0;
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
/**
 * Not found handler middleware
 */
const notFoundHandler = (req, res, next) => {
    res.status(404).json({
        error: 'Not Found',
        message: `The requested resource ${req.path} was not found`
    });
};
exports.notFoundHandler = notFoundHandler;
/**
 * Generic error handler middleware
 */
const errorHandler = (err, req, res, next) => {
    // Don't expose detailed error information in production
    const isProduction = process.env.NODE_ENV === 'production';
    // Log the error for debugging
    console.error('Error:', err);
    // Default status code and message
    const statusCode = err.statusCode || 500;
    const message = isProduction ? 'Internal Server Error' : err.message || 'Something went wrong';
    // Send the response
    res.status(statusCode).json({
        error: err.name || 'Error',
        message,
        // Only include stack trace in development
        ...(isProduction ? {} : { stack: err.stack })
    });
};
exports.errorHandler = errorHandler;
/**
 * CSRF error handler
 */
const csrfErrorHandler = (err, req, res, next) => {
    if (err.code !== 'EBADCSRFTOKEN')
        return next(err);
    // Handle CSRF token errors
    res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid or missing CSRF token'
    });
};
exports.csrfErrorHandler = csrfErrorHandler;

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logDataAccessEvent = exports.logAuthzEvent = exports.logAuthEvent = exports.logSecurityEvent = exports.errorLogger = exports.requestLogger = void 0;
const winston_1 = __importDefault(require("winston"));
// Konfigurasi logger
const logger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    transports: [
        // Tulis semua log dengan level 'error' dan di bawahnya ke 'error.log'
        new winston_1.default.transports.File({ filename: 'logs/error.log', level: 'error' }),
        // Tulis semua log dengan level 'info' dan di bawahnya ke 'combined.log'
        new winston_1.default.transports.File({ filename: 'logs/combined.log' })
    ]
});
// Jika kita tidak dalam production, log juga ke console
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston_1.default.transports.Console({
        format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
    }));
}
// Middleware untuk logging request
const requestLogger = (req, res, next) => {
    const start = Date.now();
    // Log request
    logger.info('Incoming request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    // Log response
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration: `${duration}ms`
        });
    });
    next();
};
exports.requestLogger = requestLogger;
// Middleware untuk logging error
const errorLogger = (err, req, res, next) => {
    logger.error('Error occurred', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    next(err);
};
exports.errorLogger = errorLogger;
// Fungsi untuk logging security events
const logSecurityEvent = (event, details) => {
    logger.warn('Security event', {
        event,
        details,
        timestamp: new Date().toISOString()
    });
};
exports.logSecurityEvent = logSecurityEvent;
// Fungsi untuk logging authentication events
const logAuthEvent = (event, userId, success, details) => {
    logger.info('Authentication event', {
        event,
        userId,
        success,
        details,
        timestamp: new Date().toISOString()
    });
};
exports.logAuthEvent = logAuthEvent;
// Fungsi untuk logging authorization events
const logAuthzEvent = (event, userId, resource, action, success, details) => {
    logger.info('Authorization event', {
        event,
        userId,
        resource,
        action,
        success,
        details,
        timestamp: new Date().toISOString()
    });
};
exports.logAuthzEvent = logAuthzEvent;
// Fungsi untuk logging data access events
const logDataAccessEvent = (event, userId, resource, action, details) => {
    logger.info('Data access event', {
        event,
        userId,
        resource,
        action,
        details,
        timestamp: new Date().toISOString()
    });
};
exports.logDataAccessEvent = logDataAccessEvent;
// Export logger untuk penggunaan langsung
exports.default = logger;

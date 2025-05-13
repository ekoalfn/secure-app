import winston from 'winston';
import { Request, Response, NextFunction } from 'express';

// Konfigurasi logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Tulis semua log dengan level 'error' dan di bawahnya ke 'error.log'
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    // Tulis semua log dengan level 'info' dan di bawahnya ke 'combined.log'
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Jika kita tidak dalam production, log juga ke console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Middleware untuk logging request
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
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

// Middleware untuk logging error
export const errorLogger = (err: Error, req: Request, res: Response, next: NextFunction) => {
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

// Fungsi untuk logging security events
export const logSecurityEvent = (event: string, details: any) => {
  logger.warn('Security event', {
    event,
    details,
    timestamp: new Date().toISOString()
  });
};

// Fungsi untuk logging authentication events
export const logAuthEvent = (event: string, userId: string, success: boolean, details?: any) => {
  logger.info('Authentication event', {
    event,
    userId,
    success,
    details,
    timestamp: new Date().toISOString()
  });
};

// Fungsi untuk logging authorization events
export const logAuthzEvent = (event: string, userId: string, resource: string, action: string, success: boolean, details?: any) => {
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

// Fungsi untuk logging data access events
export const logDataAccessEvent = (event: string, userId: string, resource: string, action: string, details?: any) => {
  logger.info('Data access event', {
    event,
    userId,
    resource,
    action,
    details,
    timestamp: new Date().toISOString()
  });
};

// Export logger untuk penggunaan langsung
export default logger; 
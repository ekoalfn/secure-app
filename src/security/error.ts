import { Request, Response, NextFunction } from 'express';

// Custom error class
export class AppError extends Error {
  statusCode: number;
  status: string;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Not found handler middleware
 */
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({
    error: 'Not Found',
    message: `The requested resource ${req.path} was not found`
  });
};

/**
 * Generic error handler middleware
 */
export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
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

/**
 * CSRF error handler
 */
export const csrfErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  
  // Handle CSRF token errors
  res.status(403).json({
    error: 'Forbidden',
    message: 'Invalid or missing CSRF token'
  });
}; 
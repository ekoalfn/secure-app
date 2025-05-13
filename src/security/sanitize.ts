import { Request, Response, NextFunction } from 'express';
import { sanitize } from 'class-sanitizer';
import { plainToClass } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';

// Middleware untuk sanitasi input
export const sanitizeInput = (dtoClass: any) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Konversi body request ke instance DTO
    const dtoObject = plainToClass(dtoClass, req.body);

    // Sanitasi input
    sanitize(dtoObject);

    // Validasi input
    const errors = await validate(dtoObject);
    if (errors.length > 0) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.map((error: ValidationError) => ({
          property: error.property,
          constraints: error.constraints
        }))
      });
    }

    // Update request body dengan data yang sudah disanitasi
    req.body = dtoObject;
    next();
  };
};

// Fungsi untuk sanitasi string
export const sanitizeString = (input: string): string => {
  return input
    .replace(/[<>]/g, '') // Hapus karakter < dan >
    .replace(/javascript:/gi, '') // Hapus javascript: protocol
    .replace(/on\w+=/gi, '') // Hapus event handlers
    .trim();
};

// Fungsi untuk sanitasi email
export const sanitizeEmail = (email: string): string => {
  return email.toLowerCase().trim();
};

// Fungsi untuk sanitasi URL
export const sanitizeUrl = (url: string): string => {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.toString();
  } catch {
    return '';
  }
};

// Fungsi untuk sanitasi nomor telepon
export const sanitizePhone = (phone: string): string => {
  return phone.replace(/[^0-9+]/g, '');
};

// Fungsi untuk sanitasi nomor
export const sanitizeNumber = (num: string): number => {
  const parsed = parseFloat(num);
  return isNaN(parsed) ? 0 : parsed;
};

// Fungsi untuk sanitasi boolean
export const sanitizeBoolean = (bool: any): boolean => {
  if (typeof bool === 'boolean') return bool;
  if (typeof bool === 'string') {
    return bool.toLowerCase() === 'true';
  }
  return false;
}; 
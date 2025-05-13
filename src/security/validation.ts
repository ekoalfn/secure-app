import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { validate, ValidationError } from 'class-validator';
import { plainToClass } from 'class-transformer';
import { AppError } from './errorHandler';

// Validasi untuk login
export const validateLogin = [
  body('email').isEmail().withMessage('Email tidak valid'),
  body('password').isLength({ min: 8 }).withMessage('Password minimal 8 karakter'),
  processValidationResult
];

// Validasi untuk registrasi
export const validateRegister = [
  body('name').trim().isLength({ min: 3 }).withMessage('Nama minimal 3 karakter'),
  body('email').isEmail().withMessage('Email tidak valid'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password minimal 8 karakter')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
    .withMessage('Password harus mengandung huruf besar, huruf kecil, angka, dan karakter spesial'),
  processValidationResult
];

// Validasi untuk update profile
export const validateUpdateProfile = [
  body('name').optional().trim().isLength({ min: 3 }).withMessage('Nama minimal 3 karakter'),
  body('email').optional().isEmail().withMessage('Email tidak valid'),
  processValidationResult
];

// Validasi untuk change password
export const validateChangePassword = [
  body('oldPassword').isLength({ min: 8 }).withMessage('Password lama minimal 8 karakter'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('Password baru minimal 8 karakter')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
    .withMessage('Password baru harus mengandung huruf besar, huruf kecil, angka, dan karakter spesial'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Konfirmasi password tidak sesuai');
      }
      return true;
    }),
  processValidationResult
];

// Middleware untuk memproses hasil validasi
function processValidationResult(req: Request, res: Response, next: NextFunction) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      errors: errors.array().map((err: any) => ({
        field: err.type === 'field' ? err.path : 'unknown',
        message: err.msg
      }))
    });
  }
  next();
}

// Middleware untuk validasi request menggunakan class-validator
export const validateRequest = (dtoClass: any) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Konversi body request ke instance DTO
    const dtoObject = plainToClass(dtoClass, req.body);

    // Validasi
    const errors = await validate(dtoObject);

    if (errors.length > 0) {
      const formattedErrors = errors.map(error => {
        return {
          field: error.property,
          message: Object.values(error.constraints || {}).join(', ')
        };
      });

      return res.status(400).json({
        status: 'error',
        errors: formattedErrors
      });
    }

    // Simpan data tervalidasi di request
    req.body = dtoObject;
    next();
  };
};

// Fungsi untuk validasi email
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Fungsi untuk validasi password
export const validatePassword = (password: string): boolean => {
  // Minimal 8 karakter, 1 huruf besar, 1 huruf kecil, 1 angka, 1 karakter khusus
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

// Fungsi untuk validasi nomor telepon
export const validatePhone = (phone: string): boolean => {
  // Format: +62xxxxxxxxxx atau 08xxxxxxxxxx
  const phoneRegex = /^(\+62|62|0)8[1-9][0-9]{6,9}$/;
  return phoneRegex.test(phone);
};

// Fungsi untuk validasi URL
export const validateUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

// Fungsi untuk validasi nomor
export const validateNumber = (num: string): boolean => {
  return !isNaN(Number(num));
};

// Fungsi untuk validasi boolean
export const validateBoolean = (bool: any): boolean => {
  return typeof bool === 'boolean' || 
         (typeof bool === 'string' && ['true', 'false'].includes(bool.toLowerCase()));
};

// Fungsi untuk validasi date
export const validateDate = (date: string): boolean => {
  const dateObj = new Date(date);
  return dateObj instanceof Date && !isNaN(dateObj.getTime());
};

// Fungsi untuk validasi UUID
export const validateUuid = (uuid: string): boolean => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

// Fungsi untuk validasi IP address
export const validateIpAddress = (ip: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

// Fungsi untuk validasi credit card number
export const validateCreditCard = (number: string): boolean => {
  // Luhn algorithm
  let sum = 0;
  let isEven = false;
  
  // Loop through values starting from the rightmost digit
  for (let i = number.length - 1; i >= 0; i--) {
    let digit = parseInt(number.charAt(i));

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}; 
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateCreditCard = exports.validateIpAddress = exports.validateUuid = exports.validateDate = exports.validateBoolean = exports.validateNumber = exports.validateUrl = exports.validatePhone = exports.validatePassword = exports.validateEmail = exports.validateRequest = exports.validateChangePassword = exports.validateUpdateProfile = exports.validateRegister = exports.validateLogin = void 0;
const express_validator_1 = require("express-validator");
const class_validator_1 = require("class-validator");
const class_transformer_1 = require("class-transformer");
// Validasi untuk login
exports.validateLogin = [
    (0, express_validator_1.body)('email').isEmail().withMessage('Email tidak valid'),
    (0, express_validator_1.body)('password').isLength({ min: 8 }).withMessage('Password minimal 8 karakter'),
    processValidationResult
];
// Validasi untuk registrasi
exports.validateRegister = [
    (0, express_validator_1.body)('name').trim().isLength({ min: 3 }).withMessage('Nama minimal 3 karakter'),
    (0, express_validator_1.body)('email').isEmail().withMessage('Email tidak valid'),
    (0, express_validator_1.body)('password')
        .isLength({ min: 8 }).withMessage('Password minimal 8 karakter')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
        .withMessage('Password harus mengandung huruf besar, huruf kecil, angka, dan karakter spesial'),
    processValidationResult
];
// Validasi untuk update profile
exports.validateUpdateProfile = [
    (0, express_validator_1.body)('name').optional().trim().isLength({ min: 3 }).withMessage('Nama minimal 3 karakter'),
    (0, express_validator_1.body)('email').optional().isEmail().withMessage('Email tidak valid'),
    processValidationResult
];
// Validasi untuk change password
exports.validateChangePassword = [
    (0, express_validator_1.body)('oldPassword').isLength({ min: 8 }).withMessage('Password lama minimal 8 karakter'),
    (0, express_validator_1.body)('newPassword')
        .isLength({ min: 8 }).withMessage('Password baru minimal 8 karakter')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
        .withMessage('Password baru harus mengandung huruf besar, huruf kecil, angka, dan karakter spesial'),
    (0, express_validator_1.body)('confirmPassword')
        .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
            throw new Error('Konfirmasi password tidak sesuai');
        }
        return true;
    }),
    processValidationResult
];
// Middleware untuk memproses hasil validasi
function processValidationResult(req, res, next) {
    const errors = (0, express_validator_1.validationResult)(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            status: 'error',
            errors: errors.array().map((err) => ({
                field: err.type === 'field' ? err.path : 'unknown',
                message: err.msg
            }))
        });
    }
    next();
}
// Middleware untuk validasi request menggunakan class-validator
const validateRequest = (dtoClass) => {
    return async (req, res, next) => {
        // Konversi body request ke instance DTO
        const dtoObject = (0, class_transformer_1.plainToClass)(dtoClass, req.body);
        // Validasi
        const errors = await (0, class_validator_1.validate)(dtoObject);
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
exports.validateRequest = validateRequest;
// Fungsi untuk validasi email
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
exports.validateEmail = validateEmail;
// Fungsi untuk validasi password
const validatePassword = (password) => {
    // Minimal 8 karakter, 1 huruf besar, 1 huruf kecil, 1 angka, 1 karakter khusus
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
};
exports.validatePassword = validatePassword;
// Fungsi untuk validasi nomor telepon
const validatePhone = (phone) => {
    // Format: +62xxxxxxxxxx atau 08xxxxxxxxxx
    const phoneRegex = /^(\+62|62|0)8[1-9][0-9]{6,9}$/;
    return phoneRegex.test(phone);
};
exports.validatePhone = validatePhone;
// Fungsi untuk validasi URL
const validateUrl = (url) => {
    try {
        new URL(url);
        return true;
    }
    catch (_a) {
        return false;
    }
};
exports.validateUrl = validateUrl;
// Fungsi untuk validasi nomor
const validateNumber = (num) => {
    return !isNaN(Number(num));
};
exports.validateNumber = validateNumber;
// Fungsi untuk validasi boolean
const validateBoolean = (bool) => {
    return typeof bool === 'boolean' ||
        (typeof bool === 'string' && ['true', 'false'].includes(bool.toLowerCase()));
};
exports.validateBoolean = validateBoolean;
// Fungsi untuk validasi date
const validateDate = (date) => {
    const dateObj = new Date(date);
    return dateObj instanceof Date && !isNaN(dateObj.getTime());
};
exports.validateDate = validateDate;
// Fungsi untuk validasi UUID
const validateUuid = (uuid) => {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
};
exports.validateUuid = validateUuid;
// Fungsi untuk validasi IP address
const validateIpAddress = (ip) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};
exports.validateIpAddress = validateIpAddress;
// Fungsi untuk validasi credit card number
const validateCreditCard = (number) => {
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
exports.validateCreditCard = validateCreditCard;

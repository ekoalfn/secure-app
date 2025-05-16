"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeBoolean = exports.sanitizeNumber = exports.sanitizePhone = exports.sanitizeUrl = exports.sanitizeEmail = exports.sanitizeString = exports.sanitizeInput = void 0;
const class_sanitizer_1 = require("class-sanitizer");
const class_transformer_1 = require("class-transformer");
const class_validator_1 = require("class-validator");
// Middleware untuk sanitasi input
const sanitizeInput = (dtoClass) => {
    return async (req, res, next) => {
        // Konversi body request ke instance DTO
        const dtoObject = (0, class_transformer_1.plainToClass)(dtoClass, req.body);
        // Sanitasi input
        (0, class_sanitizer_1.sanitize)(dtoObject);
        // Validasi input
        const errors = await (0, class_validator_1.validate)(dtoObject);
        if (errors.length > 0) {
            return res.status(400).json({
                message: 'Validation failed',
                errors: errors.map((error) => ({
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
exports.sanitizeInput = sanitizeInput;
// Fungsi untuk sanitasi string
const sanitizeString = (input) => {
    return input
        .replace(/[<>]/g, '') // Hapus karakter < dan >
        .replace(/javascript:/gi, '') // Hapus javascript: protocol
        .replace(/on\w+=/gi, '') // Hapus event handlers
        .trim();
};
exports.sanitizeString = sanitizeString;
// Fungsi untuk sanitasi email
const sanitizeEmail = (email) => {
    return email.toLowerCase().trim();
};
exports.sanitizeEmail = sanitizeEmail;
// Fungsi untuk sanitasi URL
const sanitizeUrl = (url) => {
    try {
        const parsedUrl = new URL(url);
        return parsedUrl.toString();
    }
    catch (_a) {
        return '';
    }
};
exports.sanitizeUrl = sanitizeUrl;
// Fungsi untuk sanitasi nomor telepon
const sanitizePhone = (phone) => {
    return phone.replace(/[^0-9+]/g, '');
};
exports.sanitizePhone = sanitizePhone;
// Fungsi untuk sanitasi nomor
const sanitizeNumber = (num) => {
    const parsed = parseFloat(num);
    return isNaN(parsed) ? 0 : parsed;
};
exports.sanitizeNumber = sanitizeNumber;
// Fungsi untuk sanitasi boolean
const sanitizeBoolean = (bool) => {
    if (typeof bool === 'boolean')
        return bool;
    if (typeof bool === 'string') {
        return bool.toLowerCase() === 'true';
    }
    return false;
};
exports.sanitizeBoolean = sanitizeBoolean;

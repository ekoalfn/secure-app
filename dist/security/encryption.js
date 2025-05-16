"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateRandomDate = exports.generateRandomBoolean = exports.generateRandomNumber = exports.generateRandomString = exports.generateToken = exports.verifyPassword = exports.hashPassword = exports.decrypt = exports.encrypt = void 0;
const crypto_1 = __importDefault(require("crypto"));
const bcrypt_1 = __importDefault(require("bcrypt"));
// Konfigurasi enkripsi
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-encryption-key-32-chars-long!!';
const IV_LENGTH = 16; // Untuk AES, ini harus 16 bytes
const SALT_ROUNDS = 10;
// Fungsi untuk mengenkripsi string
const encrypt = (text) => {
    const iv = crypto_1.default.randomBytes(IV_LENGTH);
    const cipher = crypto_1.default.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};
exports.encrypt = encrypt;
// Fungsi untuk mendekripsi string
const decrypt = (text) => {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift() || '', 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto_1.default.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
};
exports.decrypt = decrypt;
// Fungsi untuk hash password
const hashPassword = async (password) => {
    return bcrypt_1.default.hash(password, SALT_ROUNDS);
};
exports.hashPassword = hashPassword;
// Fungsi untuk memverifikasi password
const verifyPassword = async (password, hash) => {
    return bcrypt_1.default.compare(password, hash);
};
exports.verifyPassword = verifyPassword;
// Fungsi untuk generate random token
const generateToken = (length = 32) => {
    return crypto_1.default.randomBytes(length).toString('hex');
};
exports.generateToken = generateToken;
// Fungsi untuk generate random string
const generateRandomString = (length = 16) => {
    return crypto_1.default.randomBytes(length).toString('base64').slice(0, length);
};
exports.generateRandomString = generateRandomString;
// Fungsi untuk generate random number
const generateRandomNumber = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
};
exports.generateRandomNumber = generateRandomNumber;
// Fungsi untuk generate random boolean
const generateRandomBoolean = () => {
    return Math.random() >= 0.5;
};
exports.generateRandomBoolean = generateRandomBoolean;
// Fungsi untuk generate random date
const generateRandomDate = (start, end) => {
    return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
};
exports.generateRandomDate = generateRandomDate;

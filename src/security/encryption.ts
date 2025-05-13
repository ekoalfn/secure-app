import crypto from 'crypto';
import bcrypt from 'bcrypt';

// Konfigurasi enkripsi
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-encryption-key-32-chars-long!!';
const IV_LENGTH = 16; // Untuk AES, ini harus 16 bytes
const SALT_ROUNDS = 10;

// Fungsi untuk mengenkripsi string
export const encrypt = (text: string): string => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Fungsi untuk mendekripsi string
export const decrypt = (text: string): string => {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift() || '', 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

// Fungsi untuk hash password
export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, SALT_ROUNDS);
};

// Fungsi untuk memverifikasi password
export const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

// Fungsi untuk generate random token
export const generateToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

// Fungsi untuk generate random string
export const generateRandomString = (length: number = 16): string => {
  return crypto.randomBytes(length).toString('base64').slice(0, length);
};

// Fungsi untuk generate random number
export const generateRandomNumber = (min: number, max: number): number => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

// Fungsi untuk generate random boolean
export const generateRandomBoolean = (): boolean => {
  return Math.random() >= 0.5;
};

// Fungsi untuk generate random date
export const generateRandomDate = (start: Date, end: Date): Date => {
  return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
}; 
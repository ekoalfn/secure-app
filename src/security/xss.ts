import { Request, Response, NextFunction } from 'express';
import xss from 'xss';
import { AppError } from './errorHandler';

// Konfigurasi XSS
const xssOptions = {
  whiteList: {}, // Tidak ada tag yang diizinkan
  stripIgnoreTag: true, // Hapus tag yang tidak dikenal
  stripIgnoreTagBody: ['script'], // Hapus konten dalam tag script
  css: false // Nonaktifkan CSS sanitization
};

// Middleware untuk XSS protection
export const xssMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Sanitasi body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }

  // Sanitasi query
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }

  // Sanitasi params
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  next();
};

// Fungsi untuk sanitasi object
const sanitizeObject = (obj: any): any => {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }

  const sanitized: any = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      sanitized[key] = xss(value, xssOptions);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeObject(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

// Fungsi untuk sanitasi string
export const sanitizeString = (input: string): string => {
  return xss(input, xssOptions);
};

// Fungsi untuk sanitasi HTML
export const sanitizeHtml = (html: string): string => {
  return xss(html, {
    ...xssOptions,
    whiteList: {
      a: ['href', 'title', 'target'],
      b: [],
      i: [],
      em: [],
      strong: [],
      p: [],
      br: [],
      ul: [],
      ol: [],
      li: [],
      h1: [],
      h2: [],
      h3: [],
      h4: [],
      h5: [],
      h6: []
    }
  });
};

// Fungsi untuk sanitasi URL
export const sanitizeUrl = (url: string): string => {
  try {
    const parsedUrl = new URL(url);
    // Hapus javascript: dan data: protocols
    if (parsedUrl.protocol === 'javascript:' || parsedUrl.protocol === 'data:') {
      return '';
    }
    return parsedUrl.toString();
  } catch {
    return '';
  }
};

// Fungsi untuk sanitasi CSS
export const sanitizeCss = (css: string): string => {
  // Hapus url() yang berisi javascript: atau data:
  return css.replace(/url\(['"]?(javascript:|data:)[^'"]*['"]?\)/gi, '');
};

// Fungsi untuk sanitasi JavaScript
export const sanitizeJs = (js: string): string => {
  // Hapus eval, Function constructor, dan inline event handlers
  return js
    .replace(/eval\s*\(/gi, '')
    .replace(/new\s+Function\s*\(/gi, '')
    .replace(/on\w+\s*=/gi, '');
};

// Fungsi untuk sanitasi JSON
export const sanitizeJson = (json: string): string => {
  try {
    const parsed = JSON.parse(json);
    return JSON.stringify(sanitizeObject(parsed));
  } catch {
    return '{}';
  }
};

// Fungsi untuk sanitasi XML
export const sanitizeXml = (xml: string): string => {
  // Hapus CDATA sections yang berisi script
  return xml.replace(/<!\[CDATA\[.*?\]\]>/gis, '');
};

// Fungsi untuk sanitasi SQL
export const sanitizeSql = (sql: string): string => {
  // Hapus SQL injection patterns
  return sql
    .replace(/--/g, '')
    .replace(/;/g, '')
    .replace(/\/\*.*?\*\//g, '')
    .replace(/UNION\s+ALL/gi, '')
    .replace(/UNION/gi, '')
    .replace(/SELECT/gi, '')
    .replace(/INSERT/gi, '')
    .replace(/UPDATE/gi, '')
    .replace(/DELETE/gi, '')
    .replace(/DROP/gi, '')
    .replace(/TRUNCATE/gi, '');
}; 
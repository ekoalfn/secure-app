"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeSql = exports.sanitizeXml = exports.sanitizeJson = exports.sanitizeJs = exports.sanitizeCss = exports.sanitizeUrl = exports.sanitizeHtml = exports.sanitizeString = exports.xssMiddleware = void 0;
const xss_1 = __importDefault(require("xss"));
// Konfigurasi XSS
const xssOptions = {
    whiteList: {},
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script'],
    css: false // Nonaktifkan CSS sanitization
};
// Middleware untuk XSS protection
const xssMiddleware = (req, res, next) => {
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
exports.xssMiddleware = xssMiddleware;
// Fungsi untuk sanitasi object
const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject);
    }
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            sanitized[key] = (0, xss_1.default)(value, xssOptions);
        }
        else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeObject(value);
        }
        else {
            sanitized[key] = value;
        }
    }
    return sanitized;
};
// Fungsi untuk sanitasi string
const sanitizeString = (input) => {
    return (0, xss_1.default)(input, xssOptions);
};
exports.sanitizeString = sanitizeString;
// Fungsi untuk sanitasi HTML
const sanitizeHtml = (html) => {
    return (0, xss_1.default)(html, {
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
exports.sanitizeHtml = sanitizeHtml;
// Fungsi untuk sanitasi URL
const sanitizeUrl = (url) => {
    try {
        const parsedUrl = new URL(url);
        // Hapus javascript: dan data: protocols
        if (parsedUrl.protocol === 'javascript:' || parsedUrl.protocol === 'data:') {
            return '';
        }
        return parsedUrl.toString();
    }
    catch (_a) {
        return '';
    }
};
exports.sanitizeUrl = sanitizeUrl;
// Fungsi untuk sanitasi CSS
const sanitizeCss = (css) => {
    // Hapus url() yang berisi javascript: atau data:
    return css.replace(/url\(['"]?(javascript:|data:)[^'"]*['"]?\)/gi, '');
};
exports.sanitizeCss = sanitizeCss;
// Fungsi untuk sanitasi JavaScript
const sanitizeJs = (js) => {
    // Hapus eval, Function constructor, dan inline event handlers
    return js
        .replace(/eval\s*\(/gi, '')
        .replace(/new\s+Function\s*\(/gi, '')
        .replace(/on\w+\s*=/gi, '');
};
exports.sanitizeJs = sanitizeJs;
// Fungsi untuk sanitasi JSON
const sanitizeJson = (json) => {
    try {
        const parsed = JSON.parse(json);
        return JSON.stringify(sanitizeObject(parsed));
    }
    catch (_a) {
        return '{}';
    }
};
exports.sanitizeJson = sanitizeJson;
// Fungsi untuk sanitasi XML
const sanitizeXml = (xml) => {
    // Hapus CDATA sections yang berisi script
    return xml.replace(/<!\[CDATA\[.*?\]\]>/gis, '');
};
exports.sanitizeXml = sanitizeXml;
// Fungsi untuk sanitasi SQL
const sanitizeSql = (sql) => {
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
exports.sanitizeSql = sanitizeSql;

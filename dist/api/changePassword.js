"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const csrfProtection_1 = require("../security/csrfProtection");
const router = express_1.default.Router();
router.post('/change-password', (req, res) => {
    // Validasi CSRF token
    const token = req.headers['x-csrf-token'];
    const validation = csrfProtection_1.csrfProtection.validateRequest({
        token: token,
        origin: req.headers.origin,
        body: req.body
    });
    if (!validation.valid) {
        console.log('CSRF Attack Detected:', {
            headers: req.headers,
            body: req.body,
            validation
        });
        return res.status(403).json({
            error: 'CSRF validation failed',
            reason: validation.reason
        });
    }
    // Jika CSRF valid, proses perubahan password
    console.log('Password change request received with valid CSRF token');
    res.json({ success: true, message: 'Password changed successfully' });
});
exports.default = router;

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const router = express_1.default.Router();
// Vulnerable endpoint - tidak ada CSRF protection
router.post('/change-password', (req, res) => {
    // Langsung menerima request tanpa validasi CSRF
    const { newPassword } = req.body;
    console.log('Vulnerable: Password change request received');
    console.log('New password:', newPassword);
    // Simulasi perubahan password
    res.json({
        success: true,
        message: 'Password changed successfully (VULNERABLE!)',
        newPassword: newPassword
    });
});
exports.default = router;

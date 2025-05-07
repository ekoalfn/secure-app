import express from 'express';

const router = express.Router();

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

export default router; 
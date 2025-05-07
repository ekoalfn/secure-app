import express from 'express';
import { csrfProtection } from '../security/csrfProtection';

const router = express.Router();

router.post('/change-password', (req, res) => {
  // Validasi CSRF token
  const token = req.headers['x-csrf-token'];
  const validation = csrfProtection.validateRequest({
    token: token as string,
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

export default router; 
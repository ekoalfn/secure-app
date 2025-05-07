import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import { useCSRFToken, useSecurityMonitoring } from '../security';

const ChangePassword: React.FC = () => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [securityWarnings, setSecurityWarnings] = useState<string[]>([]);
  
  // Enhanced security hooks
  const { getCSRFToken } = useCSRFToken();
  const { logAuthFailure } = useSecurityMonitoring();

  const { changePassword } = useContext(AuthContext);
  const navigate = useNavigate();

  const validatePassword = (password: string): string[] => {
    const warnings: string[] = [];
    
    if (password.length < 12) {
      warnings.push('Password must be at least 12 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
      warnings.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      warnings.push('Password must contain at least one lowercase letter');
    }
    
    if (!/[0-9]/.test(password)) {
      warnings.push('Password must contain at least one number');
    }
    
    if (!/[^A-Za-z0-9]/.test(password)) {
      warnings.push('Password must contain at least one special character');
    }
    
    return warnings;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSecurityWarnings([]);

    // Enhanced password validation
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    const passwordWarnings = validatePassword(newPassword);
    if (passwordWarnings.length > 0) {
      setSecurityWarnings(passwordWarnings);
      return;
    }
    
    // Check for password reuse
    if (currentPassword === newPassword) {
      setError('New password must be different from current password');
      return;
    }

    setLoading(true);

    try {
      // This endpoint now requires a CSRF token (sent automatically in the headers)
      await changePassword(currentPassword, newPassword);
      setSuccess('Password changed successfully!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      
      // Redirect after a short delay
      setTimeout(() => {
        navigate('/profile');
      }, 2000);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to change password. Please try again.';
      setError(errorMessage);
      
      // Log auth failure
      if (errorMessage.includes('Current password is incorrect')) {
        logAuthFailure('user', 'Incorrect current password during password change');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <Navbar />
      <div className="container">
        <div className="auth-form">
          <h2>Change Password</h2>
          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}
          
          {securityWarnings.length > 0 && (
            <div className="warning-message">
              <strong>Password Requirements:</strong>
              <ul>
                {securityWarnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
          
          <form onSubmit={handleSubmit}>
            {/* Hidden CSRF token field */}
            <input type="hidden" name="_csrf" value={getCSRFToken()} />
            
            <div className="form-group">
              <label htmlFor="current-password">Current Password</label>
              <input
                type="password"
                id="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="new-password">New Password</label>
              <input
                type="password"
                id="new-password"
                value={newPassword}
                onChange={(e) => {
                  setNewPassword(e.target.value);
                  // Reset errors when input changes
                  setError('');
                  setSecurityWarnings([]);
                }}
                required
                minLength={12}
              />
              <div className="password-strength-info">
                Strong passwords include uppercase and lowercase letters, numbers, and special characters.
              </div>
            </div>
            <div className="form-group">
              <label htmlFor="confirm-password">Confirm New Password</label>
              <input
                type="password"
                id="confirm-password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  // Reset errors when input changes
                  setError('');
                }}
                required
                minLength={12}
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Changing Password...' : 'Change Password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ChangePassword; 
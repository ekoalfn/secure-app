"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const AuthContext_1 = require("../context/AuthContext");
const Navbar_1 = __importDefault(require("../components/Navbar"));
const security_1 = require("../security");
const ChangePassword = () => {
    const [currentPassword, setCurrentPassword] = (0, react_1.useState)('');
    const [newPassword, setNewPassword] = (0, react_1.useState)('');
    const [confirmPassword, setConfirmPassword] = (0, react_1.useState)('');
    const [error, setError] = (0, react_1.useState)('');
    const [success, setSuccess] = (0, react_1.useState)('');
    const [loading, setLoading] = (0, react_1.useState)(false);
    const [securityWarnings, setSecurityWarnings] = (0, react_1.useState)([]);
    // Enhanced security hooks
    const { getCSRFToken } = (0, security_1.useCSRFToken)();
    const { logAuthFailure } = (0, security_1.useSecurityMonitoring)();
    const { changePassword } = (0, react_1.useContext)(AuthContext_1.AuthContext);
    const navigate = (0, react_router_dom_1.useNavigate)();
    const validatePassword = (password) => {
        const warnings = [];
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
    const handleSubmit = async (e) => {
        var _a, _b;
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
        }
        catch (err) {
            const errorMessage = ((_b = (_a = err.response) === null || _a === void 0 ? void 0 : _a.data) === null || _b === void 0 ? void 0 : _b.message) || 'Failed to change password. Please try again.';
            setError(errorMessage);
            // Log auth failure
            if (errorMessage.includes('Current password is incorrect')) {
                logAuthFailure('user', 'Incorrect current password during password change');
            }
        }
        finally {
            setLoading(false);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "page", children: [(0, jsx_runtime_1.jsx)(Navbar_1.default, {}), (0, jsx_runtime_1.jsx)("div", { className: "container", children: (0, jsx_runtime_1.jsxs)("div", { className: "auth-form", children: [(0, jsx_runtime_1.jsx)("h2", { children: "Change Password" }), error && (0, jsx_runtime_1.jsx)("div", { className: "error-message", children: error }), success && (0, jsx_runtime_1.jsx)("div", { className: "success-message", children: success }), securityWarnings.length > 0 && ((0, jsx_runtime_1.jsxs)("div", { className: "warning-message", children: [(0, jsx_runtime_1.jsx)("strong", { children: "Password Requirements:" }), (0, jsx_runtime_1.jsx)("ul", { children: securityWarnings.map((warning, index) => ((0, jsx_runtime_1.jsx)("li", { children: warning }, index))) })] })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, children: [(0, jsx_runtime_1.jsx)("input", { type: "hidden", name: "_csrf", value: getCSRFToken() }), (0, jsx_runtime_1.jsxs)("div", { className: "form-group", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "current-password", children: "Current Password" }), (0, jsx_runtime_1.jsx)("input", { type: "password", id: "current-password", value: currentPassword, onChange: (e) => setCurrentPassword(e.target.value), required: true })] }), (0, jsx_runtime_1.jsxs)("div", { className: "form-group", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "new-password", children: "New Password" }), (0, jsx_runtime_1.jsx)("input", { type: "password", id: "new-password", value: newPassword, onChange: (e) => {
                                                setNewPassword(e.target.value);
                                                // Reset errors when input changes
                                                setError('');
                                                setSecurityWarnings([]);
                                            }, required: true, minLength: 12 }), (0, jsx_runtime_1.jsx)("div", { className: "password-strength-info", children: "Strong passwords include uppercase and lowercase letters, numbers, and special characters." })] }), (0, jsx_runtime_1.jsxs)("div", { className: "form-group", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "confirm-password", children: "Confirm New Password" }), (0, jsx_runtime_1.jsx)("input", { type: "password", id: "confirm-password", value: confirmPassword, onChange: (e) => {
                                                setConfirmPassword(e.target.value);
                                                // Reset errors when input changes
                                                setError('');
                                            }, required: true, minLength: 12 })] }), (0, jsx_runtime_1.jsx)("button", { type: "submit", disabled: loading, children: loading ? 'Changing Password...' : 'Change Password' })] })] }) })] }));
};
exports.default = ChangePassword;

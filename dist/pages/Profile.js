"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const AuthContext_1 = require("../context/AuthContext");
const Navbar_1 = __importDefault(require("../components/Navbar"));
const dompurify_1 = __importDefault(require("dompurify"));
const security_1 = require("../security");
const SecureHtml_1 = __importDefault(require("../components/SecureHtml"));
const Profile = () => {
    const { user, updateProfile } = (0, react_1.useContext)(AuthContext_1.AuthContext);
    const [bio, setBio] = (0, react_1.useState)('');
    const [website, setWebsite] = (0, react_1.useState)('');
    const [message, setMessage] = (0, react_1.useState)('');
    const [loading, setLoading] = (0, react_1.useState)(false);
    const [comments, setComments] = (0, react_1.useState)([]);
    const [newComment, setNewComment] = (0, react_1.useState)('');
    const [securityWarnings, setSecurityWarnings] = (0, react_1.useState)([]);
    // Enhanced security hooks
    const { checkValue: checkXSS } = (0, security_1.useXSSDetection)();
    const { logValidationFailure } = (0, security_1.useSecurityMonitoring)();
    const { getCSRFToken } = (0, security_1.useCSRFToken)();
    (0, react_1.useEffect)(() => {
        if (user) {
            setBio(user.bio || '');
            setWebsite(user.website || '');
        }
    }, [user]);
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage('');
        setSecurityWarnings([]);
        // Enhanced input validation with security monitoring
        const warnings = [];
        // Check for XSS in bio content
        if (checkXSS(bio)) {
            warnings.push('Potential unsafe content detected in bio field');
            logValidationFailure(bio, 'bio');
        }
        // Validate URL format for website
        if (website && !isValidUrl(website)) {
            warnings.push('Invalid URL format in website field');
            logValidationFailure(website, 'website');
        }
        if (warnings.length > 0) {
            setSecurityWarnings(warnings);
            setLoading(false);
            return;
        }
        try {
            // Include CSRF token (handled automatically by our CSRF protection)
            await updateProfile({ bio, website });
            setMessage('Profile updated successfully!');
        }
        catch (err) {
            setMessage('Failed to update profile. Please try again.');
        }
        finally {
            setLoading(false);
        }
    };
    const addComment = () => {
        if (newComment.trim()) {
            // Enhanced validation and sanitization
            if (checkXSS(newComment)) {
                setSecurityWarnings(['Potentially unsafe content detected in comment']);
                logValidationFailure(newComment, 'comment');
                return;
            }
            const newId = comments.length > 0 ? Math.max(...comments.map(c => c.id)) + 1 : 1;
            // Securely store new comment after sanitizing input
            setComments([...comments, { id: newId, text: dompurify_1.default.sanitize(newComment) }]);
            setNewComment('');
            setSecurityWarnings([]);
        }
    };
    // URL validation helper
    const isValidUrl = (url) => {
        try {
            const parsedUrl = new URL(url);
            return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
        }
        catch (_a) {
            return false;
        }
    };
    // Define sanitization options
    const sanitizeOptions = {
        ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
        ALLOWED_ATTR: ['href', 'target', 'rel'],
        FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
        ALLOW_DATA_ATTR: false
    };
    if (!user) {
        return (0, jsx_runtime_1.jsx)("div", { children: "Loading user data..." });
    }
    return ((0, jsx_runtime_1.jsxs)("div", { className: "page", children: [(0, jsx_runtime_1.jsx)(Navbar_1.default, {}), (0, jsx_runtime_1.jsxs)("div", { className: "container", children: [(0, jsx_runtime_1.jsx)("h1", { children: "User Profile" }), (0, jsx_runtime_1.jsxs)("div", { className: "profile-section", children: [(0, jsx_runtime_1.jsx)("h2", { children: "Basic Information" }), (0, jsx_runtime_1.jsxs)("div", { className: "profile-info", children: [(0, jsx_runtime_1.jsxs)("p", { children: [(0, jsx_runtime_1.jsx)("strong", { children: "Name:" }), " ", user.name] }), (0, jsx_runtime_1.jsxs)("p", { children: [(0, jsx_runtime_1.jsx)("strong", { children: "Email:" }), " ", user.email] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "profile-section", children: [(0, jsx_runtime_1.jsx)("h2", { children: "Edit Profile" }), message && (0, jsx_runtime_1.jsx)("div", { className: "message", children: message }), securityWarnings.length > 0 && ((0, jsx_runtime_1.jsxs)("div", { className: "error-message", children: [(0, jsx_runtime_1.jsx)("strong", { children: "Security Warning:" }), (0, jsx_runtime_1.jsx)("ul", { children: securityWarnings.map((warning, index) => ((0, jsx_runtime_1.jsx)("li", { children: warning }, index))) })] })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, children: [(0, jsx_runtime_1.jsx)("input", { type: "hidden", name: "_csrf", value: getCSRFToken() }), (0, jsx_runtime_1.jsxs)("div", { className: "form-group", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "bio", children: "Bio" }), (0, jsx_runtime_1.jsx)("textarea", { id: "bio", value: bio, onChange: (e) => {
                                                    const value = e.target.value;
                                                    setBio(value);
                                                    // Reset warnings when input changes
                                                    setSecurityWarnings([]);
                                                }, placeholder: "Tell us about yourself" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "form-group", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "website", children: "Website" }), (0, jsx_runtime_1.jsx)("input", { type: "text", id: "website", value: website, onChange: (e) => {
                                                    const value = e.target.value;
                                                    setWebsite(value);
                                                    // Reset warnings when input changes
                                                    setSecurityWarnings([]);
                                                }, placeholder: "Your website URL" })] }), (0, jsx_runtime_1.jsx)("button", { type: "submit", disabled: loading, children: loading ? 'Updating...' : 'Update Profile' })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "profile-section", children: [(0, jsx_runtime_1.jsx)("h2", { children: "Comments" }), (0, jsx_runtime_1.jsxs)("div", { className: "comments-section", children: [(0, jsx_runtime_1.jsxs)("div", { className: "add-comment", children: [(0, jsx_runtime_1.jsx)("textarea", { value: newComment, onChange: (e) => {
                                                    setNewComment(e.target.value);
                                                    // Reset warnings when input changes
                                                    setSecurityWarnings([]);
                                                }, placeholder: "Add a comment..." }), (0, jsx_runtime_1.jsx)("button", { onClick: addComment, children: "Post Comment" })] }), (0, jsx_runtime_1.jsx)("div", { className: "comments-list", children: comments.length > 0 ? (comments.map(comment => ((0, jsx_runtime_1.jsx)("div", { className: "comment", children: (0, jsx_runtime_1.jsx)(SecureHtml_1.default, { content: comment.text, sanitizeOptions: sanitizeOptions, className: "comment-content" }) }, comment.id)))) : ((0, jsx_runtime_1.jsx)("p", { children: "No comments yet." })) })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "profile-section", children: [(0, jsx_runtime_1.jsx)("h2", { children: "Bio Preview" }), (0, jsx_runtime_1.jsx)(SecureHtml_1.default, { content: bio, sanitizeOptions: sanitizeOptions, className: "bio-preview" })] })] })] }));
};
exports.default = Profile;

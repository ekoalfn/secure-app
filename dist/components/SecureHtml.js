"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const sanitizeHtml_1 = __importDefault(require("../utils/sanitizeHtml"));
/**
 * SecureHtml component for safely rendering sanitized HTML content
 * @param props - Component props
 * @returns React element
 */
const SecureHtml = ({ content, sanitizeOptions = {}, className = '' }) => {
    const containerRef = (0, react_1.useRef)(null);
    // Sanitize and render the content
    (0, react_1.useEffect)(() => {
        if (containerRef.current) {
            // First sanitize the HTML
            const sanitizedContent = (0, sanitizeHtml_1.default)(content, sanitizeOptions);
            // Then render it to the DOM
            containerRef.current.innerHTML = sanitizedContent;
        }
    }, [content, sanitizeOptions]);
    return (0, jsx_runtime_1.jsx)("div", { ref: containerRef, className: className });
};
exports.default = SecureHtml;

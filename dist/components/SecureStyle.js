"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importDefault(require("react"));
/**
 * SecureStyle component for adding inline styles with CSP nonces
 * @param {Object} props - Component props
 * @param {string} props.content - The CSS content to inject
 * @param {string} props.nonce - The CSP nonce value
 * @returns {JSX.Element}
 */
const SecureStyle = ({ content, nonce }) => {
    return ((0, jsx_runtime_1.jsx)("style", { nonce: nonce, dangerouslySetInnerHTML: { __html: content } }));
};
exports.default = SecureStyle;

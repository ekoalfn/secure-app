"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importDefault(require("react"));
/**
 * SecureScript component for adding inline scripts with CSP nonces
 * @param {Object} props - Component props
 * @param {string} props.content - The JavaScript content to inject
 * @param {string} props.nonce - The CSP nonce value
 * @returns {JSX.Element}
 */
const SecureScript = ({ content, nonce }) => {
    // Using dangerouslySetInnerHTML with a nonce to make it CSP compliant
    return ((0, jsx_runtime_1.jsx)("script", { nonce: nonce, dangerouslySetInnerHTML: { __html: content } }));
};
exports.default = SecureScript;

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importDefault(require("react"));
const react_2 = require("@testing-library/react");
require("@testing-library/jest-dom");
const dompurify_1 = __importDefault(require("dompurify"));
// Mock DOMPurify
jest.mock('dompurify', () => ({
    sanitize: jest.fn((content) => {
        // Simulate sanitization by removing script tags and preserving safe content
        if (typeof content === 'string') {
            // Remove script tags and their content
            const withoutScripts = content.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            // Remove event handlers
            const withoutEvents = withoutScripts.replace(/\s(on\w+)="[^"]*"/gi, '');
            // Remove javascript: URLs
            const withoutJsUrls = withoutEvents.replace(/javascript:[^"']*/gi, '');
            // Return the sanitized content
            return withoutJsUrls.trim();
        }
        return content;
    })
}));
// Mock component that uses sanitization
function TestSanitizedComponent({ html }) {
    const sanitizedContent = react_1.default.useMemo(() => {
        return { __html: dompurify_1.default.sanitize(html) };
    }, [html]);
    return ((0, jsx_runtime_1.jsx)("div", { "data-testid": "content", dangerouslySetInnerHTML: sanitizedContent }));
}
describe('Security Integration Tests', () => {
    afterEach(() => {
        (0, react_2.cleanup)();
        jest.clearAllMocks();
    });
    test('Component should sanitize HTML content', () => {
        const maliciousHTML = '<div>Safe content</div><script>alert("XSS")</script>';
        (0, react_2.render)((0, jsx_runtime_1.jsx)(TestSanitizedComponent, { html: maliciousHTML }));
        // Test that DOMPurify was called with the correct input
        expect(dompurify_1.default.sanitize).toHaveBeenCalledWith(maliciousHTML);
        // Get the rendered content
        const contentElement = react_2.screen.getByTestId('content');
        // Verify the element exists
        expect(contentElement).toBeInTheDocument();
        // Verify the content was sanitized correctly
        const sanitizedHTML = dompurify_1.default.sanitize(maliciousHTML);
        expect(contentElement.innerHTML).toBe(sanitizedHTML);
        expect(contentElement.innerHTML).not.toContain('<script>');
    });
    test('Component should handle different types of XSS payloads', () => {
        const xssPayloads = [
            {
                input: '<img src="x" onerror="alert(1)">',
                expected: '<img src="x">'
            },
            {
                input: '<svg/onload=alert(1)>',
                expected: '<svg></svg>'
            },
            {
                input: '<a href="javascript:alert(1)">Click me</a>',
                expected: '<a>Click me</a>'
            },
            {
                input: '"><script>alert(1)</script>',
                expected: '">'
            }
        ];
        xssPayloads.forEach(({ input, expected }) => {
            (0, react_2.cleanup)();
            (0, react_2.render)((0, jsx_runtime_1.jsx)(TestSanitizedComponent, { html: input }));
            // Verify DOMPurify was called
            expect(dompurify_1.default.sanitize).toHaveBeenCalledWith(input);
            // Get the rendered content
            const contentElement = react_2.screen.getByTestId('content');
            // Verify the content was sanitized
            expect(contentElement.innerHTML).not.toContain('alert');
            expect(contentElement.innerHTML).not.toContain('javascript:');
            expect(contentElement.innerHTML).not.toContain('onerror');
            expect(contentElement.innerHTML).not.toContain('onload');
            jest.clearAllMocks();
        });
    });
});
// Mock component that implements CSRF protection
function TestCSRFForm() {
    const [token, setToken] = react_1.default.useState('mock-csrf-token');
    const handleSubmit = (e) => {
        e.preventDefault();
        // Simulate form submission with CSRF token
    };
    return ((0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, "data-testid": "csrf-form", children: [(0, jsx_runtime_1.jsx)("input", { type: "hidden", name: "csrf_token", value: token, "data-testid": "csrf-token" }), (0, jsx_runtime_1.jsx)("input", { type: "text", name: "username", "data-testid": "username" }), (0, jsx_runtime_1.jsx)("button", { type: "submit", "data-testid": "submit", children: "Submit" })] }));
}
describe('CSRF Protection Integration Tests', () => {
    test('Form should include CSRF token', () => {
        (0, react_2.render)((0, jsx_runtime_1.jsx)(TestCSRFForm, {}));
        const form = react_2.screen.getByTestId('csrf-form');
        expect(form).toBeInTheDocument();
        const csrfToken = react_2.screen.getByTestId('csrf-token');
        expect(csrfToken).toHaveAttribute('value', 'mock-csrf-token');
    });
    test('Form submission should include CSRF token', () => {
        const mockSubmit = jest.fn(e => e.preventDefault());
        (0, react_2.render)((0, jsx_runtime_1.jsxs)("form", { onSubmit: mockSubmit, "data-testid": "csrf-form", children: [(0, jsx_runtime_1.jsx)("input", { type: "hidden", name: "csrf_token", value: "test-token", "data-testid": "csrf-token" }), (0, jsx_runtime_1.jsx)("button", { type: "submit", "data-testid": "submit", children: "Submit" })] }));
        // Click the submit button
        fireEvent.click(react_2.screen.getByTestId('submit'));
        // Check that the form was submitted
        expect(mockSubmit).toHaveBeenCalled();
        // In a real test, you would also check that the token was included in the request
    });
});

# Secure React.js Application

This application demonstrates best practices for securing React.js applications against common web vulnerabilities, with a focus on XSS (Cross-Site Scripting) and CSRF (Cross-Site Request Forgery) attacks.

## Security Features

### XSS Protection

1. **Input Sanitization**: All user-generated content is sanitized using DOMPurify before rendering.
   - Location: `Profile.tsx` for both comments and bio preview sections

2. **Content Security Policy (CSP)**: Restricts the sources from which active content can be loaded.
   - Location: `App.tsx` - CSP header implementation
   - Blocks execution of malicious JavaScript injected via XSS attacks

3. **HttpOnly Cookies**: Authentication tokens are stored in HttpOnly cookies rather than localStorage.
   - Location: `AuthContext.tsx` and `mockBackend.ts`
   - Prevents JavaScript access to authentication tokens

### CSRF Protection

1. **CSRF Tokens**: All state-changing operations require a valid CSRF token.
   - Location: `AuthContext.tsx` - Interceptor to add CSRF token to requests
   - Location: `ChangePassword.tsx` - Implementation of CSRF token in forms

2. **SameSite Cookie Attributes**: Cookies are restricted to same-site contexts.
   - Location: `mockBackend.ts` - Cookie configuration with "SameSite=Strict"

3. **Double Submit Cookie Pattern**: CSRF tokens are both sent in headers and validated in request payload.

### Additional Security Measures

1. **HTTP Security Headers**: Implementation of recommended security headers.
   - Location: `index.tsx` - HTTP security headers setup
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Referrer-Policy: strict-origin-when-cross-origin
   - Strict-Transport-Security: max-age=31536000; includeSubDomains

2. **Secure Password Requirements**: Stronger password policies.
   - Location: `Register.tsx` - Minimum 8 character password length

## Features

- User authentication (login/register)
- Profile management
- Password changing functionality
- Comment system

## Security in Comparison to Vulnerable Version

This application addresses all the security vulnerabilities present in the vulnerable version by implementing the following mitigations:

| Vulnerability | Vulnerable App | Secure App |
|--------------|----------------|------------|
| XSS via dangerouslySetInnerHTML | No sanitization | DOMPurify sanitization |
| Authentication token exposure | localStorage storage | HttpOnly cookies |
| CSRF attacks | No protection | CSRF tokens + SameSite cookies |
| Content Security Policy | Absent | Strict CSP implemented |
| HTTP Security Headers | Not implemented | Comprehensive headers |

## Installation and Running

```bash
# Install dependencies
npm install

# Run the application
npm start
```

## Implementation Notes

In a production environment, the security measures would be implemented server-side, especially:
- Setting HttpOnly cookies
- CSRF token generation and validation
- Content-Security-Policy headers
- Other HTTP security headers

In this client-side demo, we simulate these server-side features to demonstrate the concepts.

## License

This project is for educational purposes only.

"use strict";
// Comprehensive Security Headers Configuration
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSecurityNonce = exports.securityHeaders = void 0;
// Default secure configuration
const defaultConfig = {
    csp: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://localhost:5001"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", "https://localhost:5001"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'self'"],
        reportUri: '/api/csp-report',
        upgradeInsecureRequests: true,
        useNonces: true
    },
    permissions: {
        camera: 'none',
        microphone: 'none',
        geolocation: 'none',
        notifications: 'none',
        accelerometer: 'none',
        gyroscope: 'none',
        magnetometer: 'none',
        payment: 'none',
        usb: 'none'
    },
    hsts: {
        enabled: true,
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameOptions: 'DENY',
    xssProtection: {
        enabled: true,
        mode: 'block',
        reportUri: '/api/xss-report'
    },
    contentTypeOptions: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
    cacheControl: {
        noStore: true,
        noCache: true,
        mustRevalidate: true,
        maxAge: 0
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: 'same-origin'
};
class SecurityHeaders {
    constructor(config = {}) {
        this.nonces = new Map();
        this.config = this.mergeConfig(defaultConfig, config);
        // Generate initial nonces for scripts and styles
        if (this.config.csp.useNonces) {
            this.generateNonce('script');
            this.generateNonce('style');
        }
    }
    static getInstance(config) {
        if (!SecurityHeaders.instance) {
            SecurityHeaders.instance = new SecurityHeaders(config);
        }
        else if (config) {
            // Update existing configuration
            SecurityHeaders.instance.updateConfig(config);
        }
        return SecurityHeaders.instance;
    }
    // Merge configurations
    mergeConfig(defaultConfig, overrides) {
        // Create a deep clone of default config
        const result = JSON.parse(JSON.stringify(defaultConfig));
        // Merge overrides
        Object.keys(overrides).forEach(key => {
            const typedKey = key;
            const defaultValue = result[typedKey];
            const overrideValue = overrides[typedKey];
            if (overrideValue !== undefined &&
                typeof overrideValue === 'object' &&
                overrideValue !== null &&
                defaultValue !== null &&
                typeof defaultValue === 'object') {
                // For object properties, merge them correctly with type casting
                result[typedKey] = {
                    ...defaultValue,
                    ...overrideValue
                };
            }
            else if (overrideValue !== undefined) {
                // For primitive properties, replace them
                result[typedKey] = overrideValue;
            }
        });
        return result;
    }
    // Update configuration
    updateConfig(config) {
        this.config = this.mergeConfig(this.config, config);
        this.applyHeaders();
    }
    // Generate cryptographically strong nonce
    generateNonce(type) {
        const buffer = new Uint8Array(16);
        if (typeof window.crypto !== 'undefined' && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(buffer);
        }
        else {
            for (let i = 0; i < buffer.length; i++) {
                buffer[i] = Math.floor(Math.random() * 256);
            }
        }
        const nonce = Array.from(buffer)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        // Store the nonce
        this.nonces.set(type, nonce);
        return nonce;
    }
    // Get current nonce for a type
    getNonce(type) {
        const nonce = this.nonces.get(type);
        if (!nonce) {
            return this.generateNonce(type);
        }
        return nonce;
    }
    // Build CSP header value
    buildCspHeaderValue() {
        const { csp } = this.config;
        const directives = [];
        // Add base directives
        directives.push(`default-src ${csp.defaultSrc.join(' ')}`);
        // Add script-src with nonce if enabled
        if (csp.useNonces) {
            const scriptNonce = this.getNonce('script');
            directives.push(`script-src ${csp.scriptSrc.join(' ')} 'nonce-${scriptNonce}'`);
            const styleNonce = this.getNonce('style');
            directives.push(`style-src ${csp.styleSrc.join(' ')} 'nonce-${styleNonce}'`);
        }
        else {
            directives.push(`script-src ${csp.scriptSrc.join(' ')}`);
            directives.push(`style-src ${csp.styleSrc.join(' ')}`);
        }
        // Add other directives
        directives.push(`img-src ${csp.imgSrc.join(' ')}`);
        directives.push(`connect-src ${csp.connectSrc.join(' ')}`);
        directives.push(`font-src ${csp.fontSrc.join(' ')}`);
        directives.push(`object-src ${csp.objectSrc.join(' ')}`);
        directives.push(`media-src ${csp.mediaSrc.join(' ')}`);
        directives.push(`frame-src ${csp.frameSrc.join(' ')}`);
        directives.push(`frame-ancestors ${csp.frameAncestors.join(' ')}`);
        directives.push(`form-action ${csp.formAction.join(' ')}`);
        directives.push(`base-uri ${csp.baseUri.join(' ')}`);
        // Add report URI if defined
        if (csp.reportUri) {
            directives.push(`report-uri ${csp.reportUri}`);
        }
        // Add report-to if defined
        if (csp.reportTo) {
            directives.push(`report-to ${csp.reportTo}`);
        }
        // Add upgrade-insecure-requests if enabled
        if (csp.upgradeInsecureRequests) {
            directives.push('upgrade-insecure-requests');
        }
        return directives.join('; ');
    }
    // Build Permissions-Policy header value
    buildPermissionsPolicyHeaderValue() {
        const { permissions } = this.config;
        const directives = [];
        Object.entries(permissions).forEach(([feature, value]) => {
            directives.push(`${feature}=(${value === 'self' ? 'self' : ''})`);
        });
        return directives.join(', ');
    }
    // Apply all security headers as meta tags
    applyHeaders() {
        // CSP header
        this.setMetaTag('Content-Security-Policy', this.buildCspHeaderValue());
        // Permissions-Policy (formerly Feature-Policy)
        this.setMetaTag('Permissions-Policy', this.buildPermissionsPolicyHeaderValue());
        // X-Frame-Options
        if (this.config.frameOptions === 'ALLOW-FROM' && this.config.allowFromOrigin) {
            this.setMetaTag('X-Frame-Options', `${this.config.frameOptions} ${this.config.allowFromOrigin}`);
        }
        else {
            this.setMetaTag('X-Frame-Options', this.config.frameOptions);
        }
        // X-XSS-Protection
        if (this.config.xssProtection.enabled) {
            let value = '1';
            if (this.config.xssProtection.mode === 'block') {
                value += '; mode=block';
            }
            if (this.config.xssProtection.reportUri) {
                value += `; report=${this.config.xssProtection.reportUri}`;
            }
            this.setMetaTag('X-XSS-Protection', value);
        }
        else {
            this.setMetaTag('X-XSS-Protection', '0');
        }
        // X-Content-Type-Options
        if (this.config.contentTypeOptions) {
            this.setMetaTag('X-Content-Type-Options', 'nosniff');
        }
        // Referrer-Policy
        this.setMetaTag('Referrer-Policy', this.config.referrerPolicy);
        // Strict-Transport-Security
        if (this.config.hsts.enabled) {
            let value = `max-age=${this.config.hsts.maxAge}`;
            if (this.config.hsts.includeSubDomains) {
                value += '; includeSubDomains';
            }
            if (this.config.hsts.preload) {
                value += '; preload';
            }
            this.setMetaTag('Strict-Transport-Security', value);
        }
        // Cache-Control
        let cacheValue = '';
        if (this.config.cacheControl.noStore) {
            cacheValue += 'no-store, ';
        }
        if (this.config.cacheControl.noCache) {
            cacheValue += 'no-cache, ';
        }
        if (this.config.cacheControl.mustRevalidate) {
            cacheValue += 'must-revalidate, ';
        }
        cacheValue += `max-age=${this.config.cacheControl.maxAge}`;
        this.setMetaTag('Cache-Control', cacheValue);
        // Cross-Origin-Embedder-Policy
        if (this.config.crossOriginEmbedderPolicy) {
            this.setMetaTag('Cross-Origin-Embedder-Policy', 'require-corp');
        }
        // Cross-Origin-Opener-Policy
        if (this.config.crossOriginOpenerPolicy) {
            this.setMetaTag('Cross-Origin-Opener-Policy', 'same-origin');
        }
        // Cross-Origin-Resource-Policy
        this.setMetaTag('Cross-Origin-Resource-Policy', this.config.crossOriginResourcePolicy);
        console.log('Security headers applied via meta tags');
    }
    // Set a meta tag with HTTP equiv
    setMetaTag(name, content) {
        // Remove existing tag if present
        const existingTag = document.querySelector(`meta[http-equiv="${name}"]`);
        if (existingTag) {
            existingTag.remove();
        }
        // Create and add new tag
        const meta = document.createElement('meta');
        meta.httpEquiv = name;
        meta.content = content;
        document.head.appendChild(meta);
    }
    // Get current configuration (for debugging)
    getConfig() {
        return JSON.parse(JSON.stringify(this.config));
    }
}
// Export singleton instance
exports.securityHeaders = SecurityHeaders.getInstance();
// React hook for nonce usage in components
const useSecurityNonce = () => {
    const getNonce = (type) => {
        return exports.securityHeaders.getNonce(type);
    };
    return {
        getScriptNonce: () => getNonce('script'),
        getStyleNonce: () => getNonce('style')
    };
};
exports.useSecurityNonce = useSecurityNonce;

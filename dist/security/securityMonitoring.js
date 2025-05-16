"use strict";
// Security Monitoring and Telemetry
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSecurityMonitoring = exports.securityEvents = exports.securityMonitor = void 0;
class SecurityMonitor {
    constructor() {
        this.events = [];
        this.alertCallbacks = [];
        this.reportingEndpoint = null;
        this.anomalyThresholds = {
            'xss-attempt': 3,
            'csrf-validation-failure': 2,
            'authentication-failure': 5,
            'suspicious-activity': 2,
            'input-validation-failure': 5,
            'rate-limit-exceeded': 3,
            'permission-violation': 1
        };
        this.eventCounts = {
            'xss-attempt': 0,
            'csrf-validation-failure': 0,
            'authentication-failure': 0,
            'suspicious-activity': 0,
            'input-validation-failure': 0,
            'rate-limit-exceeded': 0,
            'permission-violation': 0
        };
        this.isEnabled = true;
        // Reset event counts every hour
        setInterval(() => this.resetEventCounts(), 60 * 60 * 1000);
    }
    static getInstance() {
        if (!SecurityMonitor.instance) {
            SecurityMonitor.instance = new SecurityMonitor();
        }
        return SecurityMonitor.instance;
    }
    // Enable or disable monitoring
    setEnabled(enabled) {
        this.isEnabled = enabled;
    }
    // Set reporting endpoint
    setReportingEndpoint(endpoint) {
        this.reportingEndpoint = endpoint;
    }
    // Log a security event
    logEvent(event) {
        if (!this.isEnabled)
            return;
        const timestamp = new Date().toISOString();
        const fullEvent = {
            ...event,
            timestamp,
            url: event.url || window.location.href
        };
        // Add to local storage
        this.events.push(fullEvent);
        // Keep only the last 100 events
        if (this.events.length > 100) {
            this.events.shift();
        }
        // Increment event count
        this.eventCounts[event.type]++;
        // Check for anomalies
        this.checkForAnomalies(event.type);
        // Report if endpoint is configured
        if (this.reportingEndpoint) {
            this.reportEvent(fullEvent);
        }
        // Log to console in development
        if (process.env.NODE_ENV === 'development') {
            console.warn('Security event:', fullEvent);
        }
    }
    // Get all logged events
    getEvents() {
        return [...this.events];
    }
    // Clear event log
    clearEvents() {
        this.events = [];
    }
    // Register for alerts on high severity events
    onAlert(callback) {
        this.alertCallbacks.push(callback);
        return () => {
            this.alertCallbacks = this.alertCallbacks.filter(cb => cb !== callback);
        };
    }
    // Set custom anomaly thresholds
    setAnomalyThresholds(thresholds) {
        this.anomalyThresholds = { ...this.anomalyThresholds, ...thresholds };
    }
    // Reset event counters
    resetEventCounts() {
        Object.keys(this.eventCounts).forEach(key => {
            this.eventCounts[key] = 0;
        });
    }
    // Check for anomalies based on event frequency
    checkForAnomalies(eventType) {
        const threshold = this.anomalyThresholds[eventType] || 5;
        if (this.eventCounts[eventType] >= threshold) {
            const anomalyEvent = {
                type: 'suspicious-activity',
                timestamp: new Date().toISOString(),
                severity: 'high',
                description: `Anomaly detected: ${eventType} threshold exceeded`,
                metadata: {
                    eventType,
                    count: this.eventCounts[eventType],
                    threshold
                },
                url: window.location.href
            };
            // Trigger alerts
            this.triggerAlerts(anomalyEvent);
            // Reset this counter to prevent repeated alerts
            this.eventCounts[eventType] = 0;
        }
    }
    // Trigger alert callbacks
    triggerAlerts(event) {
        if (event.severity === 'high' || event.severity === 'critical') {
            this.alertCallbacks.forEach(callback => {
                try {
                    callback(event);
                }
                catch (e) {
                    console.error('Error in security alert callback:', e);
                }
            });
        }
    }
    // Report event to configured endpoint
    reportEvent(event) {
        if (!this.reportingEndpoint)
            return;
        try {
            const data = JSON.stringify(event);
            // Use beacon API for reliable delivery
            if (navigator.sendBeacon) {
                navigator.sendBeacon(this.reportingEndpoint, data);
            }
            else {
                // Fallback to fetch
                fetch(this.reportingEndpoint, {
                    method: 'POST',
                    body: data,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    keepalive: true
                }).catch(e => console.error('Security event reporting failed:', e));
            }
        }
        catch (e) {
            console.error('Error reporting security event:', e);
        }
    }
}
// Export singleton instance
exports.securityMonitor = SecurityMonitor.getInstance();
// Helper functions for common security events
exports.securityEvents = {
    // Log XSS attempt
    logXssAttempt: (payload, element) => {
        exports.securityMonitor.logEvent({
            type: 'xss-attempt',
            severity: 'high',
            description: 'Potential XSS attack detected',
            metadata: {
                payload: payload.substring(0, 500),
                element
            }
        });
    },
    // Log CSRF failure
    logCsrfFailure: (token, origin) => {
        exports.securityMonitor.logEvent({
            type: 'csrf-validation-failure',
            severity: 'high',
            description: 'CSRF token validation failed',
            metadata: {
                tokenPresent: !!token,
                origin
            }
        });
    },
    // Log authentication failure
    logAuthFailure: (username, reason) => {
        exports.securityMonitor.logEvent({
            type: 'authentication-failure',
            severity: 'medium',
            description: 'Authentication attempt failed',
            metadata: {
                username,
                reason
            }
        });
    },
    // Log input validation failure
    logValidationFailure: (input, field) => {
        exports.securityMonitor.logEvent({
            type: 'input-validation-failure',
            severity: 'medium',
            description: 'Input validation failed',
            metadata: {
                field,
                inputExcerpt: input.substring(0, 100) // Limit input size
            }
        });
    },
    // Log permission violation
    logPermissionViolation: (action, resource, userId) => {
        exports.securityMonitor.logEvent({
            type: 'permission-violation',
            severity: 'high',
            description: 'Unauthorized action attempt',
            metadata: {
                action,
                resource
            },
            userId
        });
    }
};
// React hook for security monitoring in components
const useSecurityMonitoring = () => {
    return {
        logSecurityEvent: exports.securityMonitor.logEvent.bind(exports.securityMonitor),
        ...exports.securityEvents
    };
};
exports.useSecurityMonitoring = useSecurityMonitoring;

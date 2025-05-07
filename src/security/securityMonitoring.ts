// Security Monitoring and Telemetry

type SecurityEventType = 
  | 'xss-attempt'
  | 'csrf-validation-failure'
  | 'authentication-failure'
  | 'suspicious-activity'
  | 'input-validation-failure'
  | 'rate-limit-exceeded'
  | 'permission-violation';

interface SecurityEvent {
  type: SecurityEventType;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  metadata?: Record<string, any>;
  url?: string;
  userId?: string;
  ip?: string;
}

type AlertCallback = (event: SecurityEvent) => void;

class SecurityMonitor {
  private static instance: SecurityMonitor;
  private events: SecurityEvent[] = [];
  private alertCallbacks: AlertCallback[] = [];
  private reportingEndpoint: string | null = null;
  private anomalyThresholds: Record<SecurityEventType, number> = {
    'xss-attempt': 3,
    'csrf-validation-failure': 2,
    'authentication-failure': 5,
    'suspicious-activity': 2,
    'input-validation-failure': 5,
    'rate-limit-exceeded': 3,
    'permission-violation': 1
  };
  private eventCounts: Record<SecurityEventType, number> = {
    'xss-attempt': 0,
    'csrf-validation-failure': 0,
    'authentication-failure': 0,
    'suspicious-activity': 0,
    'input-validation-failure': 0,
    'rate-limit-exceeded': 0,
    'permission-violation': 0
  };
  private isEnabled: boolean = true;

  private constructor() {
    // Reset event counts every hour
    setInterval(() => this.resetEventCounts(), 60 * 60 * 1000);
  }

  public static getInstance(): SecurityMonitor {
    if (!SecurityMonitor.instance) {
      SecurityMonitor.instance = new SecurityMonitor();
    }
    return SecurityMonitor.instance;
  }

  // Enable or disable monitoring
  public setEnabled(enabled: boolean): void {
    this.isEnabled = enabled;
  }

  // Set reporting endpoint
  public setReportingEndpoint(endpoint: string | null): void {
    this.reportingEndpoint = endpoint;
  }

  // Log a security event
  public logEvent(event: Omit<SecurityEvent, 'timestamp'>): void {
    if (!this.isEnabled) return;

    const timestamp = new Date().toISOString();
    const fullEvent: SecurityEvent = {
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
  public getEvents(): SecurityEvent[] {
    return [...this.events];
  }

  // Clear event log
  public clearEvents(): void {
    this.events = [];
  }

  // Register for alerts on high severity events
  public onAlert(callback: AlertCallback): () => void {
    this.alertCallbacks.push(callback);
    return () => {
      this.alertCallbacks = this.alertCallbacks.filter(cb => cb !== callback);
    };
  }

  // Set custom anomaly thresholds
  public setAnomalyThresholds(thresholds: Partial<Record<SecurityEventType, number>>): void {
    this.anomalyThresholds = { ...this.anomalyThresholds, ...thresholds };
  }

  // Reset event counters
  private resetEventCounts(): void {
    Object.keys(this.eventCounts).forEach(key => {
      this.eventCounts[key as SecurityEventType] = 0;
    });
  }

  // Check for anomalies based on event frequency
  private checkForAnomalies(eventType: SecurityEventType): void {
    const threshold = this.anomalyThresholds[eventType] || 5;
    
    if (this.eventCounts[eventType] >= threshold) {
      const anomalyEvent: SecurityEvent = {
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
  private triggerAlerts(event: SecurityEvent): void {
    if (event.severity === 'high' || event.severity === 'critical') {
      this.alertCallbacks.forEach(callback => {
        try {
          callback(event);
        } catch (e) {
          console.error('Error in security alert callback:', e);
        }
      });
    }
  }

  // Report event to configured endpoint
  private reportEvent(event: SecurityEvent): void {
    if (!this.reportingEndpoint) return;
    
    try {
      const data = JSON.stringify(event);
      
      // Use beacon API for reliable delivery
      if (navigator.sendBeacon) {
        navigator.sendBeacon(this.reportingEndpoint, data);
      } else {
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
    } catch (e) {
      console.error('Error reporting security event:', e);
    }
  }
}

// Export singleton instance
export const securityMonitor = SecurityMonitor.getInstance();

// Helper functions for common security events
export const securityEvents = {
  // Log XSS attempt
  logXssAttempt: (payload: string, element?: string) => {
    securityMonitor.logEvent({
      type: 'xss-attempt',
      severity: 'high',
      description: 'Potential XSS attack detected',
      metadata: {
        payload: payload.substring(0, 500), // Limit payload size
        element
      }
    });
  },
  
  // Log CSRF failure
  logCsrfFailure: (token?: string, origin?: string) => {
    securityMonitor.logEvent({
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
  logAuthFailure: (username: string, reason: string) => {
    securityMonitor.logEvent({
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
  logValidationFailure: (input: string, field: string) => {
    securityMonitor.logEvent({
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
  logPermissionViolation: (action: string, resource: string, userId?: string) => {
    securityMonitor.logEvent({
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
export const useSecurityMonitoring = () => {
  return {
    logSecurityEvent: securityMonitor.logEvent.bind(securityMonitor),
    ...securityEvents
  };
}; 
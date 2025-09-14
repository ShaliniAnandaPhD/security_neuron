// Fixed Insufficient Logging & Monitoring vulnerability
// Generated: 2025-09-14T09:09:45.934Z

export class SecurityLogger {
  private static logLevels = {
    INFO: 'info',
    WARN: 'warn',
    ERROR: 'error',
    CRITICAL: 'critical'
  };
  
  static logSecurityEvent(event: string, details: any, level = 'info') {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      level,
      details: this.sanitizeLogData(details),
      ip: details.ip || 'unknown',
      userAgent: details.userAgent || 'unknown',
      userId: details.userId || 'anonymous'
    };
    
    // Send to monitoring system
    console.log('[SECURITY]', JSON.stringify(logEntry));
    
    // Alert on critical events
    if (level === 'critical') {
      this.sendAlert(logEntry);
    }
  }
  
  static logLoginAttempt(success: boolean, details: any) {
    this.logSecurityEvent(
      success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
      details,
      success ? 'info' : 'warn'
    );
  }
  
  static logAccessViolation(details: any) {
    this.logSecurityEvent('ACCESS_VIOLATION', details, 'critical');
  }
  
  private static sanitizeLogData(data: any) {
    const { password, token, ...safe } = data;
    return safe;
  }
  
  private static sendAlert(logEntry: any) {
    // Integration with alerting system
    console.error('[SECURITY ALERT]', logEntry);
  }
}
// Fixed Sensitive Data Exposure vulnerability
// Generated: 2025-09-14T08:49:04.173Z

export class DataFilter {
  private static sensitiveFields = [
    'password', 'ssn', 'creditCard', 'apiKey', 
    'privateKey', 'bankAccount', 'pin'
  ];
  
  static sanitizeUser(user: any) {
    const { password, ssn, ...safeUser } = user;
    return safeUser;
  }
  
  static sanitizeObject(obj: any): any {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const sanitized = Array.isArray(obj) ? [] : {};
    
    for (const key in obj) {
      if (this.sensitiveFields.includes(key.toLowerCase())) {
        continue; // Skip sensitive fields
      }
      
      if (typeof obj[key] === 'object') {
        sanitized[key] = this.sanitizeObject(obj[key]);
      } else {
        sanitized[key] = obj[key];
      }
    }
    
    return sanitized;
  }
  
  static sanitizeApiResponse(data: any) {
    return this.sanitizeObject(data);
  }
}
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
  
  // Fixed by AI: Automatic sanitization of API responses
  static sanitizeApiResponse(data: any) {
    return this.sanitizeObject(data);
  }
}
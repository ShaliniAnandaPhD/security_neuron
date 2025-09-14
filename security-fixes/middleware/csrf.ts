// Fixed CSRF vulnerability
// Generated: 2025-09-14T08:49:04.173Z

import crypto from 'crypto';

export class CSRFProtection {
  private static tokens = new Map<string, string>();
  
  static generateToken(sessionId: string): string {
    const token = crypto.randomBytes(32).toString('hex');
    this.tokens.set(sessionId, token);
    return token;
  }
  
  static validateToken(sessionId: string, token: string): boolean {
    const storedToken = this.tokens.get(sessionId);
    if (!storedToken || storedToken !== token) {
      return false;
    }
    this.tokens.delete(sessionId); // One-time use
    return true;
  }
  
  static middleware(req: any, res: any, next: any) {
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
      const token = req.headers['x-csrf-token'];
      const sessionId = req.session?.id;
      
      if (!token || !this.validateToken(sessionId, token)) {
        return res.status(403).json({ error: 'CSRF token invalid' });
      }
    }
    next();
  }
}
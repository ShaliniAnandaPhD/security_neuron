// Fixed Authentication Bypass vulnerability
// Generated: 2025-09-14T08:49:04.173Z

import jwt from 'jsonwebtoken';

export class AuthMiddleware {
  static validateToken(token: string): boolean {
    try {
      // Before: No proper validation
      // After: Comprehensive JWT validation
      const decoded = jwt.verify(token, process.env.JWT_SECRET!);
      
      // Additional checks
      if (!decoded || typeof decoded !== 'object') return false;
      if (decoded.exp && decoded.exp < Date.now() / 1000) return false;
      
      return true;
    } catch (error) {
      console.error('Token validation failed:', error);
      return false;
    }
  }
  
  static requireAuth(req: any, res: any, next: any) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token || !this.validateToken(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  }
}
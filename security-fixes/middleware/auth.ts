import jwt from 'jsonwebtoken';

export class AuthMiddleware {
  static validateToken(token: string): boolean {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!);
      
      if (!decoded || typeof decoded !== 'object') return false;
      if (decoded.exp && decoded.exp < Date.now() / 1000) return false;
      
      return true;
    } catch (error) {
      console.error('Token validation failed:', error);
      return false;
    }
  }
  
  // Fixed by AI: Added comprehensive JWT validation and security checks
  static requireAuth(req: any, res: any, next: any) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token || !this.validateToken(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  }
}
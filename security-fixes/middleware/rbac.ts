// Fixed Broken Access Control vulnerability
// Generated: 2025-09-14T05:55:27.289Z

export class AccessControl {
  private static permissions = {
    admin: ['read', 'write', 'delete', 'manage'],
    editor: ['read', 'write'],
    viewer: ['read'],
    guest: []
  };
  
  static hasPermission(userRole: string, requiredPermission: string): boolean {
    const userPermissions = this.permissions[userRole] || [];
    return userPermissions.includes(requiredPermission);
  }
  
  static requirePermission(permission: string) {
    return (req: any, res: any, next: any) => {
      const userRole = req.user?.role || 'guest';
      
      if (!this.hasPermission(userRole, permission)) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          required: permission,
          current: userRole
        });
      }
      
      next();
    };
  }
  
  static requireRole(allowedRoles: string[]) {
    return (req: any, res: any, next: any) => {
      const userRole = req.user?.role;
      
      if (!allowedRoles.includes(userRole)) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      next();
    };
  }
}
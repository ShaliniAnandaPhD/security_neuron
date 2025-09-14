// Fixed Insecure Direct Object Reference vulnerability
// Generated: 2025-09-14T08:49:04.173Z

export class UserController {
  // Before: Direct access without authorization
  // After: Proper ownership validation
  static async getUserData(req: any, res: any) {
    const { userId } = req.params;
    const currentUser = req.user;
    
    // Verify user can only access their own data
    if (currentUser.id !== userId && !currentUser.isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    try {
      const userData = await User.findById(userId);
      res.json(userData);
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  }
  
  static async updateUserProfile(req: any, res: any) {
    const { userId } = req.params;
    const currentUser = req.user;
    
    // Authorization check
    if (currentUser.id !== userId) {
      return res.status(403).json({ error: 'Cannot modify other users' });
    }
    
    // Proceed with update...
  }
}
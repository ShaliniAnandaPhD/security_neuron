export class UserController {
  static async getUserData(req: any, res: any) {
    const { userId } = req.params;
    const currentUser = req.user;
    
    // Fixed by AI: Verify user can only access their own data
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
    
    // Fixed by AI: Authorization check for updates
    if (currentUser.id !== userId) {
      return res.status(403).json({ error: 'Cannot modify other users' });
    }
    
    const updatedUser = await User.updateById(userId, req.body);
    res.json(updatedUser);
  }
}
export class DatabaseQueries {
  static getUserById(userId: string) {
    const query = 'SELECT * FROM users WHERE id = ?';
    return db.prepare(query).get(userId);
  }
  
  static searchUsers(searchTerm: string) {
    const query = 'SELECT * FROM users WHERE name LIKE ?';
    return db.prepare(query).all(`%${searchTerm}%`);
  }
  
  // Fixed by AI: Added parameterized queries to prevent SQL injection
  static validateInput(input: string): string {
    return input.replace(/['"\\]/g, '');
  }
}
export class DatabaseQueries {
  static getUserById(userId: string) {
    const query = 'SELECT * FROM users WHERE id = ?';
    return db.prepare(query).get(userId);
  }
  
  // Fixed by AI: Added parameterized queries to prevent SQL injection
  static validateInput(input: string): string {
    return input.replace(/['"\\]/g, '');
  }
}
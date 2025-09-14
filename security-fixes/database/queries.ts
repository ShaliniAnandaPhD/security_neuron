// Fixed SQL Injection vulnerability
// Generated: 2025-09-14T05:55:27.289Z

export class SecurityQueries {
  // Before: SELECT * FROM users WHERE id = ${userId}
  // After: Parameterized query
  static getUserById(userId: string) {
    const query = 'SELECT * FROM users WHERE id = ?';
    return db.prepare(query).get(userId);
  }
  
  // Additional security improvements
  static validateInput(input: string): string {
    return input.replace(/['"\\]/g, '');
  }
}
// Fixed XSS vulnerability
// Generated: 2025-09-14T05:30:16.777Z

import { escapeHtml } from '../utils/security';

export const UserDisplay = ({ user }: { user: any }) => {
  // Before: dangerouslySetInnerHTML={{ __html: user.bio }}
  // After: Properly escaped content
  return (
    <div className="user-profile">
      <h3>{escapeHtml(user.name)}</h3>
      <p>{escapeHtml(user.bio)}</p>
      <span className="email">{escapeHtml(user.email)}</span>
    </div>
  );
};
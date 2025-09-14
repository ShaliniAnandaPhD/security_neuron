import { escapeHtml } from '../utils/security';

export const UserDisplay = ({ user }: { user: any }) => {
  return (
    <div className="user-profile">
      <h3>{escapeHtml(user.name)}</h3>
      <p>{escapeHtml(user.bio)}</p>
      <p>Email: {escapeHtml(user.email)}</p>
    </div>
  );
};

// Fixed by AI: Removed dangerouslySetInnerHTML and added proper escaping
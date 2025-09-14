import { motion } from "framer-motion";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { GitBranch, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import { GitHubAuthState } from "@/hooks/useGitHubAuth";

// Utility function to sanitize user input
const sanitizeText = (text: string): string => {
  return text.replace(/[<>'"&]/g, (char) => {
    const entities: { [key: string]: string } = {
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;',
      '&': '&amp;'
    };
    return entities[char];
  });
};

interface GitHubAuthCardProps {
  authState: GitHubAuthState;
  onSignIn: () => void;
  onSignOut: () => void;
}

export const GitHubAuthCard: React.FC<GitHubAuthCardProps> = ({
  authState,
  onSignIn,
  onSignOut,
}) => {
  if (authState.isConnected && authState.user) {
    // Sanitize user data before display
    const sanitizedName = sanitizeText(authState.user.name || '');
    const sanitizedUsername = sanitizeText(authState.user.username || '');
    
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Avatar className="h-10 w-10">
                  <AvatarImage 
                    src={authState.user.avatar_url} 
                    alt={sanitizedUsername}
                  />
                  <AvatarFallback>
                    {sanitizedName.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <CardTitle className="text-lg">{sanitizedName}</CardTitle>
                  <CardDescription>@{sanitizedUsername}</CardDescription>
                </div>
              </div>
              <Badge variant="secondary" className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" />
                Connected
              </Badge>
            </div>
          </CardHeader>
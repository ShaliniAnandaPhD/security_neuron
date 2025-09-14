import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

// CSRF token management
const generateCSRFToken = (): string => {
  return crypto.randomUUID();
};

const validateCSRFToken = (token: string): boolean => {
  const storedToken = sessionStorage.getItem('csrf_token');
  return storedToken === token;
};

interface EnhancedGitHubCommitPanelProps {
  isConnected: boolean;
  onCommit: (data: any) => Promise<void>;
}

export const EnhancedGitHubCommitPanel: React.FC<EnhancedGitHubCommitPanelProps> = ({
  isConnected,
  onCommit,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [csrfToken, setCSRFToken] = useState<string>('');
  const [commitMessage, setCommitMessage] = useState('');
  const [branch, setBranch] = useState('main');

  useEffect(() => {
    // Generate and store CSRF token on component mount
    const token = generateCSRFToken();
    setCSRFToken(token);
    sessionStorage.setItem('csrf_token', token);
  }, []);

  const handleCommit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate CSRF token
    if (!validateCSRFToken(csrfToken)) {
      console.error('CSRF token validation failed');
      alert('Security validation failed. Please refresh the page.');
      return;
    }

    // Validate inputs
    if (!commitMessage.trim()) {
      alert('Commit message is required');
      return;
    }

    if (!branch.trim()) {
      alert('Branch name is required');
      return;
    }

    setIsLoading(true);
    
    try {
      await onCommit({
        message: commitMessage.trim(),
        branch: branch.trim(),
        csrfToken: csrfToken
      });
      
      // Generate new CSRF token after successful operation
      const newToken = generateCSRFToken();
      setCSRFToken(newToken);
      sessionStorage.setItem('csrf_token', newToken);
      
    } catch (error) {
      console.error('Commit failed:', error);
      alert('Commit operation failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };
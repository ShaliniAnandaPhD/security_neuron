import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';

export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
  description: string | null;
  updated_at: string;
  language: string | null;
  stargazers_count: number;
  forks_count: number;
}

interface RepositoriesState {
  repositories: GitHubRepository[];
  isLoading: boolean;
  error: string | null;
  retryCount: number;
}

// Error classification
const classifyError = (error: any): { type: string; message: string; retryable: boolean } => {
  if (error?.message?.includes('rate limit')) {
    return {
      type: 'RATE_LIMIT',
      message: 'GitHub API rate limit exceeded. Please try again later.',
      retryable: true
    };
  }
  
  if (error?.message?.includes('403')) {
    return {
      type: 'FORBIDDEN',
      message: 'Access denied. Please check your GitHub permissions.',
      retryable: false
    };
  }
  
  if (error?.message?.includes('network')) {
    return {
      type: 'NETWORK',
      message: 'Network error. Please check your connection.',
      retryable: true
    };
  }
  
  return {
    type: 'UNKNOWN',
    message: error?.message || 'An unexpected error occurred.',
    retryable: true
  };
};

export const useGitHubRepositories = () => {
  const [state, setState] = useState<RepositoriesState>({
    repositories: [],
    isLoading: false,
    error: null,
    retryCount: 0
  });

  const fetchRepositories = useCallback(async (forceRefresh = false) => {
    const maxRetries = 3;
    
    if (state.retryCount >= maxRetries && !forceRefresh) {
      setState(prev => ({ 
        ...prev, 
        error: 'Maximum retry attempts reached. Please refresh the page.' 
      }));
      return;
    }

    setState(prev => ({ 
      ...prev, 
      isLoading: true, 
      error: null,
      retryCount: forceRefresh ? 0 : prev.retryCount
    }));

    try {
      const { data, error } = await supabase.functions.invoke('fetch-github-repos', {
        body: { 
          refresh: forceRefresh,
          timestamp: Date.now() // Prevent caching issues
        }
      });

      if (error) throw error;

      setState(prev => ({
        ...prev,
        repositories: data?.repositories || [],
        isLoading: false,
        error: null,
        retryCount: 0
      }));

    } catch (error) {
      console.error('Failed to fetch repositories:', error);
      
      const { type, message, retryable } = classifyError(error);
      
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
        retryCount: retryable ? prev.retryCount + 1 : maxRetries
      }));

      // Auto-retry for retryable errors with exponential backoff
      if (retryable && state.retryCount < maxRetries - 1) {
        const delay = Math.pow(2, state.retryCount) * 1000; // 1s, 2s, 4s
        setTimeout(() => {
          fetchRepositories();
        }, delay);
      }
    }
  }, [state.retryCount]);
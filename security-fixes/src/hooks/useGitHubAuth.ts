export const useGitHubAuth = () => {
  const [authState, setAuthState] = useState<GitHubAuthState>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    error: null,
  });

  const checkAuthStatus = async () => {
    try {
      const { data: { session }, error } = await supabase.auth.getSession();
      
      if (error) throw error;
      
      if (session?.provider_token) {
        // Validate token expiration
        const tokenExpiry = session.expires_at;
        if (tokenExpiry && Date.now() / 1000 > tokenExpiry) {
          throw new Error('GitHub token has expired');
        }
        
        setAuthState({
          isAuthenticated: true,
          isLoading: false,
          user: {
            id: session.user.id,
            name: session.user.user_metadata.full_name,
            username: session.user.user_metadata.user_name,
            avatar_url: session.user.user_metadata.avatar_url,
          },
          error: null,
        });
      } else {
        setAuthState(prev => ({ ...prev, isAuthenticated: false, isLoading: false }));
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setAuthState({
        isAuthenticated: false,
        isLoading: false,
        user: null,
        error: error instanceof Error ? error.message : 'Authentication failed',
      });
    }
  };
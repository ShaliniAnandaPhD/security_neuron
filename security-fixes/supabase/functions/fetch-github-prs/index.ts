import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { Octokit } from 'https://esm.sh/@octokit/rest@21.0.0'

// Enhanced CORS headers with security
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Max-Age': '86400',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
}

// Request logging utility
const logRequest = (req: Request, additionalInfo?: any) => {
  const timestamp = new Date().toISOString();
  const userAgent = req.headers.get('user-agent') || 'unknown';
  const referer = req.headers.get('referer') || 'unknown';
  
  console.log(JSON.stringify({
    timestamp,
    method: req.method,
    url: req.url,
    userAgent,
    referer,
    ...additionalInfo
  }));
};

// Error logging utility
const logError = (error: any, context: string, userId?: string) => {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    context,
    userId,
    error: {
      message: error?.message || 'Unknown error',
      stack: error?.stack,
      name: error?.name
    }
  }));
};

Deno.serve(async (req) => {
  const requestId = crypto.randomUUID();
  logRequest(req, { requestId, action: 'fetch-github-prs' });
  
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { 
      headers: corsHeaders,
      status: 204
    });
  }

  // Only allow GET requests
  if (req.method !== 'GET') {
    logError(new Error('Method not allowed'), 'invalid-method', undefined);
    return new Response(
      JSON.stringify({ 
        error: 'Method not allowed',
        requestId 
      }),
      { 
        status: 405, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    );
  }

  try {
    // Initialize Supabase client with enhanced error handling
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { 
            Authorization: req.headers.get('Authorization')!,
            'X-Request-ID': requestId
          },
        },
      }
    );
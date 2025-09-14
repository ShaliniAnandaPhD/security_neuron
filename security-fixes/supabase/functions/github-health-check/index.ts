import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { Octokit } from 'https://esm.sh/@octokit/rest@21.0.0'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// Input validation function
const validateRequestBody = (body: any): { isValid: boolean; error?: string } => {
  if (!body || typeof body !== 'object') {
    return { isValid: false, error: 'Request body must be a valid JSON object' };
  }
  
  // Add specific validation rules as needed
  if (body.repository && typeof body.repository !== 'string') {
    return { isValid: false, error: 'Repository name must be a string' };
  }
  
  return { isValid: true };
};

Deno.serve(async (req) => {
  console.log('GitHub health check endpoint called', req.method)
  
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    console.error('Invalid method:', req.method);
    return new Response(
      JSON.stringify({ error: 'Method not allowed. Only POST requests are supported.' }),
      { 
        status: 405, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    )
  }

  try {
    // Validate request body
    let requestBody;
    try {
      requestBody = await req.json();
    } catch (error) {
      console.error('Invalid JSON in request body:', error);
      return new Response(
        JSON.stringify({ error: 'Invalid JSON in request body' }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      );
    }

    const validation = validateRequestBody(requestBody);
    if (!validation.isValid) {
      console.error('Request validation failed:', validation.error);
      return new Response(
        JSON.stringify({ error: validation.error }),
        { 
          status: 400, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      );
    }
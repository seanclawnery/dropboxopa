const express = require('express');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// Security middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Generate PKCE codes for OAuth security
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

// Store PKCE codes temporarily (in production, use proper session storage)
const pkceStore = new Map();

// Serve the main SPA page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Generate OAuth URL
app.post('/auth/login', express.json(), (req, res) => {
  const { clientId, redirectUri, scopes } = req.body;
  
  if (!clientId || !redirectUri) {
    return res.status(400).json({ 
      error: 'Missing required parameters',
      details: 'client_id and redirect_uri are required'
    });
  }

  const { verifier, challenge } = generatePKCE();
  const state = crypto.randomBytes(16).toString('hex');
  
  // Store PKCE codes temporarily along with credentials
  pkceStore.set(state, { 
    verifier, 
    challenge,
    clientId,
    redirectUri,
    scopes: scopes || 'files.metadata.read'
  });
  
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    token_access_type: 'offline',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: state,
    scope: scopes || 'files.metadata.read'
  });

  const authUrl = `https://www.dropbox.com/oauth2/authorize?${params.toString()}`;
  res.json({ authUrl });
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    
    if (!code || !state) {
      return res.status(400).json({ 
        error: 'Missing required parameters',
        details: code ? 'Code provided' : 'Code missing',
        details2: state ? 'State provided' : 'State missing'
      });
    }

    // Retrieve stored PKCE data
    const pkceData = pkceStore.get(state);
    if (!pkceData) {
      return res.status(400).json({ 
        error: 'Invalid or expired state parameter',
        details: 'Possible CSRF attack or session expired'
      });
    }

    // Remove used PKCE data
    pkceStore.delete(state);

    // Exchange authorization code for access token
    const tokenResponse = await axios.post('https://api.dropboxapi.com/oauth2/token', {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: pkceData.redirectUri,
      client_id: pkceData.clientId,
      client_secret: '', // Client secret is not required for OAuth 2.0 PKCE flow
      code_verifier: pkceData.verifier
    });

    // Send token back to the frontend
    res.json({
      success: true,
      token: tokenResponse.data,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('OAuth callback error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Authentication failed',
      details: error.response?.data?.error_description || error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen( () => {
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
});
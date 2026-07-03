'use strict';
const crypto = require('crypto');
const { app } = require('@azure/functions');

const STATE_TTL_MS = 600_000; // 10 minutes

/**
 * Escape string for safe use in a regular expression.
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Check if a domain matches any allowed pattern.
 * Anchored with ^ and $ to prevent suffix-confusion (evilexample.com must NOT match *.example.com).
 */
function isDomainAllowed(domain, allowedDomainsEnv) {
  if (!allowedDomainsEnv) return false;
  const patterns = allowedDomainsEnv.split(',').map(s => s.trim()).filter(Boolean);
  return patterns.some(pattern => {
    const escaped = escapeRegExp(pattern).replace('\\*', '.+');
    return new RegExp(`^${escaped}$`).test(domain);
  });
}

/**
 * Return an HTML page that communicates an error back to window.opener via postMessage.
 */
function outputError(provider, error, errorCode) {
  const content = JSON.stringify({ provider: provider || 'unknown', error, errorCode });
  const p = provider || 'unknown';
  return {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' },
    body: `<!doctype html><html><body><script>
      (() => {
        window.addEventListener('message', ({ data, origin }) => {
          if (data === 'authorizing:${p}') {
            window.opener?.postMessage('authorization:${p}:error:' + ${JSON.stringify(content)}, origin);
          }
        });
        window.opener?.postMessage('authorizing:${p}', '*');
      })();
    </script></body></html>`,
  };
}

/**
 * Return HTML that sends the token back to Decap CMS via the 3-step postMessage handshake.
 * Uses siteId as the postMessage target origin for security (not '*').
 */
function outputHTML({ provider = 'github', token, error, errorCode, siteId }) {
  const isError = Boolean(error);
  const state = isError ? 'error' : 'success';
  const content = JSON.stringify(isError ? { provider, error, errorCode } : { provider, token });
  const targetOrigin = siteId ? JSON.stringify(`https://${siteId}`) : '"*"';

  return {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' },
    body: `<!doctype html><html><body><script>
      (() => {
        const targetOrigin = ${targetOrigin};
        window.addEventListener('message', ({ data, origin }) => {
          if (data === 'authorizing:${provider}') {
            window.opener?.postMessage(
              'authorization:${provider}:${state}:' + ${JSON.stringify(content)},
              targetOrigin
            );
          }
        });
        window.opener?.postMessage('authorizing:${provider}', targetOrigin);
      })();
    </script></body></html>`,
  };
}

// ─── /api/auth ────────────────────────────────────────────────────────────────
// Initiates GitHub OAuth: validates provider + domain, generates HMAC-signed state,
// redirects to github.com/login/oauth/authorize.
app.http('auth', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const url = new URL(request.url);
    const provider  = url.searchParams.get('provider');
    const siteId    = url.searchParams.get('site_id') || '';
    const scope     = url.searchParams.get('scope') || 'repo,user';

    if (provider !== 'github') {
      return outputError(provider, 'Your Git backend is not supported by the authenticator.', 'UNSUPPORTED_BACKEND');
    }

    const { GITHUB_CLIENT_ID, ALLOWED_DOMAINS, CSRF_SECRET } = process.env;

    if (!GITHUB_CLIENT_ID || !CSRF_SECRET) {
      return outputError('github', 'OAuth app client ID or CSRF secret is not configured.', 'MISCONFIGURED_CLIENT');
    }

    if (!isDomainAllowed(siteId, ALLOWED_DOMAINS)) {
      return outputError('github', 'Your domain is not allowed to use the authenticator.', 'UNSUPPORTED_DOMAIN');
    }

    // HMAC-signed stateless CSRF state — no cookies (Safari ITP safe)
    const nonce      = crypto.randomBytes(16).toString('hex');
    const payload    = JSON.stringify({ siteId, nonce, ts: Date.now() });
    const payloadB64 = Buffer.from(payload).toString('base64url');
    const sig        = crypto.createHmac('sha256', CSRF_SECRET).update(payloadB64).digest('hex');
    const state      = `${payloadB64}.${sig}`;

    const params = new URLSearchParams({ client_id: GITHUB_CLIENT_ID, scope, state });

    return {
      status: 302,
      headers: {
        Location: `https://github.com/login/oauth/authorize?${params.toString()}`,
        'Cache-Control': 'no-store',
      },
      body: '',
    };
  },
});

// ─── /api/callback ────────────────────────────────────────────────────────────
// Handles GitHub OAuth callback: verifies HMAC state, exchanges code for token,
// returns postMessage HTML to hand the token back to Decap CMS.
app.http('callback', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const url        = new URL(request.url);
    const code       = url.searchParams.get('code');
    const stateParam = url.searchParams.get('state');

    if (!code || !stateParam) {
      return outputHTML({
        error: 'Failed to receive an authorization code. Please try again later.',
        errorCode: 'AUTH_CODE_REQUEST_FAILED',
      });
    }

    const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, CSRF_SECRET } = process.env;

    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !CSRF_SECRET) {
      return outputHTML({ error: 'OAuth credentials are not configured.', errorCode: 'MISCONFIGURED_CLIENT' });
    }

    // Verify HMAC-signed state
    const dotIndex = stateParam.lastIndexOf('.');
    if (dotIndex === -1) {
      return outputHTML({ error: 'Malformed state parameter.', errorCode: 'CSRF_DETECTED' });
    }

    const payloadB64  = stateParam.slice(0, dotIndex);
    const sig         = stateParam.slice(dotIndex + 1);
    const expectedSig = crypto.createHmac('sha256', CSRF_SECRET).update(payloadB64).digest('hex');

    let sigValid = false;
    try {
      sigValid = crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expectedSig, 'hex'));
    } catch { sigValid = false; }

    if (!sigValid) {
      return outputHTML({ error: 'Potential CSRF attack detected. Authentication flow aborted.', errorCode: 'CSRF_DETECTED' });
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch {
      return outputHTML({ error: 'Malformed state parameter.', errorCode: 'CSRF_DETECTED' });
    }

    const { siteId, ts } = payload;

    if (!ts || Date.now() - ts > STATE_TTL_MS) {
      return outputHTML({ error: 'Authentication session has expired. Please try again.', errorCode: 'CSRF_EXPIRED', siteId });
    }

    // Exchange code for GitHub access token
    let response;
    try {
      response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET }),
      });
    } catch {
      return outputHTML({ error: 'Failed to request an access token. Please try again later.', errorCode: 'TOKEN_REQUEST_FAILED', siteId });
    }

    if (!response.ok) {
      return outputHTML({ error: 'Failed to request an access token. Please try again later.', errorCode: 'TOKEN_REQUEST_FAILED', siteId });
    }

    let token, error;
    try {
      ({ access_token: token, error } = await response.json());
    } catch {
      return outputHTML({ error: 'Server responded with malformed data. Please try again later.', errorCode: 'MALFORMED_RESPONSE', siteId });
    }

    return outputHTML({ provider: 'github', token, error, siteId });
  },
});

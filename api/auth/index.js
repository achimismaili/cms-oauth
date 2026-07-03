'use strict';
const crypto = require('crypto');

/**
 * Escape string for safe use in a regular expression.
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Check if the given domain matches any of the allowed domain patterns.
 * Patterns support wildcard prefix: *.example.com
 * Anchored with ^ and $ to prevent suffix-confusion attacks (e.g. evilexample.com must NOT match *.example.com)
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
 * Output an HTML page that communicates an error back to the window opener.
 */
function outputError(provider, error, errorCode) {
  const content = { provider: provider || 'unknown', error, errorCode };
  return {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    body: `<!doctype html><html><body><script>
      (() => {
        window.addEventListener('message', ({ data, origin }) => {
          if (data === 'authorizing:${provider || 'unknown'}') {
            window.opener?.postMessage(
              'authorization:${provider || 'unknown'}:error:${JSON.stringify(content).replace(/\\/g, '\\\\').replace(/`/g, '\\`')}',
              origin
            );
          }
        });
        window.opener?.postMessage('authorizing:${provider || 'unknown'}', '*');
      })();
    </script></body></html>`
  };
}

/**
 * Azure Functions v3 handler for GET /api/auth
 * Initiates GitHub OAuth flow with HMAC-signed stateless CSRF state.
 */
module.exports = async function (context, req) {
  const provider = req.query.provider;
  const siteId = req.query.site_id || '';
  const scope = req.query.scope || 'repo,user';

  // Only GitHub is supported
  if (provider !== 'github') {
    context.res = outputError(provider, 'Your Git backend is not supported by the authenticator.', 'UNSUPPORTED_BACKEND');
    return;
  }

  const { GITHUB_CLIENT_ID, ALLOWED_DOMAINS, CSRF_SECRET } = process.env;

  if (!GITHUB_CLIENT_ID || !CSRF_SECRET) {
    context.res = outputError('github', 'OAuth app client ID or CSRF secret is not configured.', 'MISCONFIGURED_CLIENT');
    return;
  }

  // Validate origin domain against allowlist (anchored regex, wildcard-aware)
  if (!isDomainAllowed(siteId, ALLOWED_DOMAINS)) {
    context.res = outputError('github', 'Your domain is not allowed to use the authenticator.', 'UNSUPPORTED_DOMAIN');
    return;
  }

  // Generate HMAC-signed stateless CSRF state (no cookies — Safari ITP safe)
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = JSON.stringify({ siteId, nonce, ts: Date.now() });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', CSRF_SECRET).update(payloadB64).digest('hex');
  const state = `${payloadB64}.${sig}`;

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope,
    state,
  });

  context.res = {
    status: 302,
    headers: {
      Location: `https://github.com/login/oauth/authorize?${params.toString()}`,
      'Cache-Control': 'no-store',
    },
    body: '',
  };
};

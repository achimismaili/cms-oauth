'use strict';
const crypto = require('crypto');

const STATE_TTL_MS = 600_000; // 10 minutes

/**
 * Output HTML that communicates with the CMS window opener via postMessage.
 * Uses the siteId as the target origin for postMessage security.
 */
function outputHTML({ provider = 'github', token, error, errorCode, siteId }) {
  const isError = Boolean(error);
  const state = isError ? 'error' : 'success';
  const content = isError ? { provider, error, errorCode } : { provider, token };
  const targetOrigin = siteId ? JSON.stringify(`https://${siteId}`) : '"*"';

  return {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store',
    },
    body: `<!doctype html><html><body><script>
      (() => {
        const targetOrigin = ${targetOrigin};
        window.addEventListener('message', ({ data, origin }) => {
          if (data === 'authorizing:${provider}') {
            window.opener?.postMessage(
              'authorization:${provider}:${state}:' + JSON.stringify(${JSON.stringify(content)}),
              targetOrigin
            );
          }
        });
        window.opener?.postMessage('authorizing:${provider}', targetOrigin);
      })();
    </script></body></html>`,
  };
}

/**
 * Azure Functions v3 handler for GET /api/callback
 * Verifies HMAC-signed state, exchanges code for GitHub token, returns postMessage HTML.
 */
module.exports = async function (context, req) {
  const code = req.query.code;
  const stateParam = req.query.state;

  if (!code || !stateParam) {
    context.res = outputHTML({
      error: 'Failed to receive an authorization code. Please try again later.',
      errorCode: 'AUTH_CODE_REQUEST_FAILED',
    });
    return;
  }

  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, CSRF_SECRET } = process.env;

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !CSRF_SECRET) {
    context.res = outputHTML({
      error: 'OAuth app credentials are not configured.',
      errorCode: 'MISCONFIGURED_CLIENT',
    });
    return;
  }

  // Verify HMAC-signed state
  const dotIndex = stateParam.lastIndexOf('.');
  if (dotIndex === -1) {
    context.res = outputHTML({
      error: 'Potential CSRF attack detected. Authentication flow aborted.',
      errorCode: 'CSRF_DETECTED',
    });
    return;
  }

  const payloadB64 = stateParam.slice(0, dotIndex);
  const sig = stateParam.slice(dotIndex + 1);
  const expectedSig = crypto.createHmac('sha256', CSRF_SECRET).update(payloadB64).digest('hex');

  // Timing-safe comparison to prevent timing attacks
  let sigValid = false;
  try {
    sigValid = crypto.timingSafeEqual(
      Buffer.from(sig, 'hex'),
      Buffer.from(expectedSig, 'hex')
    );
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    context.res = outputHTML({
      error: 'Potential CSRF attack detected. Authentication flow aborted.',
      errorCode: 'CSRF_DETECTED',
    });
    return;
  }

  // Decode and validate payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    context.res = outputHTML({
      error: 'Malformed state parameter.',
      errorCode: 'CSRF_DETECTED',
    });
    return;
  }

  const { siteId, ts } = payload;

  // Check TTL (10 minutes)
  if (!ts || Date.now() - ts > STATE_TTL_MS) {
    context.res = outputHTML({
      error: 'Authentication session has expired. Please try again.',
      errorCode: 'CSRF_EXPIRED',
      siteId,
    });
    return;
  }

  // Exchange code for access token with GitHub
  let response;
  try {
    response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
      }),
    });
  } catch {
    context.res = outputHTML({
      error: 'Failed to request an access token. Please try again later.',
      errorCode: 'TOKEN_REQUEST_FAILED',
      siteId,
    });
    return;
  }

  if (!response.ok) {
    context.res = outputHTML({
      error: 'Failed to request an access token. Please try again later.',
      errorCode: 'TOKEN_REQUEST_FAILED',
      siteId,
    });
    return;
  }

  let token, error;
  try {
    ({ access_token: token, error } = await response.json());
  } catch {
    context.res = outputHTML({
      error: 'Server responded with malformed data. Please try again later.',
      errorCode: 'MALFORMED_RESPONSE',
      siteId,
    });
    return;
  }

  context.res = outputHTML({ provider: 'github', token, error, siteId });
};

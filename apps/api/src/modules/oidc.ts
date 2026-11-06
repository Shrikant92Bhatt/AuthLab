import { Router } from 'express';
import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';
import { env, getRedis, isProd, randomToken, rk } from '@authlab/core';
import { asJwks } from './oauth2';
import { clearSessionCookie, destroy, establishSession, requireCsrf, requireSession } from '../lib/session';

/**
 * OpenID Connect = OAuth 2.0 + an identity layer (ID Token + /userinfo + discovery).
 * This API acts as a BFF (Backend-for-Frontend) Relying Party:
 *   - confidential client (has a secret), uses Authorization Code + PKCE
 *   - tokens NEVER reach the browser; browser gets a session cookie
 * Validates: state (CSRF), nonce (replay), iss, aud, exp, signature (JWKS), at_hash.
 */
const REDIRECT_URI = `${env.WEB_ORIGIN}/api/oidc/callback`;
const STATE_COOKIE = 'authlab.oidc_state';
const b64sha = (s: string) => createHash('sha256').update(s).digest('base64url');

interface PendingLogin { nonce: string; codeVerifier: string }

export const oidcRouter = Router();

oidcRouter.get('/login', async (_req, res) => {
  const state = randomToken(24);
  const nonce = randomToken(24);
  const codeVerifier = randomToken(48); // PKCE even for confidential clients (OAuth 2.1)
  await getRedis().set(rk.oauthState(state), JSON.stringify({ nonce, codeVerifier } satisfies PendingLogin), 'EX', 600);
  // Bind state to THIS browser → prevents login-CSRF (attacker injecting their own code)
  res.cookie(STATE_COOKIE, state, { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 600_000, path: '/api/oidc' });

  const url = new URL(`${env.ISSUER}/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: env.OIDC_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email roles',
    state,
    nonce,
    code_challenge: b64sha(codeVerifier),
    code_challenge_method: 'S256',
  }).toString();
  res.redirect(url.toString());
});

oidcRouter.get('/callback', async (req, res) => {
  const q = req.query as Record<string, string>;
  const fail = (msg: string) => res.redirect(`${env.WEB_ORIGIN}/oidc?error=${encodeURIComponent(msg)}`);
  if (q.error) return fail(`${q.error}: ${q.error_description ?? ''}`);
  if (!q.state || q.state !== req.cookies[STATE_COOKIE]) return fail('state mismatch (possible CSRF)');
  if (q.iss && q.iss !== env.ISSUER) return fail('iss mismatch (mix-up attack)');
  res.clearCookie(STATE_COOKIE, { path: '/api/oidc' });

  const raw = await getRedis().getdel(rk.oauthState(q.state));
  if (!raw) return fail('login expired');
  const pending = JSON.parse(raw) as PendingLogin;

  // Back-channel: exchange code for tokens (client authenticates with its secret)
  const tokenRes = await fetch(`${env.ISSUER}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from(`${env.OIDC_CLIENT_ID}:${env.OIDC_CLIENT_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: q.code ?? '', redirect_uri: REDIRECT_URI, code_verifier: pending.codeVerifier }),
  });
  const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string; refresh_token?: string; scope?: string; error?: string; error_description?: string };
  if (!tokens.id_token || !tokens.access_token) return fail(`token exchange failed: ${tokens.error_description ?? tokens.error}`);

  let idClaims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(tokens.id_token, asJwks, { issuer: env.ISSUER, audience: env.OIDC_CLIENT_ID, algorithms: ['RS256'], maxTokenAge: '5m' });
    if (payload.nonce !== pending.nonce) throw new Error('nonce mismatch');
    const atHash = createHash('sha256').update(tokens.access_token).digest().subarray(0, 16).toString('base64url');
    if (payload.at_hash && payload.at_hash !== atHash) throw new Error('at_hash mismatch');
    idClaims = payload;
  } catch (e) {
    return fail(`ID token invalid: ${(e as Error).message}`);
  }

  const userinfo = (await (await fetch(`${env.ISSUER}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json()) as Record<string, unknown>;

  await establishSession(
    req,
    { id: String(idClaims.sub), username: String(idClaims.preferred_username), email: String(idClaims.email), name: String(idClaims.name), roles: (idClaims.roles as string[]) ?? [] },
    'oidc',
    { oidc: { idToken: tokens.id_token, idClaims, userinfo, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, scope: tokens.scope ?? '' } },
  );
  res.redirect(`${env.WEB_ORIGIN}/oidc?login=ok`);
});

oidcRouter.get('/me', requireSession('oidc'), (req, res) => {
  const o = req.session.oidc!;
  res.json({
    method: 'oidc',
    user: req.session.user,
    csrfToken: req.session.csrfToken,
    idToken: o.idToken, // shown for learning; a real BFF never sends tokens to the browser
    idTokenClaims: o.idClaims,
    userinfo: o.userinfo,
    scope: o.scope,
    accessTokenHeldServerSide: `${o.accessToken.slice(0, 16)}…`,
  });
});

oidcRouter.post('/logout', requireSession('oidc'), requireCsrf, async (req, res) => {
  await destroy(req);
  clearSessionCookie(res);
  res.json({ ok: true });
});


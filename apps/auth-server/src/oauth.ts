import { Router, type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { env, findById, getRedis, randomToken, rk, safeEqual, toPublic, verifyCredentials, type SigningKey, type User } from '@authlab/core';
import { authenticateClient, findClient, SCOPE_DESCRIPTIONS, type OAuthClient } from './clients';
import { errorPage, loginConsentPage } from './views';

/**
 * OAuth 2.0 Authorization Server (RFC 6749 + RFC 7636 PKCE + RFC 9207 iss)
 * and OpenID Provider (OIDC Core 1.0) in ~300 lines.
 *
 * Endpoints:
 *   GET  /.well-known/openid-configuration   discovery
 *   GET  /jwks.json                          public signing keys
 *   GET  /authorize                          login + consent UI
 *   POST /authorize                          user decision → code
 *   POST /token                              code / refresh / client_credentials → tokens
 *   GET  /userinfo                           OIDC claims (needs access token)
 *   POST /introspect  (RFC 7662)   POST /revoke (RFC 7009)
 */

export const API_AUDIENCE = 'authlab-api';
const ACCESS_TTL = 600; // 10 min
const CODE_TTL = 60; // auth codes are single-use and short-lived
const RT_TTL = 60 * 60 * 24 * 14;

interface AuthTxn {
  clientId: string; redirectUri: string; scope: string[]; state?: string; nonce?: string;
  codeChallenge?: string; codeChallengeMethod?: 'S256';
}
interface AuthCode extends AuthTxn { userId: string; authTime: number }
interface StoredRefresh { clientId: string; userId: string; scope: string[]; authTime: number }

const sha256b64url = (s: string) => createHash('sha256').update(s).digest('base64url');

function oauthError(res: Response, status: number, error: string, description: string) {
  return res.status(status).json({ error, error_description: description });
}

export function oauthRouter(key: SigningKey) {
  const r = Router();
  const redis = getRedis();
  const ISS = env.ISSUER;

  // ---------- discovery & keys ----------
  r.get('/.well-known/openid-configuration', (_req, res) => {
    res.json({
      issuer: ISS,
      authorization_endpoint: `${ISS}/authorize`,
      token_endpoint: `${ISS}/token`,
      userinfo_endpoint: `${ISS}/userinfo`,
      jwks_uri: `${ISS}/jwks.json`,
      introspection_endpoint: `${ISS}/introspect`,
      revocation_endpoint: `${ISS}/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      scopes_supported: Object.keys(SCOPE_DESCRIPTIONS),
      claims_supported: ['sub', 'name', 'preferred_username', 'email', 'email_verified', 'roles', 'nonce', 'auth_time'],
      authorization_response_iss_parameter_supported: true,
    });
  });
  r.get('/jwks.json', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json({ keys: [key.publicJwk] });
  });

  // ---------- authorize (front channel) ----------
  r.get('/authorize', async (req, res) => {
    const q = req.query as Record<string, string | undefined>;
    const client = q.client_id ? findClient(q.client_id) : undefined;
    // Never redirect to an unregistered URI (open-redirect / code theft)
    if (!client || !q.redirect_uri || !client.redirectUris.includes(q.redirect_uri)) {
      return res.status(400).send(errorPage('Unknown client_id or redirect_uri not registered (exact match required).'));
    }
    const back = (params: Record<string, string>) => {
      const u = new URL(q.redirect_uri!);
      Object.entries({ ...params, ...(q.state ? { state: q.state } : {}), iss: ISS }).forEach(([k, v]) => u.searchParams.set(k, v));
      return res.redirect(u.toString());
    };
    if (q.response_type !== 'code') return back({ error: 'unsupported_response_type', error_description: 'only code is supported (implicit flow is deprecated)' });
    if (client.type === 'public' && (!q.code_challenge || q.code_challenge_method !== 'S256')) {
      return back({ error: 'invalid_request', error_description: 'PKCE (S256) is required for public clients' });
    }
    const scope = (q.scope ?? '').split(' ').filter(Boolean);
    const bad = scope.filter((s) => !client.allowedScopes.includes(s));
    if (bad.length) return back({ error: 'invalid_scope', error_description: `not allowed: ${bad.join(',')}` });

    const txnId = randomToken(18);
    const txn: AuthTxn = {
      clientId: client.clientId, redirectUri: q.redirect_uri, scope, state: q.state, nonce: q.nonce,
      codeChallenge: q.code_challenge, codeChallengeMethod: q.code_challenge ? 'S256' : undefined,
    };
    await redis.set(`as:txn:${txnId}`, JSON.stringify(txn), 'EX', 600);
    res.send(loginConsentPage({
      action: '/authorize', txn: txnId, clientName: client.name,
      protocol: scope.includes('openid') ? 'OpenID Connect' : 'OAuth 2.0',
      scopes: scope.map((s) => ({ scope: s, desc: SCOPE_DESCRIPTIONS[s] ?? s })),
    }));
  });

  r.post('/authorize', async (req, res) => {
    const { txn: txnId, username, password, decision } = req.body as Record<string, string>;
    const raw = txnId ? await redis.get(`as:txn:${txnId}`) : null;
    if (!raw) return res.status(400).send(errorPage('Login transaction expired. Start again.'));
    const txn = JSON.parse(raw) as AuthTxn;
    const client = findClient(txn.clientId)!;
    const redirect = (params: Record<string, string>) => {
      const u = new URL(txn.redirectUri);
      Object.entries({ ...params, ...(txn.state ? { state: txn.state } : {}), iss: ISS }).forEach(([k, v]) => u.searchParams.set(k, v));
      return res.redirect(303, u.toString());
    };
    if (decision !== 'allow') {
      await redis.del(`as:txn:${txnId}`);
      return redirect({ error: 'access_denied', error_description: 'user denied consent' });
    }
    const user = await verifyCredentials(username ?? '', password ?? '');
    if (!user) {
      return res.status(401).send(loginConsentPage({
        action: '/authorize', txn: txnId, clientName: client.name, error: 'Invalid username or password',
        protocol: txn.scope.includes('openid') ? 'OpenID Connect' : 'OAuth 2.0',
        scopes: txn.scope.map((s) => ({ scope: s, desc: SCOPE_DESCRIPTIONS[s] ?? s })),
      }));
    }
    await redis.del(`as:txn:${txnId}`);
    const code = randomToken(32);
    const payload: AuthCode = { ...txn, userId: user.id, authTime: Math.floor(Date.now() / 1000) };
    await redis.set(rk.authCode(code), JSON.stringify(payload), 'EX', CODE_TTL);
    return redirect({ code });
  });

  // ---------- token (back channel) ----------
  const issueAccessToken = (sub: string, clientId: string, scope: string[], extra: Record<string, unknown> = {}) =>
    new SignJWT({ scope: scope.join(' '), client_id: clientId, ...extra })
      .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'at+jwt' }) // RFC 9068
      .setIssuer(ISS).setAudience(API_AUDIENCE).setSubject(sub)
      .setIssuedAt().setExpirationTime(`${ACCESS_TTL}s`).setJti(randomToken(12))
      .sign(key.privateKey);

  const issueIdToken = (user: User, clientId: string, scope: string[], nonce: string | undefined, authTime: number, accessToken: string) => {
    const claims: Record<string, unknown> = { auth_time: authTime };
    if (nonce) claims.nonce = nonce;
    // at_hash binds the ID token to the access token (OIDC Core §3.1.3.6)
    claims.at_hash = createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url');
    if (scope.includes('profile')) Object.assign(claims, { name: user.name, preferred_username: user.username });
    if (scope.includes('email')) Object.assign(claims, { email: user.email, email_verified: true });
    if (scope.includes('roles')) claims.roles = user.roles;
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
      .setIssuer(ISS).setAudience(clientId).setSubject(user.id)
      .setIssuedAt().setExpirationTime('5m')
      .sign(key.privateKey);
  };

  const clientFromRequest = (req: Request): { client: OAuthClient | null; id?: string } => {
    let id = req.body.client_id as string | undefined;
    let secret = req.body.client_secret as string | undefined;
    const h = req.headers.authorization;
    if (h?.startsWith('Basic ')) {
      const [u, p] = Buffer.from(h.slice(6), 'base64').toString().split(':');
      id = decodeURIComponent(u ?? ''); secret = decodeURIComponent(p ?? '');
    }
    return { client: id ? authenticateClient(id, secret) : null, id };
  };

  r.post('/token', async (req, res) => {
    res.set('Cache-Control', 'no-store').set('Pragma', 'no-cache');
    const { client } = clientFromRequest(req);
    if (!client) return oauthError(res, 401, 'invalid_client', 'client authentication failed');
    const grant = req.body.grant_type as string;
    if (!client.grantTypes.includes(grant as never)) return oauthError(res, 400, 'unauthorized_client', `grant ${grant} not allowed`);

    if (grant === 'authorization_code') {
      // GETDEL = atomic single use; a replayed code fails
      const raw = await redis.getdel(rk.authCode(req.body.code ?? ''));
      if (!raw) return oauthError(res, 400, 'invalid_grant', 'code invalid, expired or already used');
      const code = JSON.parse(raw) as AuthCode;
      if (code.clientId !== client.clientId) return oauthError(res, 400, 'invalid_grant', 'code was issued to another client');
      if (code.redirectUri !== req.body.redirect_uri) return oauthError(res, 400, 'invalid_grant', 'redirect_uri mismatch');
      if (code.codeChallenge) {
        const verifier = req.body.code_verifier as string | undefined;
        if (!verifier || !safeEqual(sha256b64url(verifier), code.codeChallenge)) {
          return oauthError(res, 400, 'invalid_grant', 'PKCE verification failed');
        }
      }
      const user = findById(code.userId)!;
      const access_token = await issueAccessToken(user.id, client.clientId, code.scope, { username: user.username });
      const body: Record<string, unknown> = { token_type: 'Bearer', access_token, expires_in: ACCESS_TTL, scope: code.scope.join(' ') };
      if (code.scope.includes('openid')) body.id_token = await issueIdToken(user, client.clientId, code.scope, code.nonce, code.authTime, access_token);
      if (code.scope.includes('offline_access')) {
        const rt = randomToken(32);
        await redis.set(rk.asRefresh(rt), JSON.stringify({ clientId: client.clientId, userId: user.id, scope: code.scope, authTime: code.authTime } satisfies StoredRefresh), 'EX', RT_TTL);
        body.refresh_token = rt;
      }
      return res.json(body);
    }

    if (grant === 'refresh_token') {
      const raw = await redis.getdel(rk.asRefresh(req.body.refresh_token ?? '')); // rotation: old RT dies
      if (!raw) return oauthError(res, 400, 'invalid_grant', 'refresh token invalid or already used');
      const stored = JSON.parse(raw) as StoredRefresh;
      if (stored.clientId !== client.clientId) return oauthError(res, 400, 'invalid_grant', 'wrong client');
      const user = findById(stored.userId)!;
      const access_token = await issueAccessToken(user.id, client.clientId, stored.scope, { username: user.username });
      const rt = randomToken(32);
      await redis.set(rk.asRefresh(rt), JSON.stringify(stored), 'EX', RT_TTL);
      return res.json({ token_type: 'Bearer', access_token, expires_in: ACCESS_TTL, refresh_token: rt, scope: stored.scope.join(' ') });
    }

    if (grant === 'client_credentials') {
      const requested = ((req.body.scope as string) ?? '').split(' ').filter(Boolean);
      const scope = requested.length ? requested : client.allowedScopes;
      if (scope.some((s) => !client.allowedScopes.includes(s))) return oauthError(res, 400, 'invalid_scope', 'scope not allowed');
      const access_token = await issueAccessToken(client.clientId, client.clientId, scope);
      return res.json({ token_type: 'Bearer', access_token, expires_in: ACCESS_TTL, scope: scope.join(' ') });
    }
    return oauthError(res, 400, 'unsupported_grant_type', grant);
  });

  // ---------- userinfo ----------
  r.get('/userinfo', async (req, res) => {
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    try {
      const { payload } = await jwtVerify(token ?? '', key.publicKey, { issuer: ISS, audience: API_AUDIENCE });
      const scope = String(payload.scope ?? '').split(' ');
      if (!scope.includes('openid')) return oauthError(res, 403, 'insufficient_scope', 'openid scope required');
      const user = findById(String(payload.sub));
      if (!user) return oauthError(res, 404, 'invalid_token', 'user gone');
      const u = toPublic(user);
      res.json({
        sub: u.id,
        ...(scope.includes('profile') && { name: u.name, preferred_username: u.username }),
        ...(scope.includes('email') && { email: u.email, email_verified: true }),
        ...(scope.includes('roles') && { roles: u.roles }),
      });
    } catch {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      oauthError(res, 401, 'invalid_token', 'access token invalid or expired');
    }
  });

  // ---------- introspection & revocation ----------
  r.post('/introspect', async (req, res) => {
    const { client } = clientFromRequest(req);
    if (!client || client.type !== 'confidential') return oauthError(res, 401, 'invalid_client', 'confidential client required');
    try {
      const { payload } = await jwtVerify(req.body.token ?? '', key.publicKey, { issuer: ISS });
      return res.json({ active: true, ...payload });
    } catch {
      const rt = await redis.get(rk.asRefresh(req.body.token ?? ''));
      return res.json(rt ? { active: true, token_type: 'refresh_token', ...JSON.parse(rt) } : { active: false });
    }
  });

  r.post('/revoke', async (req, res) => {
    const { client } = clientFromRequest(req);
    if (!client) return oauthError(res, 401, 'invalid_client', 'client authentication failed');
    await redis.del(rk.asRefresh(req.body.token ?? ''));
    res.status(200).end(); // RFC 7009: always 200
  });

  return r;
}

import { Router, type NextFunction, type Request, type Response } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { z } from 'zod';
import { env, getRedis, HttpError } from '@authlab/core';
import { bearer } from '../lib/local-jwt';

/**
 * OAuth 2.0 – this API is the RESOURCE SERVER.
 * It does NOT log anyone in. It only checks: "was this access token issued by the
 * Authorization Server I trust, for ME (aud), and does it carry the SCOPE needed?"
 *
 * Tokens come from apps/auth-server via:
 *   - Authorization Code + PKCE (SPA acting for a user)  → /notes
 *   - Client Credentials (service acting for itself)      → /reports
 */
export const AS_AUDIENCE = 'authlab-api';
export const asJwks = createRemoteJWKSet(new URL(`${env.ISSUER}/jwks.json`), { cacheMaxAge: 10 * 60_000 });

interface AsClaims extends JWTPayload { scope: string; client_id: string; username?: string }

export const requireScope = (...needed: string[]) => async (req: Request, res: Response, next: NextFunction) => {
  let claims: AsClaims;
  try {
    ({ payload: claims } = await jwtVerify<AsClaims>(bearer(req), asJwks, {
      issuer: env.ISSUER, audience: AS_AUDIENCE, algorithms: ['RS256'], typ: 'at+jwt',
    }));
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(401, `Invalid access token: ${(e as Error).message}`, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  }
  const granted = claims.scope.split(' ');
  const missing = needed.filter((s) => !granted.includes(s));
  if (missing.length) {
    throw new HttpError(403, `insufficient_scope: needs ${missing.join(' ')}`, {
      'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${needed.join(' ')}"`,
    });
  }
  res.locals.claims = claims;
  next();
};

export const oauth2Router = Router();
const notesKey = (sub: string) => `notes:${sub}`;

oauth2Router.get('/notes', requireScope('notes:read'), async (_req, res) => {
  const c = res.locals.claims as AsClaims;
  const notes = (await getRedis().lrange(notesKey(c.sub!), 0, 49)).map((n) => JSON.parse(n));
  res.json({ method: 'oauth2', grantedScopes: c.scope, actingClient: c.client_id, onBehalfOf: c.sub, notes });
});

oauth2Router.post('/notes', requireScope('notes:write'), async (req, res) => {
  const c = res.locals.claims as AsClaims;
  const { text } = z.object({ text: z.string().min(1).max(200) }).parse(req.body);
  const note = { text, at: new Date().toISOString(), by: c.client_id };
  await getRedis().lpush(notesKey(c.sub!), JSON.stringify(note));
  res.status(201).json(note);
});

/** Machine-to-machine resource: subject is the CLIENT itself, no user involved */
oauth2Router.get('/reports', requireScope('reports:read'), (_req, res) => {
  const c = res.locals.claims as AsClaims;
  res.json({ method: 'oauth2-client-credentials', client: c.client_id, report: { activeUsers: 2, apiCallsToday: 1234 } });
});

/**
 * Demo helper: run the Client Credentials grant server-side (a backend service would
 * do this – a browser must never hold a client secret) and call /reports with it.
 */
oauth2Router.post('/demo/client-credentials', async (_req, res) => {
  const tokenRes = await fetch(`${env.ISSUER}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from('authlab-reporting-service:reporting-secret').toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'reports:read' }),
  });
  const token = (await tokenRes.json()) as { access_token?: string };
  if (!token.access_token) return res.status(502).json({ step: 'token', token });
  const apiRes = await fetch(`${env.API_ORIGIN}/api/oauth2/reports`, { headers: { Authorization: `Bearer ${token.access_token}` } });
  res.json({ step1_tokenResponse: token, step2_resourceResponse: await apiRes.json() });
});

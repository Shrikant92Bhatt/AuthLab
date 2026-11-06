import { Router, type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { env, findById, getRedis, HttpError, isProd, randomToken, rk, toPublic, verifyCredentials } from '@authlab/core';
import { loginLimiter } from '../lib/rate-limit';
import { requireJwt, signAccessToken, type AppClaims } from '../lib/local-jwt';

/**
 * Access + Refresh tokens with ROTATION and REUSE DETECTION (OAuth 2.0 Security BCP).
 *
 *  access token : JWT, short-lived (env.ACCESS_TOKEN_TTL, default 60 s), kept in JS memory only
 *  refresh token: opaque random, long-lived, HttpOnly+SameSite=Strict cookie scoped to /api/tokens
 *
 *  Every refresh → old RT marked "used", new RT issued in the same *family*.
 *  If a USED RT is presented again → it was stolen → revoke the whole family.
 */
export const TOKENS_AUDIENCE = 'authlab-api:tokens';
const RT_COOKIE = 'authlab.rt';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

interface RtRecord { userId: string; familyId: string; used: '0' | '1'; createdAt: string }

const cookieOpts = { httpOnly: true, secure: isProd, sameSite: 'strict' as const, path: '/api/tokens', maxAge: env.REFRESH_TOKEN_TTL * 1000 };

async function issueRefresh(userId: string, familyId: string) {
  const token = randomToken(32);
  const id = sha(token); // store only a hash – a Redis dump does not leak usable tokens
  const redis = getRedis();
  await redis.hset(rk.refresh(id), { userId, familyId, used: '0', createdAt: new Date().toISOString() } satisfies RtRecord);
  await redis.expire(rk.refresh(id), env.REFRESH_TOKEN_TTL);
  await redis.sadd(rk.refreshFamily(familyId), id);
  await redis.expire(rk.refreshFamily(familyId), env.REFRESH_TOKEN_TTL);
  return token;
}

async function revokeFamily(familyId: string) {
  const redis = getRedis();
  const ids = await redis.smembers(rk.refreshFamily(familyId));
  if (ids.length) await redis.del(...ids.map(rk.refresh));
  await redis.del(rk.refreshFamily(familyId));
  return ids.length;
}

/** In dev we also echo the RT so the UI can demo a replay attack. Never do this in prod. */
const respond = async (res: Response, userId: string, refreshToken: string, extra: Record<string, unknown> = {}) => {
  const user = toPublic(findById(userId)!);
  const access_token = await signAccessToken(user, TOKENS_AUDIENCE, env.ACCESS_TOKEN_TTL);
  res.cookie(RT_COOKIE, refreshToken, cookieOpts);
  res.json({ token_type: 'Bearer', access_token, expires_in: env.ACCESS_TOKEN_TTL, ...(isProd ? {} : { debug_refresh_token: refreshToken }), ...extra });
};

// Custom header can't be sent cross-site without CORS preflight → extra CSRF guard on cookie endpoints
const requireXhr = (req: Request) => {
  if (!req.get('x-requested-with')) throw new HttpError(403, 'Missing X-Requested-With header');
};

export const tokensRouter = Router();
const Login = z.object({ username: z.string().min(1), password: z.string().min(1) });

tokensRouter.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = Login.parse(req.body);
  const user = await verifyCredentials(username, password);
  if (!user) throw new HttpError(401, 'Invalid username or password');
  const familyId = randomToken(12);
  await respond(res, user.id, await issueRefresh(user.id, familyId), { familyId });
});

tokensRouter.post('/refresh', async (req, res) => {
  requireXhr(req);
  const presented: string | undefined = (!isProd && req.body?.refresh_token) || req.cookies[RT_COOKIE];
  if (!presented) throw new HttpError(401, 'No refresh token');
  const redis = getRedis();
  const id = sha(presented);
  const rec = (await redis.hgetall(rk.refresh(id))) as unknown as RtRecord;
  if (!rec.userId) {
    res.clearCookie(RT_COOKIE, { path: '/api/tokens' });
    throw new HttpError(401, 'Refresh token invalid, expired or revoked');
  }

  // Atomically flip used 0 → 1. If it was already 1 → REUSE.
  // Lua script = atomic in Redis, so two concurrent refreshes can't both succeed.
  const prev = (await redis.eval(
    "local v = redis.call('HGET', KEYS[1], 'used'); redis.call('HSET', KEYS[1], 'used', '1'); return v",
    1,
    rk.refresh(id),
  )) as string | null;
  if (prev === '1') {
    const killed = await revokeFamily(rec.familyId);
    res.clearCookie(RT_COOKIE, { path: '/api/tokens' });
    throw new HttpError(401, `Refresh token REUSE detected – revoked entire token family (${killed} tokens). User must log in again.`);
  }
  await respond(res, rec.userId, await issueRefresh(rec.userId, rec.familyId), { rotated: true, familyId: rec.familyId });
});

tokensRouter.get('/profile', requireJwt(TOKENS_AUDIENCE), (_req, res) => {
  const c = res.locals.claims as AppClaims;
  res.json({ method: 'access+refresh', claims: c, expiresInSeconds: (c.exp ?? 0) - Math.floor(Date.now() / 1000) });
});

tokensRouter.post('/logout', async (req, res) => {
  requireXhr(req);
  const presented = req.cookies[RT_COOKIE];
  let revoked = 0;
  if (presented) {
    const rec = (await getRedis().hgetall(rk.refresh(sha(presented)))) as unknown as RtRecord;
    if (rec.familyId) revoked = await revokeFamily(rec.familyId);
  }
  res.clearCookie(RT_COOKIE, { path: '/api/tokens' });
  res.json({ ok: true, revoked });
});

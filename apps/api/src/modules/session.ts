import { Router } from 'express';
import { z } from 'zod';
import { getRedis, HttpError, rk, toPublic, verifyCredentials } from '@authlab/core';
import { loginLimiter } from '../lib/rate-limit';
import { clearSessionCookie, destroy, establishSession, requireCsrf, requireSession } from '../lib/session';

/**
 * Stateful session auth:
 *   login → server stores {user} in Redis under random id → Set-Cookie: authlab.sid=<signed id>
 *   later  → browser auto-sends cookie → server loads session from Redis
 * Logout/revocation is instant (delete the Redis key).
 */
const Login = z.object({ username: z.string().min(1), password: z.string().min(1) });

export const sessionRouter = Router();

sessionRouter.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = Login.parse(req.body);
  const user = await verifyCredentials(username, password);
  if (!user) throw new HttpError(401, 'Invalid username or password'); // generic message: no user enumeration
  await establishSession(req, toPublic(user), 'session');
  res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
});

sessionRouter.get('/me', requireSession(), async (req, res) => {
  const ttl = await getRedis().ttl(`${rk.session}${req.sessionID}`);
  res.json({
    method: req.session.method,
    user: req.session.user,
    csrfToken: req.session.csrfToken,
    session: {
      redisKey: `${rk.session}${req.sessionID.slice(0, 8)}…`,
      loginAt: new Date(req.session.loginAt ?? Date.now()).toISOString(),
      expiresInSeconds: ttl,
      cookie: 'authlab.sid (HttpOnly; SameSite=Lax; Secure in prod) – invisible to JavaScript',
    },
  });
});

/** State-changing request: cookie is sent automatically, so CSRF token is required */
sessionRouter.post('/transfer', requireSession(), requireCsrf, (req, res) => {
  res.json({ ok: true, message: `Transfer of ₹${Number(req.body?.amount ?? 0)} accepted for ${req.session.user!.username} (CSRF token valid)` });
});

sessionRouter.post('/logout', requireSession(), requireCsrf, async (req, res) => {
  await destroy(req); // server-side revocation
  clearSessionCookie(res);
  res.json({ ok: true });
});

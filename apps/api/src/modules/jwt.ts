import { Router } from 'express';
import { z } from 'zod';
import { decodeProtectedHeader } from 'jose';
import { getRedis, HttpError, rk, toPublic, verifyCredentials } from '@authlab/core';
import { loginLimiter } from '../lib/rate-limit';
import { bearer, localJwks, requireJwt, requireRole, signAccessToken, verifyLocal, type AppClaims } from '../lib/local-jwt';

/**
 * Bearer token = "whoever bears it, gets in". JWT = a self-contained, signed token format.
 *   header.payload.signature  (base64url, RS256)
 * Stateless verification (no DB hit) → scales horizontally / across microservices.
 * Trade-off: can't revoke before `exp` → we keep a Redis deny-list of `jti` on logout.
 */
export const JWT_AUDIENCE = 'authlab-api:jwt';
const TTL = 15 * 60;

const Login = z.object({ username: z.string().min(1), password: z.string().min(1) });

export const jwtRouter = Router();

jwtRouter.get('/.well-known/jwks.json', (_req, res) => res.json(localJwks()));

jwtRouter.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = Login.parse(req.body);
  const user = await verifyCredentials(username, password);
  if (!user) throw new HttpError(401, 'Invalid username or password');
  const token = await signAccessToken(toPublic(user), JWT_AUDIENCE, TTL);
  res.json({ token_type: 'Bearer', access_token: token, expires_in: TTL, header: decodeProtectedHeader(token) });
});

jwtRouter.get('/profile', requireJwt(JWT_AUDIENCE), (_req, res) => {
  const c = res.locals.claims as AppClaims;
  res.json({ method: 'jwt', message: `Verified signature with public key – no DB lookup needed.`, claims: c });
});

/** Authorization via claims (RBAC) */
jwtRouter.get('/admin', requireJwt(JWT_AUDIENCE), requireRole('admin'), (_req, res) => {
  res.json({ ok: true, message: 'Welcome admin – role claim checked.' });
});

/** "Logout" for stateless tokens = deny-list the jti until it would have expired */
jwtRouter.post('/logout', async (req, res) => {
  const claims = await verifyLocal(bearer(req), JWT_AUDIENCE);
  const ttl = Math.max(1, (claims.exp ?? 0) - Math.floor(Date.now() / 1000));
  await getRedis().set(rk.jwtDeny(claims.jti!), '1', 'EX', ttl);
  res.json({ revoked: claims.jti, deniedForSeconds: ttl });
});

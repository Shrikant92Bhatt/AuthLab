import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { NextFunction, Request, Response } from 'express';
import { env, getRedis, HttpError, loadOrCreateKey, randomToken, rk, type PublicUser, type SigningKey } from '@authlab/core';

/**
 * Tokens issued by THIS API (JWT demo + Access/Refresh demo).
 * RS256 = asymmetric: only the API can sign; any service with the public key (JWKS) can verify.
 */
let key: SigningKey;
export const initLocalKey = async () => { key = await loadOrCreateKey('api'); return key; };
export const localJwks = () => ({ keys: [key.publicJwk] });

export const LOCAL_ISSUER = env.API_ORIGIN;

export interface AppClaims extends JWTPayload {
  username: string;
  name: string;
  roles: string[];
}

export async function signAccessToken(user: PublicUser, audience: string, ttlSeconds: number) {
  return new SignJWT({ username: user.username, name: user.name, roles: user.roles })
    .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: 'JWT' })
    .setIssuer(LOCAL_ISSUER)
    .setAudience(audience)
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .setJti(randomToken(12)) // unique id → enables deny-listing on logout
    .sign(key.privateKey);
}

export function bearer(req: Request): string {
  const h = req.get('authorization') ?? '';
  const [scheme, token] = h.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token) {
    throw new HttpError(401, 'Missing Bearer token', { 'WWW-Authenticate': 'Bearer realm="authlab"' });
  }
  return token;
}

export async function verifyLocal(token: string, audience: string): Promise<AppClaims> {
  try {
    const { payload } = await jwtVerify<AppClaims>(token, key.publicKey, {
      issuer: LOCAL_ISSUER,
      audience,
      algorithms: ['RS256'], // pin alg → blocks "alg: none" & HS256/RS256 confusion attacks
      clockTolerance: 5,
    });
    if (payload.jti && (await getRedis().exists(rk.jwtDeny(payload.jti)))) throw new Error('revoked');
    return payload;
  } catch (e) {
    const msg = (e as Error).message === 'revoked' ? 'Token has been revoked' : `Invalid token: ${(e as Error).message}`;
    throw new HttpError(401, msg, { 'WWW-Authenticate': `Bearer error="invalid_token", error_description="${msg.replace(/"/g, "'")}"` });
  }
}

/** Express middleware: authenticate with a locally-issued bearer JWT */
export const requireJwt = (audience: string) => async (req: Request, res: Response, next: NextFunction) => {
  res.locals.claims = await verifyLocal(bearer(req), audience);
  next();
};

/** Authorization on top of authentication: role-based access control from token claims */
export const requireRole = (role: string) => (_req: Request, res: Response, next: NextFunction) => {
  const claims = res.locals.claims as AppClaims;
  if (!claims.roles?.includes(role)) throw new HttpError(403, `Forbidden: requires role "${role}"`);
  next();
};

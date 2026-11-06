import session from 'express-session';
import { RedisStore } from 'connect-redis';
import type { NextFunction, Request, Response } from 'express';
import { env, getRedis, HttpError, isProd, randomToken, rk, safeEqual, type PublicUser } from '@authlab/core';

export type SessionMethod = 'session' | 'oidc' | 'saml';

declare module 'express-session' {
  interface SessionData {
    user: PublicUser;
    method: SessionMethod;
    csrfToken: string;
    loginAt: number;
    oidc?: { idToken: string; idClaims: Record<string, unknown>; userinfo: Record<string, unknown>; accessToken: string; refreshToken?: string; scope: string };
    saml?: { nameID: string; attributes: Record<string, unknown>; sessionIndex?: string; issuer?: string };
  }
}

/**
 * Server-side sessions stored in Redis (`sess:<id>`).
 * The browser only holds an opaque, signed session id cookie.
 */
export const SESSION_COOKIE = 'authlab.sid';

export const sessionMiddleware = session({
  name: SESSION_COOKIE, // don't advertise "connect.sid"
  store: new RedisStore({ client: getRedis(), prefix: rk.session, ttl: 60 * 30 }),
  secret: env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false, // no cookie until login (GDPR / less Redis garbage)
  rolling: true, // sliding expiration
  cookie: {
    httpOnly: true, // JS can't read it → XSS can't steal it
    secure: isProd, // HTTPS only in prod
    sameSite: 'lax', // blocks most CSRF; still allows top-level SAML/OIDC redirects back
    maxAge: 30 * 60 * 1000,
  },
});

/** Prevent session fixation: always issue a NEW session id at privilege change. */
export const regenerate = (req: Request) =>
  new Promise<void>((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));

export const destroy = (req: Request) =>
  new Promise<void>((resolve, reject) => req.session.destroy((e) => (e ? reject(e) : resolve())));

export async function establishSession(req: Request, user: PublicUser, method: SessionMethod, extra: Partial<Express.Request['session']> = {}) {
  await regenerate(req);
  req.session.user = user;
  req.session.method = method;
  req.session.csrfToken = randomToken(24);
  req.session.loginAt = Date.now();
  Object.assign(req.session, extra);
  await new Promise<void>((res, rej) => req.session.save((e) => (e ? rej(e) : res())));
}

export const requireSession = (method?: SessionMethod) => (req: Request, _res: Response, next: NextFunction) => {
  if (!req.session.user) throw new HttpError(401, 'Not logged in (no valid session cookie)');
  if (method && req.session.method !== method) throw new HttpError(401, `Session was created via "${req.session.method}", not "${method}"`);
  next();
};

/** Synchronizer-token CSRF check for state-changing requests on cookie-authenticated routes. */
export const requireCsrf = (req: Request, _res: Response, next: NextFunction) => {
  const sent = req.get('x-csrf-token') ?? '';
  if (!req.session.csrfToken || !safeEqual(sent, req.session.csrfToken)) throw new HttpError(403, 'CSRF token missing or invalid');
  next();
};

export const clearSessionCookie = (res: Response) =>
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'lax', secure: isProd });

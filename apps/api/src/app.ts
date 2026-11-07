import express, { type ErrorRequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { ZodError } from 'zod';
import { createLogger, env, getRedis, HttpError, initUsers, isProd } from '@authlab/core';
import { AUTH_METHODS } from '@authlab/shared';
import { globalLimiter } from './lib/rate-limit';
import { sessionMiddleware } from './lib/session';
import { initLocalKey } from './lib/local-jwt';
import { basicRouter } from './modules/basic';
import { digestRouter } from './modules/digest';
import { apiKeysRouter } from './modules/api-keys';
import { sessionRouter } from './modules/session';
import { jwtRouter } from './modules/jwt';
import { tokensRouter } from './modules/tokens';
import { oauth2Router } from './modules/oauth2';
import { oidcRouter } from './modules/oidc';
import { samlRouter } from './modules/saml';

const log = createLogger('api');

/** Builds the Express app. `main.ts` listens on a port; `vercel.ts` exports it as a function. */
export async function createApp() {
  await Promise.all([initUsers(), initLocalKey()]);
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1); // behind Vite proxy / nginx → correct req.ip for rate limiting
  app.use(helmet());
  app.use(cors({ origin: env.WEB_ORIGIN, credentials: true, exposedHeaders: ['WWW-Authenticate', 'RateLimit', 'RateLimit-Policy'] }));
  app.use(pinoHttp({ logger: log, autoLogging: { ignore: (req) => req.url === '/api/health' } }));
  app.use(express.json({ limit: '100kb' }));
  app.use(cookieParser());
  app.use('/api', globalLimiter);

  app.get('/api/health', async (_req, res) => res.json({ ok: true, redis: await getRedis().ping() }));
  app.get('/api/meta', (_req, res) => res.json(AUTH_METHODS));

  // Stateless / header-based schemes – no session middleware
  app.use('/api/basic', basicRouter);
  app.use('/api/digest', digestRouter);
  app.use('/api/api-keys', apiKeysRouter);
  app.use('/api/jwt', jwtRouter);
  app.use('/api/tokens', tokensRouter);
  app.use('/api/oauth2', oauth2Router);

  // Cookie-session based (session login, OIDC BFF, SAML SP all end in a server session)
  app.use('/api/session', sessionMiddleware, sessionRouter);
  app.use('/api/oidc', sessionMiddleware, oidcRouter);
  app.use('/api/saml', sessionMiddleware, samlRouter);

  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    if (err instanceof HttpError) {
      for (const [k, v] of Object.entries(err.headers)) res.setHeader(k, v);
      return res.status(err.status).json({ error: err.message });
    }
    if (err instanceof ZodError) return res.status(400).json({ error: 'Validation failed', issues: err.issues });
    log.error(err);
    res.status(500).json({ error: isProd ? 'Internal error' : String(err?.message ?? err) });
  };
  app.use(onError);

  return app;
}


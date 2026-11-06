import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { randomBytes } from 'node:crypto';
import { createLogger, env, getRedis, initUsers, loadOrCreateKey } from '@authlab/core';
import { oauthRouter } from './oauth';
import { samlRouter } from './saml';

const log = createLogger('auth-server');

async function bootstrap() {
  await initUsers();
  const key = await loadOrCreateKey('auth-server');
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use((_req, res, next) => { res.locals.cspNonce = randomBytes(16).toString('base64'); next(); });
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        'script-src': ["'self'", (_req, res) => `'nonce-${(res as express.Response).locals.cspNonce}'`],
        'style-src': ["'self'", (_req, res) => `'nonce-${(res as express.Response).locals.cspNonce}'`],
        // SAML POST binding / OAuth redirects target the web origin
        'form-action': ["'self'", env.WEB_ORIGIN],
      },
    },
  }));
  app.use(pinoHttp({ logger: log, autoLogging: { ignore: (req) => req.url === '/health' } }));
  app.use(express.urlencoded({ extended: false, limit: '200kb' }));
  app.use(express.json({ limit: '100kb' }));

  // Only the back-channel endpoints that a SPA calls directly need CORS
  const spaCors = cors({ origin: env.WEB_ORIGIN, methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] });
  app.use(['/token', '/userinfo', '/jwks.json', '/.well-known/openid-configuration', '/revoke'], spaCors);

  app.get('/health', async (_req, res) => res.json({ ok: true, redis: await getRedis().ping() }));
  app.use(oauthRouter(key));
  app.use(await samlRouter());

  app.listen(env.AUTH_SERVER_PORT, () => log.info(`Auth server (OAuth2 AS / OIDC OP / SAML IdP) on ${env.ISSUER}`));
}

bootstrap().catch((e) => { log.error(e); process.exit(1); });

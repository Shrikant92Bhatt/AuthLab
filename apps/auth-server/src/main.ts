import { createLogger, env } from '@authlab/core';
import { createApp } from './app';

const log = createLogger('auth-server');

createApp()
  .then((app) => app.listen(env.AUTH_SERVER_PORT, () => log.info(`Auth server (OAuth2 AS / OIDC OP / SAML IdP) on ${env.ISSUER}`)))
  .catch((e) => { log.error(e); process.exit(1); });

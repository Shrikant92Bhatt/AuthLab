import { createLogger, env } from '@authlab/core';
import { createApp } from './app';

const log = createLogger('api');

createApp()
  .then((app) => app.listen(env.API_PORT, () => log.info(`API on http://localhost:${env.API_PORT}`)))
  .catch((e) => { log.error(e); process.exit(1); });

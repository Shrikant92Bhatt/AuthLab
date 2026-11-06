import pino from 'pino';
import { isProd } from './config';

export const createLogger = (name: string) =>
  pino({
    name,
    level: process.env.LOG_LEVEL ?? 'info',
    // Never log credentials
    redact: {
      paths: ['req.headers.authorization', 'req.headers.cookie', 'req.headers["x-api-key"]', 'password', '*.password'],
      censor: '[REDACTED]',
    },
    transport: isProd ? undefined : { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } },
  });

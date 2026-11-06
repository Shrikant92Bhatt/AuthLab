import { rateLimit, type Options } from 'express-rate-limit';
import { RedisStore, type RedisReply } from 'rate-limit-redis';
import { getRedis } from '@authlab/core';

/** Redis-backed limiter: counters are shared across all API instances. */
const store = (prefix: string) =>
  new RedisStore({
    prefix: `rl:${prefix}:`,
    sendCommand: (command: string, ...args: string[]) => getRedis().call(command, ...args) as Promise<RedisReply>,
  });

const make = (prefix: string, opts: Partial<Options>) =>
  rateLimit({
    standardHeaders: 'draft-7', // RateLimit-* headers
    legacyHeaders: false,
    store: store(prefix),
    message: { error: 'Too many requests, slow down.' },
    ...opts,
  });

/** Global safety net */
export const globalLimiter = make('global', { windowMs: 60_000, limit: 300 });

/** Brute-force protection for anything that checks a password. Keyed by IP + username. */
export const loginLimiter = make('login', {
  windowMs: 15 * 60_000,
  limit: 10,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.username ?? '').toLowerCase()}`,
});

/** Per-API-key quota (metering is a core reason API keys exist) */
export const apiKeyLimiter = make('apikey', {
  windowMs: 60_000,
  limit: 20,
  keyGenerator: (req, res) => String(res.locals.apiKeyPrefix ?? req.ip),
});

import { Router, type NextFunction, type Request, type Response } from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { findById, getRedis, HttpError, rk, safeEqual, toPublic, verifyCredentials } from '@authlab/core';
import { apiKeyLimiter, loginLimiter } from '../lib/rate-limit';

/**
 * API keys:  ak_<8-char public prefix>_<43-char secret>
 *
 * - Shown ONCE at creation; only SHA-256(key) is stored. (Keys are 256-bit random,
 *   so a fast hash is fine – bcrypt is for low-entropy human passwords.)
 * - Prefix = O(1) lookup + safe to log/display ("ak_3f9a…").
 * - Scoped, revocable, rate-limited per key.
 */
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

interface StoredKey { userId: string; name: string; hash: string; scopes: string; createdAt: string; lastUsedAt?: string }

const CreateSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
  name: z.string().min(1).max(50).default('my-key'),
  scopes: z.array(z.enum(['data:read', 'data:write'])).default(['data:read']),
});

export const apiKeysRouter = Router();

/** Create a key (in real life: from a logged-in developer dashboard) */
apiKeysRouter.post('/', loginLimiter, async (req, res) => {
  const body = CreateSchema.parse(req.body);
  const user = await verifyCredentials(body.username, body.password);
  if (!user) throw new HttpError(401, 'Invalid username or password');

  const prefix = randomBytes(4).toString('hex');
  const secret = randomBytes(32).toString('base64url');
  const apiKey = `ak_${prefix}_${secret}`;
  const redis = getRedis();
  const record: StoredKey = { userId: user.id, name: body.name, hash: sha256(apiKey), scopes: body.scopes.join(' '), createdAt: new Date().toISOString() };
  await redis.hset(rk.apiKey(prefix), record as never);
  await redis.sadd(rk.apiKeysOfUser(user.id), prefix);

  res.status(201).json({
    apiKey, // the only time the full key is ever returned
    prefix: `ak_${prefix}`,
    stored: { ...record, hash: `${record.hash.slice(0, 16)}… (sha256)` },
    warning: 'Copy it now – it cannot be shown again.',
  });
});

/** Authentication middleware */
export async function requireApiKey(req: Request, res: Response, next: NextFunction) {
  const key = req.get('x-api-key') ?? '';
  const m = /^ak_([0-9a-f]{8})_[A-Za-z0-9_-]{43}$/.exec(key);
  if (!m) throw new HttpError(401, 'Missing or malformed X-API-Key');
  const redis = getRedis();
  const stored = (await redis.hgetall(rk.apiKey(m[1]!))) as unknown as StoredKey;
  if (!stored.hash || !safeEqual(sha256(key), stored.hash)) throw new HttpError(401, 'Invalid or revoked API key');
  await redis.hset(rk.apiKey(m[1]!), 'lastUsedAt', new Date().toISOString());
  res.locals.apiKeyPrefix = m[1];
  res.locals.apiKey = stored;
  next();
}

const requireScope = (scope: string) => (_req: Request, res: Response, next: NextFunction) => {
  if (!String(res.locals.apiKey.scopes).split(' ').includes(scope)) throw new HttpError(403, `API key lacks scope ${scope}`);
  next();
};

apiKeysRouter.get('/data', requireApiKey, apiKeyLimiter, requireScope('data:read'), (_req, res) => {
  const k = res.locals.apiKey as StoredKey;
  const owner = findById(k.userId);
  res.json({
    method: 'api-key',
    message: `Data for key "${k.name}" (ak_${res.locals.apiKeyPrefix}…)`,
    owner: owner ? toPublic(owner) : null,
    scopes: k.scopes,
    lastUsedAt: k.lastUsedAt ?? null,
    data: [{ symbol: 'NIFTYBEES', ltp: 287.4 }, { symbol: 'BANKBEES', ltp: 568.1 }],
  });
});

apiKeysRouter.post('/data', requireApiKey, apiKeyLimiter, requireScope('data:write'), (_req, res) => {
  res.json({ ok: true, message: 'Write allowed – key has data:write' });
});

/** Revoke the key used for this request */
apiKeysRouter.delete('/self', requireApiKey, async (_req, res) => {
  const redis = getRedis();
  const prefix = res.locals.apiKeyPrefix as string;
  await redis.del(rk.apiKey(prefix));
  await redis.srem(rk.apiKeysOfUser((res.locals.apiKey as StoredKey).userId), prefix);
  res.json({ revoked: `ak_${prefix}` });
});

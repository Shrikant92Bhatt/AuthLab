import { Redis } from 'ioredis';
import { env } from './config';

/**
 * Single Redis connection per process.
 * Used for: sessions, refresh-token families, JWT deny-list, API-key hashes,
 * digest nonces, OAuth auth codes / state / PKCE, rate limiting.
 */
let client: Redis | undefined;

export function getRedis(): Redis {
  if (!client) {
    if (process.env.VERCEL && !process.env.REDIS_URL && !process.env.KV_URL) {
      throw new Error('Redis is not connected. In Vercel, add a Redis database (Storage → Upstash for Redis) and connect it to this project, then redeploy.');
    }
    client = new Redis(env.REDIS_URL, { maxRetriesPerRequest: 3, lazyConnect: false });
    client.on('error', (e) => console.error('[redis]', e.message));
  }
  return client;
}

/** Namespaced keys keep each auth method's data separate and easy to inspect. */
export const rk = {
  session: 'sess:',
  digestNonce: (n: string) => `digest:nonce:${n}`,
  apiKey: (prefix: string) => `apikey:${prefix}`,
  apiKeysOfUser: (userId: string) => `apikey:user:${userId}`,
  jwtDeny: (jti: string) => `jwt:deny:${jti}`,
  refresh: (tokenId: string) => `rt:${tokenId}`,
  refreshFamily: (familyId: string) => `rt:family:${familyId}`,
  oauthState: (state: string) => `oauth:state:${state}`,
  authCode: (code: string) => `as:code:${code}`,
  asRefresh: (token: string) => `as:rt:${token}`,
  samlRequest: (id: string) => `saml:req:${id}`,
};

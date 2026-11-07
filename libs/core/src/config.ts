import { config as loadDotenv } from 'dotenv';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';

// Nx runs each project's scripts from the project folder, so look for the
// workspace-root .env as well as a local one.
for (const p of [resolve(process.cwd(), '.env'), resolve(process.cwd(), '../../.env')]) {
  if (existsSync(p)) loadDotenv({ path: p });
}

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  REDIS_URL: z.string().default('redis://localhost:6379'),

  API_PORT: z.coerce.number().default(3333),
  API_ORIGIN: z.string().default('http://localhost:3333'),
  WEB_ORIGIN: z.string().default('http://localhost:4200'),
  SESSION_SECRET: z.string().min(32).default('dev-only-session-secret-change-me-please-123'),
  ACCESS_TOKEN_TTL: z.coerce.number().default(60),
  REFRESH_TOKEN_TTL: z.coerce.number().default(60 * 60 * 24 * 7),

  AUTH_SERVER_PORT: z.coerce.number().default(4000),
  ISSUER: z.string().default('http://localhost:4000'),
  OIDC_CLIENT_ID: z.string().default('authlab-bff'),
  OIDC_CLIENT_SECRET: z.string().default('bff-secret-change-me'),
});

/** Validated, typed environment. Fails fast on bad config (12-factor). */
// Vercel's Redis integrations expose the connection string under different names.
export const env = EnvSchema.parse({ ...process.env, REDIS_URL: process.env.REDIS_URL ?? process.env.KV_URL });
export type Env = z.infer<typeof EnvSchema>;
export const isProd = env.NODE_ENV === 'production';

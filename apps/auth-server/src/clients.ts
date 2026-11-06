import { createHash } from 'node:crypto';
import { env, safeEqual } from '@authlab/core';

export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials';

export interface OAuthClient {
  clientId: string;
  name: string;
  /** Public clients (SPA, mobile) cannot keep a secret → PKCE is mandatory */
  type: 'public' | 'confidential';
  secretSha256?: string;
  redirectUris: string[];
  grantTypes: GrantType[];
  allowedScopes: string[];
}

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/** Client registry. Production: a DB table managed via dynamic client registration / admin UI. */
export const CLIENTS: OAuthClient[] = [
  {
    clientId: 'authlab-spa',
    name: 'AuthLab SPA (public client, PKCE)',
    type: 'public',
    redirectUris: [`${env.WEB_ORIGIN}/oauth2/callback`],
    grantTypes: ['authorization_code', 'refresh_token'],
    allowedScopes: ['notes:read', 'notes:write', 'offline_access'],
  },
  {
    clientId: env.OIDC_CLIENT_ID,
    name: 'AuthLab BFF (confidential client, OIDC)',
    type: 'confidential',
    secretSha256: sha(env.OIDC_CLIENT_SECRET),
    // The browser reaches the API through the web origin (Vite proxy / reverse proxy in prod)
    redirectUris: [`${env.WEB_ORIGIN}/api/oidc/callback`],
    grantTypes: ['authorization_code', 'refresh_token'],
    allowedScopes: ['openid', 'profile', 'email', 'roles', 'notes:read', 'offline_access'],
  },
  {
    clientId: 'authlab-reporting-service',
    name: 'Reporting micro-service (machine-to-machine)',
    type: 'confidential',
    secretSha256: sha('reporting-secret'),
    redirectUris: [],
    grantTypes: ['client_credentials'],
    allowedScopes: ['reports:read'],
  },
];

export const findClient = (id: string) => CLIENTS.find((c) => c.clientId === id);

export function authenticateClient(id: string, secret: string | undefined): OAuthClient | null {
  const c = findClient(id);
  if (!c) return null;
  if (c.type === 'public') return secret ? null : c;
  if (!secret || !c.secretSha256) return null;
  return safeEqual(sha(secret), c.secretSha256) ? c : null;
}

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Sign you in (share your user id)',
  profile: 'Read your name and username',
  email: 'Read your email address',
  roles: 'Read your roles',
  offline_access: 'Stay signed in (refresh token)',
  'notes:read': 'Read your notes',
  'notes:write': 'Create and edit your notes',
  'reports:read': 'Read reports',
};

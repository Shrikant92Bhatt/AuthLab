/** Shared, isomorphic catalog used by the web app and the API (/api/meta). */

export type AuthCategory = 'HTTP auth scheme' | 'Credential' | 'Stateful auth' | 'Token format' | 'Token strategy' | 'Authorization framework' | 'Identity protocol';

export interface AuthMethod {
  id: string;
  title: string;
  category: AuthCategory;
  /** Answers "who are you?" (AuthN) and/or "what may you do?" (AuthZ) */
  answers: ('Authentication' | 'Authorization' | 'Federation / SSO')[];
  stateful: boolean;
  credentialIn: string;
  bestFor: string;
  avoidWhen: string;
  apiBase: string;
}

export const AUTH_METHODS: AuthMethod[] = [
  {
    id: 'basic', title: 'Basic Authentication', category: 'HTTP auth scheme', answers: ['Authentication'], stateful: false,
    credentialIn: 'Authorization: Basic base64(user:pass) on EVERY request',
    bestFor: 'Internal tools, quick scripts, server-to-server over TLS', avoidWhen: 'Public apps; no logout, password sent each call',
    apiBase: '/api/basic',
  },
  {
    id: 'digest', title: 'Digest Authentication', category: 'HTTP auth scheme', answers: ['Authentication'], stateful: true,
    credentialIn: 'Authorization: Digest username, nonce, response=H(HA1:nonce:nc:cnonce:qop:HA2)',
    bestFor: 'Legacy devices (IP cameras, routers, SIP) without TLS', avoidWhen: 'Anything modern – server must store password-equivalent HA1',
    apiBase: '/api/digest',
  },
  {
    id: 'api-key', title: 'API Keys', category: 'Credential', answers: ['Authentication'], stateful: true,
    credentialIn: 'X-API-Key: ak_<prefix>_<secret>',
    bestFor: 'Machine/developer access to public APIs, metering, rate limits', avoidWhen: 'End-user login; keys identify an app, not a person',
    apiBase: '/api/api-keys',
  },
  {
    id: 'session', title: 'Session-Based Authentication', category: 'Stateful auth', answers: ['Authentication'], stateful: true,
    credentialIn: 'Cookie: sid=<opaque id> (HttpOnly, Secure, SameSite)',
    bestFor: 'Classic server-rendered / same-site web apps', avoidWhen: 'Many independent APIs/mobile clients across domains',
    apiBase: '/api/session',
  },
  {
    id: 'jwt', title: 'Bearer Tokens & JWT', category: 'Token format', answers: ['Authentication', 'Authorization'], stateful: false,
    credentialIn: 'Authorization: Bearer <header.payload.signature>',
    bestFor: 'Stateless APIs, microservices verifying with a public key', avoidWhen: 'You need instant revocation without a deny-list',
    apiBase: '/api/jwt',
  },
  {
    id: 'tokens', title: 'Access & Refresh Tokens', category: 'Token strategy', answers: ['Authentication', 'Authorization'], stateful: true,
    credentialIn: 'Short-lived access token (memory) + rotating refresh token (HttpOnly cookie)',
    bestFor: 'SPAs/mobile needing long sessions with short-lived credentials', avoidWhen: 'Simple same-site apps where a session cookie suffices',
    apiBase: '/api/tokens',
  },
  {
    id: 'oauth2', title: 'OAuth 2.0', category: 'Authorization framework', answers: ['Authorization'], stateful: true,
    credentialIn: 'Access token obtained via Authorization Code + PKCE (or Client Credentials)',
    bestFor: 'Delegated access: "let App X read my data at Service Y"', avoidWhen: 'Using it alone as "login" – that is what OIDC is for',
    apiBase: '/api/oauth2',
  },
  {
    id: 'oidc', title: 'OpenID Connect (OIDC)', category: 'Identity protocol', answers: ['Authentication', 'Federation / SSO'], stateful: true,
    credentialIn: 'ID Token (JWT) + access token from the OpenID Provider',
    bestFor: '"Sign in with Google/Okta/Azure AD", modern SSO', avoidWhen: 'Never really – it is the modern default for federated login',
    apiBase: '/api/oidc',
  },
  {
    id: 'saml', title: 'SAML 2.0', category: 'Identity protocol', answers: ['Authentication', 'Federation / SSO'], stateful: true,
    credentialIn: 'Signed XML <Assertion> POSTed by the browser to the SP ACS URL',
    bestFor: 'Enterprise SSO (ADFS, Okta, PingFederate) with legacy apps', avoidWhen: 'Mobile/native apps, new greenfield systems',
    apiBase: '/api/saml',
  },
];

export const DEMO_USERS = [
  { username: 'alice', password: 'Password123!', roles: ['admin', 'user'] },
  { username: 'bob', password: 'Password123!', roles: ['user'] },
];

export const PORTS = { web: 4200, api: 3333, authServer: 4000 } as const;

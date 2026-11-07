/**
 * Generates the signing keys and secrets a serverless deploy needs as env vars,
 * written to `.env.vercel` (git-ignored). Paste them into each Vercel project.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import selfsigned from 'selfsigned';

const rsa = () => generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const oneLine = (pem: string) => JSON.stringify(pem.replace(/\r/g, '').trim()); // "\n" escapes, read back by libs/core/src/keys.ts
const saml = selfsigned.generate([{ name: 'commonName', value: 'idp.authlab.local' }], { keySize: 2048, days: 3650, algorithm: 'sha256' });
const oidcSecret = randomBytes(24).toString('base64url');

const text = `# ---------- web project (UI + apps/api) ----------
SESSION_SECRET=${randomBytes(32).toString('base64url')}
OIDC_CLIENT_SECRET=${oidcSecret}
API_JWT_PRIVATE_KEY_PEM=${oneLine(rsa())}

# ---------- auth project (apps/auth-server) ----------
OIDC_CLIENT_SECRET=${oidcSecret}
AUTH_SERVER_JWT_PRIVATE_KEY_PEM=${oneLine(rsa())}
IDP_SAML_KEY_PEM=${oneLine(saml.private)}
IDP_SAML_CERT_PEM=${oneLine(saml.cert)}
`;
writeFileSync('.env.vercel', text, { mode: 0o600 });
console.log('Wrote .env.vercel');

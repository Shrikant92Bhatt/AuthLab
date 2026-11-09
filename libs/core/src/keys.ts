import { calculateJwkThumbprint, exportJWK, exportPKCS8, generateKeyPair, importPKCS8, importSPKI, type JWK, type KeyLike } from 'jose';
import { createPublicKey } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { getRedis } from './redis';

/**
 * Keys can be supplied as env vars (needed on serverless hosts like Vercel, where the
 * disk is not shared or persistent). `\n` escapes are accepted for one-line values.
 * Names: <NAME>_JWT_PRIVATE_KEY_PEM, <NAME>_SAML_KEY_PEM, <NAME>_SAML_CERT_PEM
 * with NAME upper-cased and dashes → underscores (e.g. AUTH_SERVER_JWT_PRIVATE_KEY_PEM).
 */
const envPem = (name: string, suffix: string) => {
  const v = process.env[`${name.toUpperCase().replace(/-/g, '_')}_${suffix}`];
  if (!v) return undefined;
  return v.trim().replace(/^"|"$/g, '').replace(/\\r/g, '').replace(/\\n/g, '\n').replace(/\r/g, '').trim() + '\n';
};

/**
 * Serverless instances (Vercel) don't share a disk, so a key generated on one instance would be
 * unknown to the others. There, the first instance generates the key and stores it in Redis
 * (SET NX, so concurrent cold starts agree on one key); everyone else reads it.
 * Env vars still win, which is the better choice for anything real (rotate via a secret manager).
 */
const serverless = () => Boolean(process.env.VERCEL);
async function sharedInRedis(id: string, make: () => Promise<string>): Promise<string> {
  const redis = getRedis();
  const k = `keys:${id}`;
  const existing = await redis.get(k);
  if (existing) return existing;
  await redis.set(k, await make(), 'NX');
  return (await redis.get(k))!;
}
const newRsaPem = async () => exportPKCS8((await generateKeyPair('RS256', { modulusLength: 2048, extractable: true })).privateKey);
const spkiOf = (privatePem: string) => createPublicKey(privatePem).export({ type: 'spki', format: 'pem' }).toString();

const keysDir = () => (existsSync(resolve(process.cwd(), 'nx.json')) ? resolve(process.cwd(), '.keys') : resolve(process.cwd(), '../../.keys'));

export interface SigningKey {
  kid: string;
  alg: 'RS256';
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
  privatePem: string;
  publicPem: string;
}

/**
 * RS256 key pair persisted to <workspace>/.keys so tokens survive restarts.
 * Production: load from a KMS / secrets manager and rotate using `kid`.
 */
export async function loadOrCreateKey(name: string): Promise<SigningKey> {
  let privatePem: string;
  let publicPem: string;
  const fromEnv = envPem(name, 'JWT_PRIVATE_KEY_PEM');
  if (fromEnv) return toSigningKey(name, fromEnv, spkiOf(fromEnv));
  if (serverless()) {
    const shared = await sharedInRedis(`${name}:jwt`, newRsaPem);
    return toSigningKey(name, shared, spkiOf(shared));
  }

  const dir = keysDir();
  mkdirSync(dir, { recursive: true });
  const privPath = resolve(dir, `${name}.private.pem`);
  const pubPath = resolve(dir, `${name}.public.pem`);
  if (existsSync(privPath) && existsSync(pubPath)) {
    privatePem = readFileSync(privPath, 'utf8');
    publicPem = readFileSync(pubPath, 'utf8');
  } else {
    privatePem = await newRsaPem();
    publicPem = spkiOf(privatePem);
    writeFileSync(privPath, privatePem, { mode: 0o600 });
    writeFileSync(pubPath, publicPem);
  }
  return toSigningKey(name, privatePem, publicPem);
}

async function toSigningKey(name: string, privatePem: string, publicPem: string): Promise<SigningKey> {
  const privateKey = await importPKCS8(privatePem, 'RS256', { extractable: true });
  const publicKey = await importSPKI(publicPem, 'RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  // RFC 7638 thumbprint: unique per key (the old PEM-suffix id was the same for every key)
  const kid = `${name}-${(await calculateJwkThumbprint(jwk)).slice(0, 16)}`;
  const publicJwk = { ...jwk, kid, alg: 'RS256', use: 'sig' };
  return { kid, alg: 'RS256', privateKey, publicKey, publicJwk, privatePem, publicPem };
}

/** Self-signed X.509 cert + key for SAML XML signatures (SAML metadata needs a certificate, not a bare key). */
export async function loadOrCreateCert(name: string): Promise<{ key: string; cert: string }> {
  const envKey = envPem(name, 'SAML_KEY_PEM');
  const envCert = envPem(name, 'SAML_CERT_PEM');
  if (envKey && envCert) return { key: envKey, cert: envCert };
  if (serverless()) return JSON.parse(await sharedInRedis(`${name}:saml`, async () => JSON.stringify(await selfSignedCert(name))));

  const dir = keysDir();
  mkdirSync(dir, { recursive: true });
  const keyPath = resolve(dir, `${name}.saml.key.pem`);
  const certPath = resolve(dir, `${name}.saml.cert.pem`);
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    const pems = await selfSignedCert(name);
    writeFileSync(keyPath, pems.key, { mode: 0o600 });
    writeFileSync(certPath, pems.cert);
  }
  return { key: readFileSync(keyPath, 'utf8'), cert: readFileSync(certPath, 'utf8') };
}

async function selfSignedCert(name: string): Promise<{ key: string; cert: string }> {
  const { default: selfsigned } = await import('selfsigned');
  const pems = selfsigned.generate([{ name: 'commonName', value: `${name}.authlab.local` }], { keySize: 2048, days: 3650, algorithm: 'sha256' });
  return { key: pems.private, cert: pems.cert };
}

import { exportJWK, exportPKCS8, exportSPKI, generateKeyPair, importPKCS8, importSPKI, type JWK, type KeyLike } from 'jose';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

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
  const dir = existsSync(resolve(process.cwd(), 'nx.json')) ? resolve(process.cwd(), '.keys') : resolve(process.cwd(), '../../.keys');
  mkdirSync(dir, { recursive: true });
  const privPath = resolve(dir, `${name}.private.pem`);
  const pubPath = resolve(dir, `${name}.public.pem`);

  let privatePem: string;
  let publicPem: string;
  if (existsSync(privPath) && existsSync(pubPath)) {
    privatePem = readFileSync(privPath, 'utf8');
    publicPem = readFileSync(pubPath, 'utf8');
  } else {
    const kp = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    privatePem = await exportPKCS8(kp.privateKey);
    publicPem = await exportSPKI(kp.publicKey);
    writeFileSync(privPath, privatePem, { mode: 0o600 });
    writeFileSync(pubPath, publicPem);
  }
  const privateKey = await importPKCS8(privatePem, 'RS256', { extractable: true });
  const publicKey = await importSPKI(publicPem, 'RS256', { extractable: true });
  const kid = `${name}-${Buffer.from(publicPem).toString('base64url').slice(-12)}`;
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { kid, alg: 'RS256', privateKey, publicKey, publicJwk, privatePem, publicPem };
}

/** Self-signed X.509 cert + key for SAML XML signatures (SAML metadata needs a certificate, not a bare key). */
export async function loadOrCreateCert(name: string): Promise<{ key: string; cert: string }> {
  const dir = existsSync(resolve(process.cwd(), 'nx.json')) ? resolve(process.cwd(), '.keys') : resolve(process.cwd(), '../../.keys');
  mkdirSync(dir, { recursive: true });
  const keyPath = resolve(dir, `${name}.saml.key.pem`);
  const certPath = resolve(dir, `${name}.saml.cert.pem`);
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    const { default: selfsigned } = await import('selfsigned');
    const pems = selfsigned.generate([{ name: 'commonName', value: `${name}.authlab.local` }], { keySize: 2048, days: 3650, algorithm: 'sha256' });
    writeFileSync(keyPath, pems.private, { mode: 0o600 });
    writeFileSync(certPath, pems.cert);
  }
  return { key: readFileSync(keyPath, 'utf8'), cert: readFileSync(certPath, 'utf8') };
}

/** Browser-side crypto helpers (Web Crypto API). */

const enc = new TextEncoder();

export async function sha256Hex(s: string) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const randomString = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

/** PKCE: code_challenge = BASE64URL(SHA256(code_verifier)) */
export async function pkcePair() {
  const verifier = randomString(48);
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(verifier))));
  return { verifier, challenge };
}

export function decodeJwt(token: string): { header: any; payload: any; signature: string } | null {
  try {
    const [h, p, s] = token.split('.');
    const dec = (x: string) => JSON.parse(decodeURIComponent(escape(atob(x.replace(/-/g, '+').replace(/_/g, '/')))));
    return { header: dec(h!), payload: dec(p!), signature: s! };
  } catch {
    return null;
  }
}

/** RFC 7616 Digest client (SHA-256, qop=auth) */
export async function digestAuthorization(challengeHeader: string, method: string, uri: string, username: string, password: string, nc: number) {
  const first = challengeHeader.split(/,\s*(?=x?-?Digest )/i)[0]!;
  const params: Record<string, string> = {};
  first.replace(/(\w+)=(?:"([^"]*)"|([^\s,]+))/g, (_m, k, v1, v2) => ((params[k] = v1 ?? v2), ''));
  const cnonce = randomString(8);
  const ncHex = nc.toString(16).padStart(8, '0');
  const HA1 = await sha256Hex(`${username}:${params.realm}:${password}`);
  const HA2 = await sha256Hex(`${method}:${uri}`);
  const response = await sha256Hex(`${HA1}:${params.nonce}:${ncHex}:${cnonce}:auth:${HA2}`);
  return {
    header: `Digest username="${username}", realm="${params.realm}", nonce="${params.nonce}", uri="${uri}", algorithm=SHA-256, qop=auth, nc=${ncHex}, cnonce="${cnonce}", response="${response}", opaque="${params.opaque}"`,
    steps: { HA1, HA2, response, nonce: params.nonce, cnonce, nc: ncHex },
  };
}

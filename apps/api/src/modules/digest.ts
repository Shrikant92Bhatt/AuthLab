import { Router, type Request } from 'express';
import { createHash } from 'node:crypto';
import { DIGEST_REALM, findByUsername, getRedis, HttpError, initUsers, randomToken, rk, safeEqual, toPublic } from '@authlab/core';

/**
 * RFC 7616 – HTTP Digest (qop=auth, SHA-256 and MD5).
 *
 *   HA1      = H(username:realm:password)        ← server stores this (password-equivalent!)
 *   HA2      = H(method:uri)
 *   response = H(HA1:nonce:nc:cnonce:qop:HA2)
 *
 * Password never crosses the wire, nonces (in Redis) + nonce-count stop replay.
 * But: no bcrypt possible, MD5 is weak, no mutual auth → legacy only.
 */
const NONCE_TTL = 300;
type Alg = 'SHA-256' | 'MD5';
const H = (alg: Alg, s: string) => createHash(alg === 'MD5' ? 'md5' : 'sha256').update(s).digest('hex');

async function challenges(req: Request, stale = false): Promise<string[]> {
  const nonce = randomToken(24);
  const opaque = randomToken(12);
  // value = last nonce-count seen (replay protection)
  await getRedis().set(rk.digestNonce(nonce), '0', 'EX', NONCE_TTL);
  const scheme = req.get('x-requested-with') ? 'x-Digest' : 'Digest';
  const common = `realm="${DIGEST_REALM}", qop="auth", nonce="${nonce}", opaque="${opaque}"${stale ? ', stale=true' : ''}`;
  // Offer the strongest algorithm first (RFC 7616 §3.7)
  return [`${scheme} ${common}, algorithm=SHA-256`, `${scheme} ${common}, algorithm=MD5`];
}

function parseDigest(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /(\w+)=(?:"([^"]*)"|([^\s,]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header.replace(/^Digest\s+/i, '')))) out[m[1]!] = m[2] ?? m[3] ?? '';
  return out;
}

export const digestRouter = Router();

digestRouter.get('/profile', async (req, res) => {
  await initUsers();
  const header = req.get('authorization') ?? '';
  const fail = async (msg: string, stale = false) => {
    throw new HttpError(401, msg, { 'WWW-Authenticate': await challenges(req, stale) });
  };
  if (!/^Digest /i.test(header)) return fail('Digest credentials required');

  const p = parseDigest(header);
  const alg: Alg = (p.algorithm ?? 'MD5').toUpperCase() === 'SHA-256' ? 'SHA-256' : 'MD5';
  const user = findByUsername(p.username ?? '');
  if (!user || p.realm !== DIGEST_REALM || p.qop !== 'auth' || !p.nonce || !p.nc || !p.cnonce || !p.response) {
    return fail('Invalid digest credentials');
  }
  if (p.uri !== req.originalUrl) return fail('Digest uri does not match request');

  // Nonce must exist and nonce-count must strictly increase (blocks replay)
  const redis = getRedis();
  const lastNc = await redis.get(rk.digestNonce(p.nonce));
  if (lastNc === null) return fail('Nonce expired', true);
  const nc = parseInt(p.nc, 16);
  if (!(nc > parseInt(lastNc, 10))) return fail('Replay detected (nonce-count reused)');

  const HA1 = alg === 'SHA-256' ? user.digestHA1.sha256 : user.digestHA1.md5;
  const HA2 = H(alg, `${req.method}:${p.uri}`);
  const expected = H(alg, `${HA1}:${p.nonce}:${p.nc}:${p.cnonce}:${p.qop}:${HA2}`);
  if (!safeEqual(expected, p.response)) return fail('Invalid digest response');

  await redis.set(rk.digestNonce(p.nonce), String(nc), 'KEEPTTL');
  res.json({
    method: 'digest',
    message: `Hello ${user.name} – your password never left your machine.`,
    user: toPublic(user),
    algorithm: alg,
    nonceCount: p.nc,
    computed: { HA2, response: expected },
  });
});

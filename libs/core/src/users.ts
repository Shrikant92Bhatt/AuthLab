import bcrypt from 'bcrypt';
import { createHash } from 'node:crypto';

/**
 * Minimal user repository. In production this is a DB table (Postgres + Prisma, etc).
 * Passwords are stored ONLY as bcrypt hashes (cost 12 ≈ 250 ms/hash).
 *
 * Digest auth is the exception: the server must know HA1 = H(user:realm:password),
 * which is a password-equivalent. That is one reason Digest is considered legacy.
 */
export const BCRYPT_COST = 12;
export const DIGEST_REALM = 'authlab@localhost';

export interface User {
  id: string;
  username: string;
  email: string;
  name: string;
  roles: string[];
  passwordHash: string; // bcrypt
  digestHA1: { md5: string; sha256: string }; // only for the Digest demo
}

export type PublicUser = Omit<User, 'passwordHash' | 'digestHA1'>;

const SEED = [
  { id: 'u_1', username: 'alice', email: 'alice@authlab.dev', name: 'Alice Admin', roles: ['admin', 'user'], password: 'Password123!' },
  { id: 'u_2', username: 'bob', email: 'bob@authlab.dev', name: 'Bob Builder', roles: ['user'], password: 'Password123!' },
];

const h = (alg: 'md5' | 'sha256', s: string) => createHash(alg).update(s).digest('hex');

const users = new Map<string, User>();
let ready: Promise<void> | undefined;

// A real hash used to equalise timing when the username does not exist
// (prevents user-enumeration via response time).
let dummyHash = '';

export function initUsers(): Promise<void> {
  ready ??= (async () => {
    dummyHash = await bcrypt.hash('dummy-password-for-timing', BCRYPT_COST);
    for (const s of SEED) {
      const passwordHash = await bcrypt.hash(s.password, BCRYPT_COST);
      const a1 = `${s.username}:${DIGEST_REALM}:${s.password}`;
      users.set(s.username, {
        id: s.id, username: s.username, email: s.email, name: s.name, roles: s.roles,
        passwordHash, digestHA1: { md5: h('md5', a1), sha256: h('sha256', a1) },
      });
    }
  })();
  return ready;
}

export const toPublic = ({ passwordHash: _p, digestHA1: _d, ...u }: User): PublicUser => u;

export function findByUsername(username: string): User | undefined {
  return users.get(username);
}

export function findById(id: string): User | undefined {
  return [...users.values()].find((u) => u.id === id);
}

/** Verify credentials in constant-ish time whether or not the user exists. */
export async function verifyCredentials(username: string, password: string): Promise<User | null> {
  await initUsers();
  const user = users.get(username);
  const ok = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
  return user && ok ? user : null;
}

import { randomBytes, timingSafeEqual } from 'node:crypto';

export class HttpError extends Error {
  constructor(public status: number, message: string, public headers: Record<string, string | string[]> = {}) {
    super(message);
  }
}

/** Constant-time string compare (prevents timing attacks on secrets). */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    timingSafeEqual(ab, ab); // keep timing similar
    return false;
  }
  return timingSafeEqual(ab, bb);
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

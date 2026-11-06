import { Router, type Request } from 'express';
import { HttpError, toPublic, verifyCredentials } from '@authlab/core';

/**
 * RFC 7617 – HTTP Basic.
 *   Authorization: Basic base64("user:password")
 * Stateless: credentials travel on EVERY request (TLS is mandatory). No real logout.
 * Each request costs one bcrypt compare (~250 ms) – a hidden scalability cost.
 */
const REALM = 'authlab-basic';

// Browsers pop up a native login dialog on `WWW-Authenticate: Basic`.
// SPAs send `X-Requested-With` so we can switch the scheme name and suppress it.
const challenge = (req: Request) => `${req.get('x-requested-with') ? 'x-Basic' : 'Basic'} realm="${REALM}", charset="UTF-8"`;

export const basicRouter = Router();

basicRouter.get('/profile', async (req, res) => {
  const header = req.get('authorization') ?? '';
  if (!header.startsWith('Basic ')) {
    throw new HttpError(401, 'Basic credentials required', { 'WWW-Authenticate': challenge(req) });
  }
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const sep = decoded.indexOf(':'); // password may contain ':'
  const username = decoded.slice(0, sep);
  const password = decoded.slice(sep + 1);
  const user = sep > 0 ? await verifyCredentials(username, password) : null;
  if (!user) throw new HttpError(401, 'Invalid username or password', { 'WWW-Authenticate': challenge(req) });

  res.json({
    method: 'basic',
    message: `Hello ${user.name} – you sent your password with this request.`,
    user: toPublic(user),
    receivedHeader: `Basic ${header.slice(6, 14)}… (base64 is encoding, NOT encryption)`,
  });
});

import express, { Router } from 'express';
import samlify from 'samlify';
import * as validator from '@authenio/samlify-node-xmllint';
import { env, getRedis, rk } from '@authlab/core';
import { clearSessionCookie, destroy, establishSession, requireCsrf, requireSession } from '../lib/session';

/**
 * SAML 2.0 – this API is the SERVICE PROVIDER (SP).
 *   1. GET  /login  → AuthnRequest (HTTP-Redirect binding) to the IdP
 *   2. IdP authenticates the user, signs an XML Assertion
 *   3. POST /acs    ← browser auto-POSTs SAMLResponse (HTTP-POST binding)
 *   4. SP verifies XML signature with IdP cert (from metadata), InResponseTo,
 *      Audience, NotBefore/NotOnOrAfter, Destination → creates a local session
 */
samlify.setSchemaValidator(validator);
const { binding } = samlify.Constants.namespace;

const sp = samlify.ServiceProvider({
  entityID: `${env.WEB_ORIGIN}/api/saml/metadata`,
  wantAssertionsSigned: true,
  authnRequestsSigned: false,
  assertionConsumerService: [{ Binding: binding.post, Location: `${env.WEB_ORIGIN}/api/saml/acs` }],
});

// Trust is established by importing the IdP's metadata (entityID, SSO URL, signing cert)
let idp: ReturnType<typeof samlify.IdentityProvider> | undefined;
async function getIdp() {
  if (!idp) {
    const metadata = await (await fetch(`${env.ISSUER}/saml/metadata`)).text();
    idp = samlify.IdentityProvider({ metadata });
  }
  return idp;
}

export const samlRouter = Router();

samlRouter.get('/metadata', (_req, res) => res.type('application/xml').send(sp.getMetadata()));

samlRouter.get('/login', async (_req, res) => {
  const { id, context } = sp.createLoginRequest(await getIdp(), 'redirect') as { id: string; context: string };
  // Remember the request id → the response's InResponseTo must match (prevents unsolicited/replayed responses)
  await getRedis().set(rk.samlRequest(id), '1', 'EX', 600);
  res.redirect(context);
});

samlRouter.post('/acs', express.urlencoded({ extended: false, limit: '200kb' }), async (req, res) => {
  const fail = (msg: string) => res.redirect(`${env.WEB_ORIGIN}/saml?error=${encodeURIComponent(msg)}`);
  try {
    const { extract } = await sp.parseLoginResponse(await getIdp(), 'post', { body: req.body } as never);
    const inResponseTo = extract.response?.inResponseTo as string | undefined;
    if (!inResponseTo || !(await getRedis().getdel(rk.samlRequest(inResponseTo)))) return fail('Unknown or replayed InResponseTo');

    const attrs = (extract.attributes ?? {}) as Record<string, string>;
    const nameID = String(extract.nameID);
    await establishSession(
      req,
      { id: `saml:${nameID}`, username: attrs.username ?? nameID, email: attrs.email ?? nameID, name: attrs.name ?? nameID, roles: (attrs.roles ?? '').split(',').filter(Boolean) },
      'saml',
      { saml: { nameID: String(extract.nameID), attributes: attrs, sessionIndex: [extract.sessionIndex?.sessionIndex].flat()[0], issuer: [extract.issuer].flat()[0] } },
    );
    res.redirect(303, `${env.WEB_ORIGIN}/saml?login=ok`);
  } catch (e) {
    fail(`SAML response rejected: ${(e as Error).message ?? e}`);
  }
});

samlRouter.get('/me', requireSession('saml'), (req, res) => {
  res.json({ method: 'saml', user: req.session.user, csrfToken: req.session.csrfToken, assertion: req.session.saml });
});

samlRouter.post('/logout', requireSession('saml'), requireCsrf, async (req, res) => {
  await destroy(req);
  clearSessionCookie(res);
  res.json({ ok: true });
});

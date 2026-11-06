import { Router } from 'express';
import samlify from 'samlify';
import * as validator from '@authenio/samlify-node-xmllint';
import { env, getRedis, loadOrCreateCert, randomToken, rk, verifyCredentials } from '@authlab/core';
import { errorPage, loginConsentPage, samlPostPage } from './views';

/**
 * SAML 2.0 Identity Provider.
 *   SP  --(HTTP-Redirect: AuthnRequest)-->  IdP /saml/sso
 *   IdP --(login)--> user
 *   IdP --(HTTP-POST: signed <Response><Assertion>)--> SP ACS
 */
samlify.setSchemaValidator(validator);

const { binding, format: nameid } = samlify.Constants.namespace;
const SP_ENTITY_ID = `${env.WEB_ORIGIN}/api/saml/metadata`;
const SP_ACS = `${env.WEB_ORIGIN}/api/saml/acs`;

const RESPONSE_TEMPLATE =
  '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">' +
  '<saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status>' +
  '<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">' +
  '<saml:Issuer>{Issuer}</saml:Issuer>' +
  '<saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>' +
  '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject>' +
  '<saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>' +
  '<saml:AuthnStatement AuthnInstant="{IssueInstant}" SessionIndex="{SessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>' +
  '{AttributeStatement}</saml:Assertion></samlp:Response>';

const ATTR_FMT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
const ATTRIBUTES = [
  { name: 'email', valueTag: 'email', nameFormat: ATTR_FMT, valueXsiType: 'xs:string' },
  { name: 'name', valueTag: 'name', nameFormat: ATTR_FMT, valueXsiType: 'xs:string' },
  { name: 'username', valueTag: 'username', nameFormat: ATTR_FMT, valueXsiType: 'xs:string' },
  { name: 'roles', valueTag: 'roles', nameFormat: ATTR_FMT, valueXsiType: 'xs:string' },
];

export async function samlRouter() {
  const r = Router();
  const redis = getRedis();
  const { key, cert } = await loadOrCreateCert('idp');

  const idp = samlify.IdentityProvider({
    entityID: `${env.ISSUER}/saml/metadata`,
    privateKey: key,
    signingCert: cert,
    nameIDFormat: [nameid.emailAddress],
    wantAuthnRequestsSigned: false,
    singleSignOnService: [{ Binding: binding.redirect, Location: `${env.ISSUER}/saml/sso` }],
    loginResponseTemplate: { context: RESPONSE_TEMPLATE, attributes: ATTRIBUTES } as never,
  });

  // The IdP must know (trust) each SP: entityID + ACS URL. Usually imported from SP metadata.
  const sp = samlify.ServiceProvider({
    entityID: SP_ENTITY_ID,
    wantAssertionsSigned: true,
    assertionConsumerService: [{ Binding: binding.post, Location: SP_ACS }],
  });

  r.get('/saml/metadata', (_req, res) => res.type('application/xml').send(idp.getMetadata()));

  // 1. SP redirects browser here with a deflated+base64 AuthnRequest
  r.get('/saml/sso', async (req, res) => {
    try {
      const parsed = await idp.parseLoginRequest(sp, 'redirect', { query: req.query } as never);
      const requestId = parsed.extract.request?.id as string;
      const txn = randomToken(18);
      await redis.set(rk.samlRequest(txn), JSON.stringify({ requestId, relayState: req.query.RelayState }), 'EX', 600);
      res.send(loginConsentPage({ action: '/saml/sso', txn, clientName: `SAML SP ${SP_ENTITY_ID}`, protocol: 'SAML 2.0', scopes: [] }));
    } catch (e) {
      res.status(400).send(errorPage(`Invalid AuthnRequest: ${(e as Error).message}`));
    }
  });

  // 2. User authenticates → IdP signs an assertion and auto-POSTs it to the SP
  r.post('/saml/sso', async (req, res) => {
    const { txn, username, password, decision } = req.body as Record<string, string>;
    const raw = await redis.get(rk.samlRequest(txn ?? ''));
    if (!raw) return res.status(400).send(errorPage('SAML transaction expired'));
    if (decision !== 'allow') return res.status(403).send(errorPage('User cancelled sign in'));
    const user = await verifyCredentials(username ?? '', password ?? '');
    if (!user) {
      return res.status(401).send(loginConsentPage({ action: '/saml/sso', txn, clientName: `SAML SP ${SP_ENTITY_ID}`, protocol: 'SAML 2.0', scopes: [], error: 'Invalid username or password' }));
    }
    await redis.del(rk.samlRequest(txn));
    const { requestId, relayState } = JSON.parse(raw) as { requestId: string; relayState?: string };

    const now = new Date();
    const later = new Date(now.getTime() + 5 * 60_000).toISOString();
    const result = await idp.createLoginResponse(
      sp,
      { extract: { request: { id: requestId } } },
      'post',
      { email: user.email },
      {
        relayState,
        customTagReplacement: (template: string) => {
          const id = `_${randomToken(16)}`;
          const values: Record<string, string> = {
            ID: id, AssertionID: `_${randomToken(16)}`, Destination: SP_ACS, Audience: SP_ENTITY_ID,
            SubjectRecipient: SP_ACS, Issuer: `${env.ISSUER}/saml/metadata`, IssueInstant: now.toISOString(),
            StatusCode: samlify.Constants.StatusCode.Success, ConditionsNotBefore: now.toISOString(),
            ConditionsNotOnOrAfter: later, SubjectConfirmationDataNotOnOrAfter: later,
            NameIDFormat: nameid.emailAddress, NameID: user.email, InResponseTo: requestId,
            SessionIndex: `_${randomToken(8)}`,
            attrEmail: user.email, attrName: user.name, attrUsername: user.username, attrRoles: user.roles.join(','),
          };
          return { id, context: samlify.SamlLib.replaceTagsByValue(template, values) };
        },
      } as never,
    );
    const post = result as { entityEndpoint: string; context: string };
    res.send(samlPostPage(post.entityEndpoint, post.context, relayState, res.locals.cspNonce));
  });

  return r;
}

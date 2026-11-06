import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AUTH_SERVER, call } from '../lib/http';
import { pkcePair, randomString } from '../lib/crypto';
import { tokens, useToken } from '../lib/token-store';
import { MethodPage } from '../components/MethodPage';
import { JwtView } from '../components/JwtView';

const SPA_CLIENT = 'authlab-spa';
const SPA_REDIRECT = `${location.origin}/oauth2/callback`;

export function OAuth2Page() {
  const at = useToken('oauth2.at');
  const [scopes, setScopes] = useState(['notes:read']);
  const [text, setText] = useState('Buy NIFTYBEES on dip');
  const auth = { Authorization: `Bearer ${at}` };

  const start = async () => {
    const { verifier, challenge } = await pkcePair();
    const state = randomString(16);
    // sessionStorage: survives the redirect, scoped to this tab, cleared on callback
    sessionStorage.setItem('pkce', JSON.stringify({ verifier, state }));
    const u = new URL(`${AUTH_SERVER}/authorize`);
    u.search = new URLSearchParams({ response_type: 'code', client_id: SPA_CLIENT, redirect_uri: SPA_REDIRECT, scope: scopes.join(' '), state, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
    location.assign(u);
  };

  return (
    <MethodPage id="oauth2">
      <h4>A · Authorization Code + PKCE (SPA on behalf of a user)</h4>
      <div className="row">
        {['notes:read', 'notes:write'].map((s) => (
          <label key={s} className="check"><input type="checkbox" checked={scopes.includes(s)} onChange={() => setScopes((x) => (x.includes(s) ? x.filter((y) => y !== s) : [...x, s]))} /> {s}</label>
        ))}
        <button className="primary" onClick={start}>1 · Authorize at Auth Server</button>
      </div>
      <div className="row">
        <button onClick={() => call('/api/oauth2/notes', { headers: auth })} disabled={!at}>2 · GET notes (notes:read)</button>
        <input value={text} onChange={(e) => setText(e.target.value)} />
        <button onClick={() => call('/api/oauth2/notes', { json: { text }, headers: auth })} disabled={!at}>3 · POST note (notes:write)</button>
        <button className="danger" onClick={() => call('/api/oauth2/reports', { headers: auth })} disabled={!at}>4 · GET reports (scope not granted)</button>
      </div>
      <h4>B · Client Credentials (service → service, no user)</h4>
      <div className="row"><button onClick={() => call('/api/oauth2/demo/client-credentials', { method: 'POST' })}>Run M2M flow on the backend</button></div>
      <JwtView token={at} label="Access token from Auth Server (aud = authlab-api)" />
    </MethodPage>
  );
}

export function OAuth2Callback() {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const [msg, setMsg] = useState('Exchanging code for tokens…');
  const done = useRef(false);
  useEffect(() => {
    if (done.current) return; // StrictMode double-run guard: codes are single-use
    done.current = true;
    (async () => {
      const saved = JSON.parse(sessionStorage.getItem('pkce') ?? 'null') as { verifier: string; state: string } | null;
      sessionStorage.removeItem('pkce');
      if (params.get('error')) return setMsg(`${params.get('error')}: ${params.get('error_description')}`);
      if (!saved || saved.state !== params.get('state')) return setMsg('State mismatch – possible CSRF. Aborted.');
      if (params.get('iss') !== AUTH_SERVER) return setMsg('Issuer mismatch – possible mix-up attack.');
      const r = await call(`${AUTH_SERVER}/token`, {
        form: { grant_type: 'authorization_code', client_id: SPA_CLIENT, code: params.get('code') ?? '', redirect_uri: SPA_REDIRECT, code_verifier: saved.verifier },
        credentials: 'omit',
        headers: {},
      });
      if (r.status !== 200) return setMsg(`Token exchange failed: ${JSON.stringify(r.body)}`);
      tokens.set('oauth2.at', r.body.access_token);
      nav('/oauth2', { replace: true }); // client-side nav keeps the in-memory token
    })();
  }, [params, nav]);
  return <div className="page"><div className="panel"><h3>OAuth 2.0 callback</h3><p>{msg}</p></div></div>;
}

function useSessionInfo(path: string) {
  const [params] = useSearchParams();
  const [me, setMe] = useState<any>();
  const load = () => call(path).then((r) => setMe(r.status === 200 ? r.body : undefined));
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return { me, load, error: params.get('error') };
}

export function OidcPage() {
  const { me, load, error } = useSessionInfo('/api/oidc/me');
  return (
    <MethodPage id="oidc">
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="primary" onClick={() => location.assign('/api/oidc/login')}>1 · Sign in with AuthLab ID (OIDC)</button>
        <button onClick={load}>2 · GET /api/oidc/me</button>
        <button onClick={() => call(`${AUTH_SERVER}/.well-known/openid-configuration`, { credentials: 'omit', headers: {} })}>Discovery doc</button>
        {me && <button onClick={async () => { await call('/api/oidc/logout', { method: 'POST', headers: { 'X-CSRF-Token': me.csrfToken } }); load(); }}>Logout</button>}
      </div>
      {me ? (
        <>
          <p>Signed in as <b>{me.user.name}</b> ({me.user.email}). Access token stays on the server: <code>{me.accessTokenHeldServerSide}</code></p>
          <JwtView token={me.idToken} label="ID Token (aud = client_id)" />
          <h4>/userinfo</h4><pre className="code">{JSON.stringify(me.userinfo, null, 2)}</pre>
        </>
      ) : <p className="muted">Not signed in via OIDC.</p>}
    </MethodPage>
  );
}

export function SamlPage() {
  const { me, load, error } = useSessionInfo('/api/saml/me');
  return (
    <MethodPage id="saml">
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="primary" onClick={() => location.assign('/api/saml/login')}>1 · Sign in with SAML SSO</button>
        <button onClick={load}>2 · GET /api/saml/me</button>
        <a className="btn" href="/api/saml/metadata" target="_blank" rel="noreferrer">SP metadata</a>
        <a className="btn" href={`${AUTH_SERVER}/saml/metadata`} target="_blank" rel="noreferrer">IdP metadata</a>
        {me && <button onClick={async () => { await call('/api/saml/logout', { method: 'POST', headers: { 'X-CSRF-Token': me.csrfToken } }); load(); }}>Logout</button>}
      </div>
      {me ? (
        <>
          <p>Signed in as <b>{me.user.name}</b> via SAML.</p>
          <h4>Assertion data</h4><pre className="code">{JSON.stringify(me.assertion, null, 2)}</pre>
        </>
      ) : <p className="muted">Not signed in via SAML.</p>}
    </MethodPage>
  );
}

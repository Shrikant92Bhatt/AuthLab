import { useEffect, useState } from 'react';
import { call } from '../lib/http';
import { Creds, MethodPage } from '../components/MethodPage';

export function ApiKeyPage() {
  const [creds, setCreds] = useState({ username: 'alice', password: 'Password123!' });
  const [key, setKey] = useState('');
  const [scopes, setScopes] = useState<string[]>(['data:read']);
  const toggle = (s: string) => setScopes((x) => (x.includes(s) ? x.filter((y) => y !== s) : [...x, s]));

  const create = async () => {
    const r = await call('/api/api-keys', { json: { ...creds, name: 'web-demo', scopes } });
    if (r.status === 201) setKey(r.body.apiKey);
  };
  const burst = async () => { for (let i = 0; i < 22; i++) await call('/api/api-keys/data', { headers: { 'X-API-Key': key } }); };

  return (
    <MethodPage id="api-key">
      <Creds value={creds} onChange={setCreds} />
      <div className="row">
        {['data:read', 'data:write'].map((s) => (
          <label key={s} className="check"><input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} /> {s}</label>
        ))}
        <button className="primary" onClick={create}>1 · Create API key</button>
      </div>
      <label>X-API-Key<input value={key} onChange={(e) => setKey(e.target.value)} placeholder="ak_xxxxxxxx_..." /></label>
      <div className="row">
        <button onClick={() => call('/api/api-keys/data', { headers: { 'X-API-Key': key } })} disabled={!key}>2 · GET /data (read)</button>
        <button onClick={() => call('/api/api-keys/data', { method: 'POST', headers: { 'X-API-Key': key } })} disabled={!key}>3 · POST /data (needs write)</button>
        <button onClick={burst} disabled={!key}>4 · Burst 22 calls → 429</button>
        <button className="danger" onClick={() => call('/api/api-keys/self', { method: 'DELETE', headers: { 'X-API-Key': key } })} disabled={!key}>5 · Revoke</button>
      </div>
    </MethodPage>
  );
}

export function SessionPage() {
  const [creds, setCreds] = useState({ username: 'bob', password: 'Password123!' });
  const [csrf, setCsrf] = useState('');
  useEffect(() => { call('/api/session/me').then((r) => r.status === 200 && setCsrf(r.body.csrfToken)); }, []);

  return (
    <MethodPage id="session">
      <Creds value={creds} onChange={setCreds} />
      <div className="row">
        <button className="primary" onClick={async () => { const r = await call('/api/session/login', { json: creds }); if (r.status === 200) setCsrf(r.body.csrfToken); }}>1 · Log in</button>
        <button onClick={() => call('/api/session/me')}>2 · GET /me (cookie sent automatically)</button>
        <button onClick={() => alert(`document.cookie = "${document.cookie}"\n\nThe HttpOnly session cookie is NOT visible to JavaScript.`)}>3 · Can JS read it?</button>
      </div>
      <div className="row">
        <button className="danger" onClick={() => call('/api/session/transfer', { json: { amount: 1000 } })}>4 · POST without CSRF token (simulated CSRF)</button>
        <button onClick={() => call('/api/session/transfer', { json: { amount: 1000 }, headers: { 'X-CSRF-Token': csrf } })} disabled={!csrf}>5 · POST with CSRF token</button>
        <button onClick={async () => { await call('/api/session/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf } }); setCsrf(''); }} disabled={!csrf}>6 · Logout (Redis DEL)</button>
      </div>
      {csrf && <p className="muted">CSRF token (from session): <code>{csrf}</code></p>}
    </MethodPage>
  );
}

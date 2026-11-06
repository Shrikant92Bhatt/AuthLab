import { useEffect, useState } from 'react';
import { call } from '../lib/http';
import { tokens, useToken } from '../lib/token-store';
import { Creds, MethodPage } from '../components/MethodPage';
import { JwtView } from '../components/JwtView';

export function JwtPage() {
  const [creds, setCreds] = useState({ username: 'alice', password: 'Password123!' });
  const token = useToken('jwt');
  const auth = { Authorization: `Bearer ${token}` };
  const tamper = () => {
    const [h, p, s] = token!.split('.');
    const payload = JSON.parse(atob(p!.replace(/-/g, '+').replace(/_/g, '/')));
    payload.roles = ['admin', 'superuser']; // privilege escalation attempt
    payload.exp = payload.exp + 86400 * 365; // and extend expiry
    const forged = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    call('/api/jwt/admin', { headers: { Authorization: `Bearer ${h}.${forged}.${s}` } });
  };
  return (
    <MethodPage id="jwt">
      <Creds value={creds} onChange={setCreds} />
      <div className="row">
        <button className="primary" onClick={async () => { const r = await call('/api/jwt/login', { json: creds }); tokens.set('jwt', r.body.access_token); }}>1 · Log in → JWT</button>
        <button onClick={() => call('/api/jwt/profile', { headers: auth })} disabled={!token}>2 · GET /profile</button>
        <button onClick={() => call('/api/jwt/admin', { headers: auth })} disabled={!token}>3 · GET /admin (role check)</button>
      </div>
      <div className="row">
        <button className="danger" onClick={tamper} disabled={!token}>4 · Forge roles=[admin] (signature breaks)</button>
        <button onClick={() => call('/api/jwt/logout', { method: 'POST', headers: auth })} disabled={!token}>5 · Logout (deny-list jti)</button>
        <button onClick={() => call('/api/jwt/.well-known/jwks.json')}>JWKS</button>
      </div>
      <JwtView token={token} label="Access token (kept in memory, not localStorage)" />
    </MethodPage>
  );
}

export function TokensPage() {
  const [creds, setCreds] = useState({ username: 'alice', password: 'Password123!' });
  const at = useToken('tokens.at');
  const [oldRt, setOldRt] = useState<string>();
  const [, tick] = useState(0);
  useEffect(() => { const t = setInterval(() => tick((x) => x + 1), 1000); return () => clearInterval(t); }, []);

  const refresh = async () => {
    const r = await call('/api/tokens/refresh', { method: 'POST' });
    if (r.status === 200) tokens.set('tokens.at', r.body.access_token);
    return r.status === 200;
  };

  /** Typical interceptor: 401 → refresh → retry once */
  const profile = async () => {
    const r = await call('/api/tokens/profile', { headers: { Authorization: `Bearer ${tokens.get('tokens.at')}` } });
    if (r.status === 401 && (await refresh())) await call('/api/tokens/profile', { headers: { Authorization: `Bearer ${tokens.get('tokens.at')}` } });
  };

  return (
    <MethodPage id="tokens">
      <Creds value={creds} onChange={setCreds} />
      <div className="row">
        <button className="primary" onClick={async () => { const r = await call('/api/tokens/login', { json: creds }); tokens.set('tokens.at', r.body.access_token); setOldRt(r.body.debug_refresh_token); }}>1 · Log in</button>
        <button onClick={profile} disabled={!at}>2 · GET /profile (auto-refresh on 401)</button>
        <button onClick={refresh}>3 · Refresh now (rotate)</button>
      </div>
      <div className="row">
        <button className="danger" onClick={() => call('/api/tokens/refresh', { json: { refresh_token: oldRt } })} disabled={!oldRt}>4 · Attacker replays FIRST refresh token</button>
        <button onClick={() => { tokens.set('tokens.at', undefined); }}>Simulate page reload (drop memory)</button>
        <button onClick={async () => { await call('/api/tokens/logout', { method: 'POST' }); tokens.set('tokens.at', undefined); }}>5 · Logout</button>
      </div>
      <p className="muted">Access TTL is 60 s (ACCESS_TOKEN_TTL). Do 1 → 3 → 4: the replay of a used token revokes the whole family, then 3 fails too.</p>
      <JwtView token={at} label="Access token" />
    </MethodPage>
  );
}

import { useRef, useState } from 'react';
import { call } from '../lib/http';
import { digestAuthorization } from '../lib/crypto';
import { Creds, MethodPage } from '../components/MethodPage';

export function BasicPage() {
  const [creds, setCreds] = useState({ username: 'alice', password: 'Password123!' });
  const encoded = btoa(`${creds.username}:${creds.password}`);
  return (
    <MethodPage id="basic">
      <Creds value={creds} onChange={setCreds} />
      <p className="muted">Header that will be sent: <code>Authorization: Basic {encoded}</code><br />
        Decode it yourself: <code>atob("{encoded}")</code> → <code>{creds.username}:{creds.password}</code></p>
      <div className="row">
        <button onClick={() => call('/api/basic/profile')}>1 · Call without credentials</button>
        <button className="primary" onClick={() => call('/api/basic/profile', { headers: { Authorization: `Basic ${encoded}` } })}>2 · Call with Basic header</button>
      </div>
    </MethodPage>
  );
}

export function DigestPage() {
  const [creds, setCreds] = useState({ username: 'alice', password: 'Password123!' });
  const [steps, setSteps] = useState<Record<string, string>>();
  const last = useRef<{ challenge: string; nc: number; header: string } | null>(null);
  const uri = '/api/digest/profile';

  const run = async () => {
    const r1 = await call(uri);
    const challenge = r1.headers.get('www-authenticate') ?? '';
    const { header, steps } = await digestAuthorization(challenge, 'GET', uri, creds.username, creds.password, 1);
    setSteps(steps);
    last.current = { challenge, nc: 1, header };
    await call(uri, { headers: { Authorization: header } });
  };
  const next = async () => {
    if (!last.current) return;
    const nc = last.current.nc + 1;
    const { header, steps } = await digestAuthorization(last.current.challenge, 'GET', uri, creds.username, creds.password, nc);
    setSteps(steps);
    last.current = { ...last.current, nc, header };
    await call(uri, { headers: { Authorization: header } });
  };
  const replay = () => last.current && call(uri, { headers: { Authorization: last.current.header } });

  return (
    <MethodPage id="digest">
      <Creds value={creds} onChange={setCreds} />
      <div className="row">
        <button className="primary" onClick={run}>1 · Challenge → compute → authenticate</button>
        <button onClick={next} disabled={!steps}>2 · Reuse nonce, nc+1</button>
        <button className="danger" onClick={replay} disabled={!steps}>3 · Replay exact same header</button>
      </div>
      {steps && (
        <pre className="code">{`HA1      = SHA256("${creds.username}:authlab@localhost:${creds.password}")\n         = ${steps.HA1}\nHA2      = SHA256("GET:${uri}")\n         = ${steps.HA2}\nresponse = SHA256(HA1:${steps.nonce}:${steps.nc}:${steps.cnonce}:auth:HA2)\n         = ${steps.response}`}</pre>
      )}
      <p className="muted">The password itself is never sent. Step 3 fails because the nonce-count must increase.</p>
    </MethodPage>
  );
}

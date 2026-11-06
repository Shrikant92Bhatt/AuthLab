import { decodeJwt } from '../lib/crypto';

/** Color-coded JWT viewer (like jwt.io) – decoding is NOT verifying. */
export function JwtView({ token, label = 'Token' }: { token?: string; label?: string }) {
  if (!token) return null;
  const d = decodeJwt(token);
  const [h, p, s] = token.split('.');
  const exp = d?.payload?.exp ? Math.round(d.payload.exp - Date.now() / 1000) : undefined;
  return (
    <div className="jwt">
      <h4>{label} {exp !== undefined && <span className={`pill ${exp > 0 ? 'ok' : 'bad'}`}>{exp > 0 ? `expires in ${exp}s` : 'expired'}</span>}</h4>
      <p className="jwt-raw"><span className="jh">{h}</span>.<span className="jp">{p}</span>.<span className="js">{s}</span></p>
      {d && (
        <div className="http-grid">
          <div><h4 className="jh">Header</h4><pre className="code">{JSON.stringify(d.header, null, 2)}</pre></div>
          <div><h4 className="jp">Payload</h4><pre className="code">{JSON.stringify(d.payload, null, 2)}</pre></div>
        </div>
      )}
    </div>
  );
}

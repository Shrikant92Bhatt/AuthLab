import { httpLog, useHttpLog } from '../lib/http';

const statusClass = (s: number) => (s < 300 ? 'ok' : s < 400 ? 'warn' : 'bad');

export function HttpLog() {
  const entries = useHttpLog();
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>HTTP traffic</h3>
        <button className="ghost" onClick={httpLog.clear}>Clear</button>
      </div>
      {entries.length === 0 && <p className="muted">Run a demo – requests and responses appear here.</p>}
      {entries.map((e) => (
        <details key={e.id} className="http" open={e.id === entries[0]?.id}>
          <summary>
            <span className={`status ${statusClass(e.status)}`}>{e.status}</span>
            <b>{e.method}</b> <code>{e.url.replace(location.origin, '')}</code>
            <span className="muted"> · {e.ms} ms · {e.at}</span>
          </summary>
          <div className="http-grid">
            <div>
              <h4>Request headers</h4>
              <pre className="code">{Object.entries(e.reqHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>
              {e.reqBody && (<><h4>Body</h4><pre className="code">{e.reqBody}</pre></>)}
            </div>
            <div>
              <h4>Response headers</h4>
              <pre className="code">{Object.entries(e.resHeaders).map(([k, v]) => `${k}: ${v}`).join('\n') || '—'}</pre>
              <h4>Body</h4>
              <pre className="code">{typeof e.resBody === 'string' ? e.resBody : JSON.stringify(e.resBody, null, 2)}</pre>
            </div>
          </div>
        </details>
      ))}
    </section>
  );
}

import type { ReactNode } from 'react';
import { AUTH_METHODS } from '@authlab/shared';
import { CONTENT } from '../content';
import { Mermaid } from './Mermaid';
import { HttpLog } from './HttpLog';

export function MethodPage({ id, children }: { id: string; children: ReactNode }) {
  const m = AUTH_METHODS.find((x) => x.id === id)!;
  const c = CONTENT[id]!;
  return (
    <div className="page">
      <header className="hero">
        <div className="badges">
          <span className="pill cat">{m.category}</span>
          {m.answers.map((a) => <span key={a} className="pill">{a}</span>)}
          <span className="pill">{m.stateful ? 'Stateful' : 'Stateless'}</span>
        </div>
        <h1>{m.title}</h1>
        <p className="lead">{c.summary}</p>
        <dl className="facts">
          <div><dt>Credential travels as</dt><dd><code>{m.credentialIn}</code></dd></div>
          <div><dt>Best for</dt><dd>{m.bestFor}</dd></div>
          <div><dt>Avoid when</dt><dd>{m.avoidWhen}</dd></div>
        </dl>
      </header>

      <div className="diagrams">
        {c.diagrams.map((d) => <Mermaid key={d.title} title={d.title} code={d.code} />)}
      </div>

      <div className="two-col">
        <div>
          <section className="panel demo">
            <h3>Try it</h3>
            {children}
          </section>
          <HttpLog />
        </div>
        <div>
          <section className="panel">
            <h3>Standard practices implemented</h3>
            <ul className="checks">{c.practices.map((p) => <li key={p}>{p}</li>)}</ul>
            <h3>Pitfalls</h3>
            <ul className="warns">{c.pitfalls.map((p) => <li key={p}>{p}</li>)}</ul>
            <h3>curl</h3>
            <pre className="code">{c.curl}</pre>
          </section>
        </div>
      </div>
    </div>
  );
}

export function Creds({ value, onChange }: { value: { username: string; password: string }; onChange: (v: { username: string; password: string }) => void }) {
  return (
    <div className="row">
      <label>Username
        <select value={value.username} onChange={(e) => onChange({ ...value, username: e.target.value })}>
          <option value="alice">alice (admin)</option>
          <option value="bob">bob (user)</option>
          <option value="mallory">mallory (unknown)</option>
        </select>
      </label>
      <label>Password<input value={value.password} onChange={(e) => onChange({ ...value, password: e.target.value })} /></label>
    </div>
  );
}

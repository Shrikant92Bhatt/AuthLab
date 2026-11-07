import { Link } from 'react-router-dom';
import { AUTH_METHODS, DEMO_USERS } from '@authlab/shared';
import { OVERVIEW_DIAGRAMS } from '../content';
import { Mermaid } from '../components/Mermaid';

export function Home() {
  return (
    <div className="page">
      <header className="hero">
        <div className="eyebrow">Authentication · Authorization · Federation</div>
        <h1>9 ways to prove <span className="hl">who you are</span></h1>
        <p className="lead">
          Every method below runs for real against a Node.js backend with Redis and bcrypt. Pick one on the left, press the buttons,
          and watch the raw HTTP traffic. Demo users: {DEMO_USERS.map((u) => <code key={u.username}>{u.username} / {u.password}</code>)}.
        </p>
      </header>

      <div className="grid-2">
        {OVERVIEW_DIAGRAMS.map((d) => <Mermaid key={d.title} title={d.title} code={d.code} />)}
      </div>

      <section className="panel">
        <h3>Comparison</h3>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Method</th><th>Kind</th><th>Answers</th><th>State</th><th>Best for</th><th>Avoid when</th></tr></thead>
            <tbody>
              {AUTH_METHODS.map((m) => (
                <tr key={m.id}>
                  <td><Link to={`/${m.id}`}>{m.title}</Link></td>
                  <td><span className="pill cat">{m.category}</span></td>
                  <td>{m.answers.join(', ')}</td>
                  <td>{m.stateful ? 'Stateful' : 'Stateless'}</td>
                  <td>{m.bestFor}</td>
                  <td>{m.avoidWhen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h3>Which one should I use?</h3>
        <Mermaid code={`flowchart TD
  S{"Who is calling?"} -->|"A human in a browser, same site"| SES["Session cookie"]
  S -->|"A human, SPA / mobile, your own API"| AR["Access + Refresh tokens<br/>(or BFF + session)"]
  S -->|"A human, log in with another org's identity"| F{"Enterprise legacy?"}
  F -->|"yes"| SAML["SAML 2.0"]
  F -->|"no"| OIDC["OpenID Connect"]
  S -->|"A 3rd-party app acting for a user"| OA["OAuth 2.0 Auth Code + PKCE"]
  S -->|"A backend service"| M{"Your org or external dev?"}
  M -->|"internal service"| CC["OAuth 2.0 Client Credentials / mTLS"]
  M -->|"external developer"| KEY["API Key"]
  S -->|"curl / internal tool / device"| B["Basic over TLS<br/>(Digest only for legacy devices)"]`} />
      </section>
    </div>
  );
}

import type React from 'react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom';
import { AUTH_METHODS } from '@authlab/shared';
import { Home } from './pages/Home';
import { BasicPage, DigestPage } from './pages/BasicDigest';
import { ApiKeyPage, SessionPage } from './pages/ApiKeySession';
import { JwtPage, TokensPage } from './pages/JwtTokens';
import { OAuth2Callback, OAuth2Page, OidcPage, SamlPage } from './pages/Federation';
import './styles.css';

const PAGES: Record<string, () => React.JSX.Element> = {
  basic: BasicPage, digest: DigestPage, 'api-key': ApiKeyPage, session: SessionPage,
  jwt: JwtPage, tokens: TokensPage, oauth2: OAuth2Page, oidc: OidcPage, saml: SamlPage,
};

function App() {
  return (
    <div className="layout">
      <nav className="sidebar">
        <NavLink to="/" end className="brand">
          <span className="mark" aria-hidden="true" />Auth<span className="lab">Lab</span>
          <span className="brand-tag">9 methods · live backend</span>
        </NavLink>
        {AUTH_METHODS.map((m, i) => (
          <NavLink key={m.id} to={`/${m.id}`}>
            <span className="num">{String(i + 1).padStart(2, '0')}</span>
            <span>{m.title}<small>{m.category}</small></span>
          </NavLink>
        ))}
        <div className="sidebar-foot"><span className="g">■</span> granted &nbsp; <span className="r">■</span> denied</div>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          {Object.entries(PAGES).map(([id, C]) => <Route key={id} path={`/${id}`} element={<C />} />)}
          <Route path="/oauth2/callback" element={<OAuth2Callback />} />
        </Routes>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter><App /></BrowserRouter>
  </StrictMode>,
);

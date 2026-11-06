/** Explanations + Mermaid diagrams for every method. Rendered by <Mermaid/>. */

export interface Diagram { title: string; code: string }
export interface MethodContent {
  summary: string;
  diagrams: Diagram[];
  practices: string[];
  pitfalls: string[];
  curl: string;
}

export const OVERVIEW_DIAGRAMS: Diagram[] = [
  {
    title: 'System architecture (Nx monorepo)',
    code: `flowchart LR
  subgraph Browser
    WEB["apps/web<br/>React 19 + Vite<br/>:4200"]
  end
  subgraph Backend
    API["apps/api<br/>Express resource server + clients<br/>:3333"]
    AS["apps/auth-server<br/>OAuth2 AS / OIDC OP / SAML IdP<br/>:4000"]
  end
  R[("Redis<br/>sessions · refresh families<br/>deny-list · api keys · nonces<br/>auth codes · rate limits")]
  LIBS["libs/core · libs/shared<br/>users+bcrypt · keys · config"]
  WEB -- "/api/* (Vite proxy, same-origin cookies)" --> API
  WEB -- "redirect: /authorize, /saml/sso" --> AS
  WEB -- "CORS: /token (SPA + PKCE)" --> AS
  API -- "back-channel: /token, /userinfo, JWKS, SAML metadata" --> AS
  API --> R
  AS --> R
  API -.imports.-> LIBS
  AS -.imports.-> LIBS`,
  },
  {
    title: 'Taxonomy – they are NOT all the same kind of thing',
    code: `flowchart TB
  A["How does the server know who / what you are?"] --> B["HTTP auth schemes"]
  A --> C["Credentials"]
  A --> D["State model"]
  A --> E["Delegation & federation"]
  B --> B1["Basic"] & B2["Digest"] & B3["Bearer"]
  C --> C1["Password + bcrypt"] & C2["API Key"]
  D --> D1["Stateful: Session cookie"] & D2["Stateless: JWT"] & D3["Hybrid: Access + Refresh"]
  E --> E1["OAuth 2.0<br/><b>Authorization framework</b>"]
  E1 --> E2["OIDC<br/><b>Identity layer on OAuth2</b>"]
  E --> E3["SAML 2.0<br/><b>XML identity protocol</b>"]
  B3 -. "token format often" .-> D2
  E1 -. "issues" .-> D3`,
  },
  {
    title: 'Authentication vs Authorization',
    code: `flowchart LR
  U(("User / App")) -->|"1 · Who are you?"| AUTHN["Authentication<br/>password · key · assertion · ID token"]
  AUTHN -->|"identity established"| AUTHZ["Authorization<br/>roles · scopes · policies"]
  AUTHZ -->|"2 · What may you do?"| RES[("Resource")]
  AUTHZ -->|"denied"| X["403 Forbidden"]
  AUTHN -->|"failed"| Y["401 Unauthorized + WWW-Authenticate"]`,
  },
];

export const CONTENT: Record<string, MethodContent> = {
  basic: {
    summary: 'The client sends username:password, base64-encoded, in the Authorization header on every single request. Simple and universally supported, but the password is effectively sent in clear text, so TLS is mandatory.',
    diagrams: [{
      title: 'Basic auth – challenge / response',
      code: `sequenceDiagram
  autonumber
  participant C as Client
  participant API as API /api/basic
  participant DB as User store (bcrypt)
  C->>API: GET /profile
  API-->>C: 401 + WWW-Authenticate: Basic realm="authlab-basic"
  Note over C: base64("alice:Password123!")<br/>= YWxpY2U6UGFzc3dvcmQxMjMh
  C->>API: GET /profile<br/>Authorization: Basic YWxpY2U6...
  API->>DB: bcrypt.compare(password, hash) ~250ms
  DB-->>API: match
  API-->>C: 200 profile
  Note over C,API: Repeated on EVERY request - no session, no logout`,
    }],
    practices: ['Always over HTTPS', 'Verify with bcrypt + constant-time fallback hash for unknown users (no user enumeration)', 'Rate-limit per IP+username', 'Suppress browser popup for SPAs (x-Basic scheme trick)'],
    pitfalls: ['Base64 is encoding, not encryption', 'No logout / expiry', 'bcrypt on every request is CPU-heavy', 'Browsers cache credentials until closed'],
    curl: `curl -u alice:Password123! http://localhost:3333/api/basic/profile`,
  },

  digest: {
    summary: 'A challenge-response scheme: the server sends a nonce, the client proves it knows the password by hashing it together with the nonce. The password never crosses the wire, but the server must store a password-equivalent hash (HA1), so bcrypt is impossible.',
    diagrams: [{
      title: 'Digest auth (RFC 7616, qop=auth)',
      code: `sequenceDiagram
  autonumber
  participant C as Client
  participant API as API /api/digest
  participant R as Redis
  C->>API: GET /profile
  API->>R: SET digest:nonce:N = 0 (TTL 300s)
  API-->>C: 401 WWW-Authenticate: Digest realm, nonce=N, qop=auth, algorithm=SHA-256
  Note over C: HA1 = H(user:realm:pass)<br/>HA2 = H(GET:/api/digest/profile)<br/>resp = H(HA1:N:nc:cnonce:auth:HA2)
  C->>API: Authorization: Digest username, nonce=N, nc=00000001, cnonce, response
  API->>R: GET nonce N (exists? nc > last?)
  API->>API: recompute with stored HA1, timingSafeEqual
  API->>R: SET nonce N = nc (replay guard)
  API-->>C: 200 profile`,
    }],
    practices: ['Prefer SHA-256 over MD5', 'Short-lived nonces in Redis', 'Strictly increasing nonce-count to block replay', 'Constant-time comparison'],
    pitfalls: ['Server stores HA1 = password-equivalent (no bcrypt)', 'MD5 is broken', 'Complex, poorly supported by modern clients', 'Still vulnerable to MITM without TLS'],
    curl: `curl --digest -u alice:Password123! http://localhost:3333/api/digest/profile`,
  },

  'api-key': {
    summary: 'A long random secret identifying an application (not a person). Ideal for developer access, metering and rate limits. Shown once, stored only as a hash, scoped and revocable.',
    diagrams: [
      {
        title: 'Issue & use an API key',
        code: `sequenceDiagram
  autonumber
  participant Dev as Developer
  participant API as API /api/api-keys
  participant R as Redis
  Dev->>API: POST / {username, password, scopes}
  API->>API: key = ak_ + prefix8 + _ + secret43
  API->>R: HSET apikey:prefix {sha256(key), userId, scopes}
  API-->>Dev: 201 { apiKey } (shown ONCE)
  Dev->>API: GET /data   X-API-Key: ak_3f9a..._...
  API->>R: HGETALL apikey:3f9a... (O(1) via prefix)
  API->>API: timingSafeEqual(sha256(key), stored)
  API->>R: INCR rl:apikey:3f9a (20/min)
  API-->>Dev: 200 data + RateLimit headers`,
      },
      {
        title: 'Key anatomy',
        code: `flowchart LR
  K["ak_3f9a1c2d_Yx7...43 chars"] --> P["ak_ = type marker<br/>(secret scanners detect leaks)"]
  K --> PR["3f9a1c2d = public prefix<br/>lookup id, safe to log"]
  K --> S["secret = 256-bit random<br/>stored only as SHA-256"]`,
      },
    ],
    practices: ['Hash keys (SHA-256 is fine – high entropy)', 'Public prefix for lookup & display', 'Per-key scopes + rate limit', 'Send in header, never in URL (logs!)', 'Rotation & revocation'],
    pitfalls: ['Identifies the app, not the user', 'Long-lived – leaks are common (Git, front-end bundles)', 'Never embed in a browser/mobile app'],
    curl: `curl -X POST localhost:3333/api/api-keys -H 'content-type: application/json' \\
  -d '{"username":"alice","password":"Password123!","scopes":["data:read"]}'
curl localhost:3333/api/api-keys/data -H 'X-API-Key: ak_xxxxxxxx_...'`,
  },

  session: {
    summary: 'The server keeps the login state (in Redis) and gives the browser only an opaque, signed session-id cookie. Logout and revocation are instant because the server simply deletes the session.',
    diagrams: [
      {
        title: 'Session login with Redis store',
        code: `sequenceDiagram
  autonumber
  participant B as Browser
  participant API as API /api/session
  participant R as Redis
  B->>API: POST /login {username, password}
  API->>API: bcrypt.compare
  API->>API: session.regenerate() (anti-fixation)
  API->>R: SET sess:abc123 {user, csrfToken} EX 1800
  API-->>B: Set-Cookie: authlab.sid=s:abc123.sig HttpOnly SameSite=Lax
  B->>API: GET /me   Cookie: authlab.sid=...
  API->>R: GET sess:abc123 (+ sliding TTL)
  API-->>B: 200 user
  B->>API: POST /logout + X-CSRF-Token
  API->>R: DEL sess:abc123
  API-->>B: clear cookie`,
      },
      {
        title: 'Why the CSRF token?',
        code: `sequenceDiagram
  participant Evil as evil.com
  participant B as Browser (logged in)
  participant API as API
  Evil->>B: hidden form POST /api/session/transfer
  B->>API: POST + Cookie (sent automatically!)
  API-->>B: 403 - no X-CSRF-Token header
  Note over API: SameSite=Lax blocks most of these too.<br/>Defence in depth: synchronizer token.`,
      },
    ],
    practices: ['HttpOnly + Secure + SameSite cookie', 'Regenerate id on login', 'Server-side store (Redis) with TTL & sliding expiry', 'CSRF token on state-changing requests', 'saveUninitialized=false'],
    pitfalls: ['Needs shared store for horizontal scaling', 'Cookies are awkward for cross-domain APIs & native apps', 'CSRF if SameSite misconfigured'],
    curl: `curl -c jar -X POST localhost:3333/api/session/login -H 'content-type: application/json' \\
  -d '{"username":"bob","password":"Password123!"}'
curl -b jar localhost:3333/api/session/me`,
  },

  jwt: {
    summary: 'A Bearer token is any token where possession = access. JWT is a signed, self-contained token format: the API can verify it with a public key without any database lookup. Revocation needs extra work (a jti deny-list).',
    diagrams: [
      {
        title: 'JWT structure',
        code: `flowchart LR
  T["eyJhbGciOi... . eyJzdWIiOi... . SflKxwRJ..."] --> H["Header<br/>{alg: RS256, kid, typ}"]
  T --> P["Payload (claims)<br/>{sub, iss, aud, exp, iat, jti, roles}"]
  T --> S["Signature<br/>RSASSA(base64url(H).base64url(P), privateKey)"]
  S -.verify with.-> J["Public key / JWKS<br/>/api/jwt/.well-known/jwks.json"]`,
      },
      {
        title: 'Login, use, revoke',
        code: `sequenceDiagram
  autonumber
  participant C as Client
  participant API as API /api/jwt
  participant R as Redis
  C->>API: POST /login {username, password}
  API->>API: sign RS256 {sub, roles, jti, exp=15m}
  API-->>C: { access_token }
  C->>API: GET /profile  Authorization: Bearer eyJ...
  API->>API: verify signature, alg pinned, iss, aud, exp
  API->>R: EXISTS jwt:deny:jti ?
  API-->>C: 200 claims
  C->>API: GET /admin
  API-->>C: 403 (roles lacks admin) - authorization
  C->>API: POST /logout
  API->>R: SET jwt:deny:jti EX (exp - now)
  C->>API: GET /profile (same token)
  API-->>C: 401 revoked`,
      },
    ],
    practices: ['Asymmetric RS256/ES256 with kid + JWKS', 'Pin allowed algorithms (block alg=none)', 'Validate iss, aud, exp, nbf', 'Short expiry, minimal claims (no secrets – payload is readable)', 'Deny-list jti for logout'],
    pitfalls: ['Cannot be revoked without state', 'Storing in localStorage exposes it to XSS', 'Big tokens on every request', 'Never trust decoded claims without verifying'],
    curl: `TOKEN=$(curl -s -X POST localhost:3333/api/jwt/login -H 'content-type: application/json' \\
  -d '{"username":"alice","password":"Password123!"}' | jq -r .access_token)
curl localhost:3333/api/jwt/profile -H "Authorization: Bearer $TOKEN"`,
  },

  tokens: {
    summary: 'Short-lived access token (here 60 s, in memory) + long-lived refresh token (HttpOnly cookie). Each refresh rotates the refresh token; presenting an already-used one means theft, so the whole token family is revoked.',
    diagrams: [
      {
        title: 'Rotation flow',
        code: `sequenceDiagram
  autonumber
  participant SPA as SPA (memory)
  participant API as API /api/tokens
  participant R as Redis
  SPA->>API: POST /login
  API->>R: HSET rt:sha(RT1) {family F, used 0}
  API-->>SPA: access AT1 (60s) + Set-Cookie authlab.rt=RT1 (HttpOnly, Strict, path=/api/tokens)
  SPA->>API: GET /profile Bearer AT1
  API-->>SPA: 200
  Note over SPA: ...60s later AT1 expired
  SPA->>API: GET /profile Bearer AT1
  API-->>SPA: 401 expired
  SPA->>API: POST /refresh (cookie RT1)
  API->>R: Lua: used 0 to 1 (atomic)
  API->>R: HSET rt:sha(RT2) {family F, used 0}
  API-->>SPA: AT2 + cookie RT2
  SPA->>API: retry GET /profile Bearer AT2
  API-->>SPA: 200`,
      },
      {
        title: 'Reuse detection',
        code: `stateDiagram-v2
  [*] --> Active: issued
  Active --> Used: refresh (rotated)
  Used --> FamilyRevoked: presented AGAIN (stolen)
  Active --> FamilyRevoked: logout
  FamilyRevoked --> [*]: user must log in
  note right of FamilyRevoked: attacker AND victim lose access, theft contained`,
      },
    ],
    practices: ['Access token short TTL, memory only', 'Refresh token: HttpOnly, Secure, SameSite=Strict, narrow path', 'Rotate on every use + reuse detection', 'Store only hashed refresh tokens', 'Atomic used-flag (Lua) to avoid races'],
    pitfalls: ['Parallel tabs refreshing concurrently can trip reuse detection (use a refresh lock / grace window)', 'Must handle 401 → refresh → retry in the client'],
    curl: `curl -c jar -X POST localhost:3333/api/tokens/login -H 'content-type: application/json' \\
  -d '{"username":"alice","password":"Password123!"}'
curl -b jar -c jar -X POST localhost:3333/api/tokens/refresh -H 'X-Requested-With: curl'`,
  },

  oauth2: {
    summary: 'OAuth 2.0 is an AUTHORIZATION framework: it lets a client app obtain a scoped access token to call an API on behalf of a user (Authorization Code + PKCE) or itself (Client Credentials) — without ever seeing the user\'s password. It says nothing standard about who the user is.',
    diagrams: [
      {
        title: 'The four roles',
        code: `flowchart LR
  RO(("Resource Owner<br/>user alice")) -- "grants consent" --> AS["Authorization Server<br/>apps/auth-server :4000"]
  CL["Client<br/>SPA authlab-spa"] -- "1 · redirect to /authorize" --> AS
  AS -- "2 · code → access token (scopes)" --> CL
  CL -- "3 · Bearer token" --> RS["Resource Server<br/>apps/api /api/oauth2"]
  RS -. "verify via JWKS: iss, aud, scope" .-> AS`,
      },
      {
        title: 'Authorization Code + PKCE (public SPA client)',
        code: `sequenceDiagram
  autonumber
  participant U as User
  participant SPA as SPA :4200
  participant AS as Auth Server :4000
  participant RS as API (Resource Server)
  SPA->>SPA: verifier = random, challenge = SHA256(verifier), state
  SPA->>AS: redirect /authorize?client_id, redirect_uri, scope=notes:read, state, code_challenge
  AS->>U: login + consent page
  U->>AS: allow
  AS->>AS: code (60s, single use) in Redis
  AS-->>SPA: 303 /oauth2/callback?code&state&iss
  SPA->>SPA: check state
  SPA->>AS: POST /token code + code_verifier (no secret)
  AS->>AS: SHA256(verifier) == challenge ?
  AS-->>SPA: access_token (JWT, aud=authlab-api, scope)
  SPA->>RS: GET /api/oauth2/notes Bearer
  RS->>AS: JWKS (cached)
  RS-->>SPA: 200 (scope ok) or 403 insufficient_scope`,
      },
      {
        title: 'Client Credentials (machine-to-machine)',
        code: `sequenceDiagram
  participant SVC as Reporting service
  participant AS as Auth Server
  participant RS as API
  SVC->>AS: POST /token grant_type=client_credentials, Basic(client_id:secret), scope=reports:read
  AS-->>SVC: access_token (sub = client_id, no user)
  SVC->>RS: GET /api/oauth2/reports Bearer
  RS-->>SVC: 200`,
      },
    ],
    practices: ['Authorization Code + PKCE for every client (OAuth 2.1)', 'Exact redirect_uri matching', 'state for CSRF, iss param against mix-up', 'Short single-use codes', 'Scopes = least privilege, enforced at RS', 'Resource server validates aud'],
    pitfalls: ['Implicit & password grants are deprecated', 'An access token is NOT proof of login (use OIDC)', 'Tokens in SPA memory still exposed to XSS – consider BFF'],
    curl: `curl -X POST localhost:4000/token -u authlab-reporting-service:reporting-secret \\
  -d grant_type=client_credentials -d scope=reports:read`,
  },

  oidc: {
    summary: 'OpenID Connect adds an identity layer on top of OAuth 2.0: the scope "openid" makes the provider return a signed ID Token (who the user is, when and how they logged in) plus a /userinfo endpoint and discovery. Here the API is a BFF: tokens stay server-side, the browser only gets a session cookie.',
    diagrams: [
      {
        title: 'OIDC = OAuth 2.0 + identity',
        code: `flowchart TB
  O["OAuth 2.0<br/>access token, scopes, /authorize, /token"] --> I["+ OpenID Connect"]
  I --> I1["scope=openid"]
  I --> I2["ID Token (JWT)<br/>sub, iss, aud=client, nonce, auth_time"]
  I --> I3["/userinfo"]
  I --> I4["/.well-known/openid-configuration<br/>+ JWKS"]`,
      },
      {
        title: 'BFF login flow (confidential client)',
        code: `sequenceDiagram
  autonumber
  participant B as Browser
  participant BFF as API /api/oidc (RP)
  participant R as Redis
  participant OP as OpenID Provider :4000
  B->>BFF: GET /login
  BFF->>R: state → {nonce, code_verifier}
  BFF-->>B: 302 /authorize?scope=openid profile email roles, nonce, PKCE + state cookie
  B->>OP: login + consent
  OP-->>B: 303 /api/oidc/callback?code&state&iss
  B->>BFF: callback (+ state cookie)
  BFF->>BFF: state == cookie, iss ok
  BFF->>OP: POST /token code + verifier + client_secret (back-channel)
  OP-->>BFF: id_token + access_token
  BFF->>OP: GET /jwks.json (cached)
  BFF->>BFF: verify id_token sig, iss, aud, exp, nonce, at_hash
  BFF->>OP: GET /userinfo
  BFF->>R: create session (regenerate)
  BFF-->>B: Set-Cookie authlab.sid → 302 /oidc`,
      },
    ],
    practices: ['Validate ID token: signature (JWKS), iss, aud, exp, nonce', 'state bound to browser cookie', 'BFF keeps tokens out of the browser', 'Use discovery instead of hard-coding endpoints', 'PKCE even for confidential clients'],
    pitfalls: ['Using an access token as identity proof', 'Skipping nonce → replay', 'Sending ID token to APIs (it is for the client, aud = client_id)'],
    curl: `curl localhost:4000/.well-known/openid-configuration | jq`,
  },

  saml: {
    summary: 'SAML 2.0 is the XML-based enterprise SSO protocol. The Service Provider redirects the user to the Identity Provider; the IdP authenticates and returns a digitally-signed XML Assertion through the browser (HTTP-POST binding). Trust is set up by exchanging metadata (entityID, URLs, X.509 cert).',
    diagrams: [
      {
        title: 'SP-initiated SSO',
        code: `sequenceDiagram
  autonumber
  participant B as Browser
  participant SP as API /api/saml (SP)
  participant R as Redis
  participant IdP as IdP :4000/saml
  B->>SP: GET /login
  SP->>R: SET saml:req:ID (InResponseTo check)
  SP-->>B: 302 IdP /saml/sso?SAMLRequest=deflate+base64(AuthnRequest)
  B->>IdP: AuthnRequest
  IdP->>B: login form
  B->>IdP: credentials
  IdP->>IdP: build Response + Assertion, sign XML (RSA-SHA256)
  IdP-->>B: auto-submit form POST SAMLResponse
  B->>SP: POST /acs SAMLResponse
  SP->>SP: verify signature with IdP cert (metadata), Audience, Destination, NotOnOrAfter
  SP->>R: GETDEL saml:req:InResponseTo (one-time)
  SP->>R: create session
  SP-->>B: Set-Cookie authlab.sid → 303 /saml`,
      },
      {
        title: 'Assertion anatomy',
        code: `flowchart TB
  RESP["samlp:Response (Destination, InResponseTo)"] --> ISS["Issuer = IdP entityID"]
  RESP --> A["saml:Assertion  (signed: ds:Signature)"]
  A --> SUB["Subject: NameID = bob@authlab.dev"]
  A --> CON["Conditions: NotBefore / NotOnOrAfter, Audience = SP entityID"]
  A --> AUTHN["AuthnStatement: AuthnInstant, SessionIndex"]
  A --> ATTR["AttributeStatement: email, name, username, roles"]`,
      },
    ],
    practices: ['Require signed assertions; verify with cert from metadata', 'Validate Audience, Destination, time window, InResponseTo', 'One-time request ids (replay protection)', 'Schema validation (XML signature wrapping defence)', 'Prefer SP-initiated flows'],
    pitfalls: ['XML Signature Wrapping attacks if you hand-roll parsing', 'Clock skew', 'Heavy, browser-only (poor for mobile/APIs)', 'Certificate rotation coordination'],
    curl: `curl localhost:3333/api/saml/metadata   # SP metadata
curl localhost:4000/saml/metadata       # IdP metadata`,
  },
};

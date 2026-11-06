const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const layout = (title: string, body: string, nonce = '') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style nonce="${nonce}">
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0}
  .card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px;width:380px;box-shadow:0 10px 40px #0006}
  h1{font-size:18px;margin:0 0 4px} .sub{color:#94a3b8;font-size:13px;margin-bottom:18px}
  label{display:block;font-size:12px;color:#94a3b8;margin:10px 0 4px}
  input{width:100%;box-sizing:border-box;padding:9px 10px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0}
  ul{padding-left:18px;font-size:13px} .row{display:flex;gap:8px;margin-top:18px}
  button{flex:1;padding:10px;border:0;border-radius:8px;font-weight:600;cursor:pointer}
  .ok{background:#6366f1;color:white} .no{background:#334155;color:#e2e8f0}
  .badge{display:inline-block;font-size:11px;background:#312e81;color:#c7d2fe;padding:2px 8px;border-radius:99px}
  .err{background:#7f1d1d;color:#fecaca;padding:8px 10px;border-radius:8px;font-size:13px}
  code{font-size:11px;color:#a5b4fc}
</style></head><body><div class="card">${body}</div></body></html>`;

export function loginConsentPage(opts: {
  action: string; txn: string; clientName: string; scopes: { scope: string; desc: string }[]; protocol: string; error?: string;
}) {
  return layout(
    'Sign in – AuthLab IdP',
    `<span class="badge">${esc(opts.protocol)}</span>
     <h1>AuthLab Identity Provider</h1>
     <div class="sub"><b>${esc(opts.clientName)}</b> wants to access your account</div>
     ${opts.error ? `<div class="err">${esc(opts.error)}</div>` : ''}
     <form method="post" action="${esc(opts.action)}">
       <input type="hidden" name="txn" value="${esc(opts.txn)}">
       <label>Username</label><input name="username" value="alice" autocomplete="username" required>
       <label>Password</label><input name="password" type="password" value="Password123!" autocomplete="current-password" required>
       ${opts.scopes.length ? `<label>This app is requesting:</label><ul>${opts.scopes.map((s) => `<li>${esc(s.desc)} <code>${esc(s.scope)}</code></li>`).join('')}</ul>` : ''}
       <div class="row"><button class="no" name="decision" value="deny">Deny</button><button class="ok" name="decision" value="allow">Allow &amp; sign in</button></div>
     </form>`,
  );
}

/** SAML HTTP-POST binding: browser auto-submits the signed assertion to the SP's ACS. */
export function samlPostPage(acs: string, samlResponse: string, relayState: string | undefined, nonce: string) {
  return layout(
    'Redirecting to service provider…',
    `<h1>Posting SAML assertion…</h1><div class="sub">HTTP-POST binding → <code>${esc(acs)}</code></div>
     <form id="f" method="post" action="${esc(acs)}">
       <input type="hidden" name="SAMLResponse" value="${esc(samlResponse)}">
       ${relayState ? `<input type="hidden" name="RelayState" value="${esc(relayState)}">` : ''}
       <div class="row"><button class="ok" type="submit">Continue</button></div>
     </form>
     <script nonce="${nonce}">document.getElementById('f').submit()</script>`,
    nonce,
  );
}

export const errorPage = (msg: string) => layout('Error', `<h1>Authorization error</h1><div class="err">${esc(msg)}</div>`);

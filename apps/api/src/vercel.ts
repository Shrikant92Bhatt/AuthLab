import type { IncomingMessage, ServerResponse } from 'node:http';

type App = (req: IncomingMessage, res: ServerResponse) => void;

// Built once per function instance and reused. Imported lazily so a config error (e.g. Redis not
// connected) becomes a readable 503 instead of crashing the function with a bare 500.
let appReady: Promise<App> | undefined;
const load = () =>
  (appReady ??= import('./app')
    .then((m) => m.createApp() as unknown as Promise<App>)
    .catch((e) => { appReady = undefined; throw e; })); // retry on the next request

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  let app: App;
  try {
    app = await load();
  } catch (e) {
    console.error('[startup]', e);
    res.statusCode = 503;
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    res.end(JSON.stringify({ error: 'Server is not ready', detail: e instanceof Error ? e.message : String(e) }));
    return;
  }
  app(req, res);
}

import type { IncomingMessage, ServerResponse } from 'node:http';
import { createApp } from './app';

// Built once per function instance and reused across requests.
const appReady = createApp();

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  const app = await appReady;
  app(req as never, res as never);
}

/**
 * Builds one Vercel project into `.vercel/output` (Vercel's Build Output API v3).
 *
 *   tsx tools/vercel-build.mts web    → React UI (static) + apps/api as the /api function
 *   tsx tools/vercel-build.mts auth   → apps/auth-server as a single function
 *
 * Why not Vercel's zero-config builders: the workspace libs are raw TypeScript and bcrypt is
 * a native module. esbuild bundles our own code, and @vercel/nft copies the npm packages
 * (including bcrypt's prebuilt binary) that the bundle still imports.
 */
import { execSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { build } from 'esbuild';
import { nodeFileTrace } from '@vercel/nft';

const root = resolve(import.meta.dirname, '..');
const out = join(root, '.vercel/output');
const target = process.argv[2];
if (target !== 'web' && target !== 'auth') throw new Error('usage: vercel-build.ts <web|auth>');

async function buildFunction(app: 'api' | 'auth-server', name: string) {
  // Emit the bundle inside the app folder so package resolution matches local runs.
  const entry = `apps/${app}/dist/vercel.mjs`;
  await build({
    entryPoints: [join(root, `apps/${app}/src/vercel.ts`)],
    outfile: join(root, entry),
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    packages: 'external',
    tsconfig: join(root, `apps/${app}/tsconfig.json`),
    logLevel: 'warning',
  });

  const fnDir = join(out, 'functions', `${name}.func`);
  const { fileList, warnings } = await nodeFileTrace([join(root, entry)], { base: root });
  for (const w of warnings) if (!String(w.message).includes('Failed to resolve dependency')) console.warn('[nft]', w.message);
  for (const f of fileList) {
    mkdirSync(dirname(join(fnDir, f)), { recursive: true });
    cpSync(join(root, f), join(fnDir, f), { dereference: true });
  }
  writeFileSync(join(fnDir, '.vc-config.json'), JSON.stringify({
    runtime: 'nodejs22.x',
    handler: entry,
    launcherType: 'Nodejs',
    shouldAddHelpers: false, // Express parses bodies itself
    maxDuration: 30,
  }, null, 2));
  console.log(`function ${name}: ${fileList.size} files`);
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

if (target === 'web') {
  execSync('npm run build -w web', { cwd: root, stdio: 'inherit' });
  cpSync(join(root, 'apps/web/dist'), join(out, 'static'), { recursive: true });
  await buildFunction('api', 'api');
  writeFileSync(join(out, 'config.json'), JSON.stringify({
    version: 3,
    routes: [
      // `^/api(/|$)` so the /api-key page is still served by the SPA
      { src: '^/api(/.*)?$', dest: '/api' },
      { handle: 'filesystem' },
      { src: '/.*', dest: '/index.html' }, // client-side routing
    ],
  }, null, 2));
} else {
  await buildFunction('auth-server', 'index');
  writeFileSync(join(out, 'config.json'), JSON.stringify({ version: 3, routes: [{ src: '/.*', dest: '/index' }] }, null, 2));
}

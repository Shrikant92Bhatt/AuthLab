import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [react(), tsconfigPaths({ root: '../..' })],
  server: {
    port: 4200,
    strictPort: true,
    // Same-origin proxy ('^/api/' regex so the /api-key page route isn't proxied): cookies (session, refresh token) stay first-party, no CORS needed.
    proxy: { '^/api/': { target: 'http://localhost:3333', changeOrigin: false, xfwd: true } },
  },
  preview: { port: 4200, proxy: { '^/api/': 'http://localhost:3333' } },
  build: { outDir: 'dist', chunkSizeWarningLimit: 3000 },
});

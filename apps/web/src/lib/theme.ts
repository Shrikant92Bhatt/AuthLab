import { useSyncExternalStore } from 'react';

/** Dark is the default. The choice is remembered per browser; index.html applies it before first paint. */
export type Theme = 'dark' | 'light';
const KEY = 'authlab-theme';
const listeners = new Set<() => void>();

const read = (): Theme => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');

export function setTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', t === 'light' ? '#f6f5f0' : '#0a0a0a');
  try { localStorage.setItem(KEY, t); } catch { /* private mode: just don't persist */ }
  listeners.forEach((l) => l());
}

export const useTheme = () =>
  useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, read);

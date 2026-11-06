import { useSyncExternalStore } from 'react';

/**
 * In-memory token store. Access tokens live ONLY in JS memory:
 * not localStorage (readable by any XSS), not cookies (CSRF-able).
 * A page reload loses them – the refresh-token cookie / re-login recovers.
 */
type Store = Record<string, string | undefined>;
let state: Store = {};
const ls = new Set<() => void>();

export const tokens = {
  get: (k: string) => state[k],
  set: (k: string, v: string | undefined) => { state = { ...state, [k]: v }; ls.forEach((l) => l()); },
  subscribe: (l: () => void) => { ls.add(l); return () => ls.delete(l); },
};

export const useToken = (k: string) => useSyncExternalStore(tokens.subscribe, () => state[k]);

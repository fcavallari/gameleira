import { useEffect, useState } from 'react';
import { openStore, type Store } from '../session/store';
import { ErrorBoundary } from './ErrorBoundary';
import { SessionProvider, useSession } from './session-context';
import { SessionScreen } from './SessionScreen';
import { StartScreen } from './StartScreen';

export { SessionContext, SessionProvider, useSession } from './session-context';
export type { SessionCtx, View, Progress } from './session-context';

function Screens() {
  const { session } = useSession();
  return session ? <SessionScreen /> : <StartScreen />;
}

/** `store` is a test seam; the app opens its own IndexedDB store. */
export function App(props: { store?: Store } = {}) {
  return <ErrorBoundary><Storage {...props} /></ErrorBoundary>;
}

function Storage({ store: injected }: { store?: Store }) {
  const [store, setStore] = useState<Store | null>(injected ?? null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (injected) return;
    openStore().then(setStore, (e: unknown) => { setError(e instanceof Error ? e.message : String(e)); });
  }, [injected]);
  if (error) {
    return (
      <main className="shell">
        <p role="alert" className="error">Browser storage is unavailable ({error}). Sessions cannot be saved here; try a normal (non-private) window.</p>
      </main>
    );
  }
  if (!store) return <main className="shell"><p className="muted">Opening storage…</p></main>;
  return <SessionProvider store={store}><Screens /></SessionProvider>;
}

import { useEffect, useState } from 'react';
import { openStore, type Store } from '../session/store';
import { SessionProvider, useSession } from './session-context';
import { SessionScreen } from './SessionScreen';
import { StartScreen } from './StartScreen';

export { SessionContext, SessionProvider, useSession } from './session-context';
export type { SessionCtx, View, Progress } from './session-context';

function Screens() {
  const { session } = useSession();
  return session ? <SessionScreen /> : <StartScreen />;
}

export function App() {
  const [store, setStore] = useState<Store | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    openStore().then(setStore, (e: unknown) => { setError(e instanceof Error ? e.message : String(e)); });
  }, []);
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

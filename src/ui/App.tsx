import { useEffect, useState } from 'react';
import { openStore, type Store } from '../session/store';
import { Frame } from './Brand';
import { ErrorBoundary } from './ErrorBoundary';
import { GuideScreen } from './GuideScreen';
import { useGuideSection } from './route';
import { SessionProvider, useSession } from './session-context';
import { SessionScreen } from './SessionScreen';
import { StartScreen } from './StartScreen';

export { SessionContext, SessionProvider, useSession } from './session-context';
export type { SessionCtx, View, Progress } from './session-context';

/**
 * The guide replaces the screen while it is open (the screens' key handlers must not act on keys typed in it); the
 * session and its loaded captures live in the context above, so closing the guide comes back to them as they were.
 */
function Screens() {
  const { session } = useSession();
  const guide = useGuideSection();
  if (guide !== null) return <GuideScreen section={guide} />;
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
      <Frame>
        <p role="alert" className="error">Browser storage is unavailable ({error}). Sessions cannot be saved here; try a normal (non-private) window.</p>
      </Frame>
    );
  }
  if (!store) return <Frame><p className="muted">Opening storage…</p></Frame>;
  return <SessionProvider store={store}><Screens /></SessionProvider>;
}

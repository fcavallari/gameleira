import { useSession } from './session-context';

/** A failed IndexedDB operation: shown on both screens until dismissed, never swallowed. */
export function StoreErrorBanner() {
  const { storeError, dismissStoreError } = useSession();
  if (!storeError) return null;
  return (
    <div role="alert" className="banner">
      <span className="grow">{storeError}. Your change may not have been saved.</span>
      <button onClick={dismissStoreError}>Dismiss</button>
    </div>
  );
}

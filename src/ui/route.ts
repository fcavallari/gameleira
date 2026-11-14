import { useEffect, useState } from 'react';

/**
 * The guide lives at `#guide`, a section of it at `#guide/<section>`. A hash works wherever the page does (the hosted
 * copy, localhost, a file opened from Finder), needs no server, and lets the browser's Back button leave the guide.
 * Everything else is the app itself; its state lives in the session context, so leaving and coming back keeps it.
 */
export const GUIDE_HASH = '#guide';

/** The guide section the address names: '' for the top of the guide, null when the guide is not open. */
export function guideSection(hash: string = location.hash): string | null {
  if (hash === GUIDE_HASH) return '';
  if (hash.startsWith(`${GUIDE_HASH}/`)) return decodeURIComponent(hash.slice(GUIDE_HASH.length + 1));
  return null;
}

export const guideHref = (section?: string): string => (section ? `${GUIDE_HASH}/${section}` : GUIDE_HASH);

export function useGuideSection(): string | null {
  const [section, setSection] = useState(() => guideSection());
  useEffect(() => {
    const f = () => { setSection(guideSection()); };
    window.addEventListener('hashchange', f);
    return () => { window.removeEventListener('hashchange', f); };
  }, []);
  return section;
}

/** Back to the app: drops the hash (a new history entry, so Back reopens the guide). */
export function leaveGuide(): void {
  // The address without its hash. (Not built from location.search: the build test bans that string, which only the
  // dev-only fixture loader may use.)
  history.pushState(null, '', location.href.split('#')[0]);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}

/** Points the address at a section without a new history entry, so reading the guide does not fill Back with sections. */
export function markSection(section: string): void {
  history.replaceState(null, '', guideHref(section));
}

import type { ReactNode } from 'react';
import type { LoadedCapture } from '../ingest/load';
import { displayName } from '../model/relations';
import type { PersistenceItem, ProcId } from '../model/types';
import { itemPathKind, latestImage } from '../model/util';
import { launchTarget, persistenceOwner } from '../rules/rules';
import { fmtTime } from './triage-model';

/** es_btm_item_type_t, in words. */
const ITEM_TYPES = ['User item', 'App', 'Login item', 'Launch agent', 'Launch daemon'];
export const itemTypeName = (t: number | null): string => (t !== null ? ITEM_TYPES[t] : undefined) ?? 'Unknown';

/** Who registered the item, in order: the app, the XPC caller that asked for it, then whoever wrote the plist. */
const LABEL = { app: 'app', instigator: 'instigator', creator: 'plist writer' } as const;
const REGISTRANTS = ['app', 'instigator', 'creator'] as const;

const Code = ({ children }: { children: ReactNode }) => <code className="mono wrap">{children}</code>;

function who(cap: LoadedCapture, id: ProcId, onSelect: (id: ProcId) => void): ReactNode {
  return <button className="link" onClick={() => { onSelect(id); }}>{displayName(cap.model, id)}</button>;
}

/**
 * One launch item (a btm registration), written for a learner. "Registered by" is the app, else the instigator (the XPC
 * caller that asked for it), else the process that wrote the plist, labelled with which one it is. The daemon that emitted
 * the event is a different thing (it reports, it does not register), so it is listed apart. `attachedTo` says which row
 * carries the finding: the process the viewer is looking at, or nothing when the item stands alone.
 */
export function LaunchItem({ cap, item, current, onSelect }: {
  cap: LoadedCapture; item: PersistenceItem; current: ProcId | null; onSelect(id: ProcId): void;
}) {
  const m = cap.model;
  const registrant = REGISTRANTS.map(field => ({ id: item[field], label: LABEL[field] })).find(r => r.id !== null && m.processes.has(r.id));
  const registrantProc = registrant ? m.processes.get(registrant.id!) : undefined;
  const relays = registrantProc !== undefined && latestImage(registrantProc)?.isPlatform === true;
  const owner = persistenceOwner(m, item);
  const kind = itemPathKind(item.plistPath);
  const target = launchTarget(item);
  const rows: [string, ReactNode][] = [['Item type', itemTypeName(item.itemType)]];
  // The item URL is a plist for an agent or daemon, but the app bundle for a login item or an app.
  if (item.plistPath !== null) rows.push([kind === 'plist' ? 'Plist' : kind === 'app' ? 'App' : 'Item', <Code>{item.plistPath}</Code>]);
  rows.push(['Runs', <Code>{target ? target.path : item.executablePath ?? 'unknown'}{target?.isApp && <span className="muted"> (the app itself)</span>}</Code>]);
  const same = (a: string, b: string): boolean => a.replace(/\/+$/, '') === b.replace(/\/+$/, '');
  if (item.appPath && !(item.plistPath !== null && same(item.appPath, item.plistPath))) rows.push(['App', <Code>{item.appPath}</Code>]);
  rows.push(['Time', <span className="mono">{fmtTime(item.time)}</span>]);
  rows.push(['Registered by', registrant
    ? <>{who(cap, registrant.id!, onSelect)} <span className="muted">({registrant.label}{relays ? '; an Apple system process, which may only be relaying the request for someone else' : ''})</span></>
    : <span className="muted">no captured process: the event names none that was seen</span>]);
  if (m.processes.has(item.emitter)) {
    rows.push(['Reported by', <>{who(cap, item.emitter, onSelect)} <span className="muted">(the system daemon that emitted the event; it reports registrations, it does not make them)</span></>]);
  }
  rows.push(['Finding on', owner === null
    ? <span className="muted">no process: this item stands alone in the queue</span>
    : <>{owner.id === current ? <span>this process</span> : who(cap, owner.id, onSelect)} <span className="muted">({LABEL[owner.via]})</span></>]);
  return (
    <dl className="dl" aria-label={`Launch item ${item.id}`}>
      {rows.map(([k, v]) => <div key={k} className="dlrow"><dt>{k}</dt><dd>{v}</dd></div>)}
    </dl>
  );
}

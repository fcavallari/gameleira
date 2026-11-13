import type { ReactNode } from 'react';

/** The mark: one limb, two roots that reached the ground and thickened into trunks, two still hanging. */
export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" aria-hidden="true" fill="currentColor">
      <rect x="1" y="2" width="18" height="3" />
      <rect x="2" y="5" width="3" height="13" />
      <rect x="8.25" y="5" width="1.5" height="7" />
      <rect x="11.75" y="5" width="1.5" height="10" />
      <rect x="15" y="5" width="3" height="13" />
    </svg>
  );
}

export function Wordmark() {
  return <span className="brand"><Mark /><span className="wordmark">Gameleira</span></span>;
}

/** The bark-tinted frame and its one sheet, for the screens that have nothing but a message to show. */
export function Frame({ children }: { children: ReactNode }) {
  return (
    <div className="app">
      <header className="topbar"><Wordmark /></header>
      <main className="sheet">{children}</main>
    </div>
  );
}

/*
 * The home page's gameleira, in two parts that meet at one limb: the crown above it (Canopy) and the roots below it
 * (RootField). Between them the page draws the limb itself, across the whole sheet, and one root from its left end down
 * the session list. Geometric masses with engraved contour lines; the branches inside the crown are drawn as a graph.
 */

// Crown domes standing on the limb (y 240): [centre x, radius]. The back row is set first, in the deeper tone.
const BACK: [number, number][] = [[300, 150], [570, 192], [830, 168]];
const FRONT: [number, number][] = [[140, 104], [420, 132], [700, 146], [930, 112]];
// Branches as a graph: each path runs from the limb up through its forks; nodes sit at the forks, figs at the ends.
const BRANCHES: [number, number][][] = [
  [[210, 240], [290, 176], [350, 112]], [[290, 176], [236, 126]],
  [[500, 240], [560, 160], [612, 92]], [[560, 160], [500, 104]],
  [[760, 240], [806, 168], [866, 124]], [[806, 168], [770, 112]],
  [[90, 240], [130, 186]],
];
const FORKS: [number, number][] = [[290, 176], [560, 160], [806, 168]];
const FIGS: [number, number][] = [[350, 112], [236, 126], [612, 92], [500, 104], [866, 124], [770, 112], [130, 186]];

const arc = (cx: number, r: number, y = 240): string => `M ${cx - r} ${y} A ${r} ${r} 0 0 1 ${cx + r} ${y}`;

/** A short sample of a root's line, drawn as the Roots panel and the root field draw it. */
export function RootSwatch({ kind }: { kind: 'original' | 'current' | 'responsible' }) {
  return (
    <svg className="swatch" width="22" height="8" viewBox="0 0 22 8" aria-hidden="true">
      <line x1="0" y1="4" x2="22" y2="4" strokeWidth="3" stroke={`var(--root-${kind})`}
        strokeDasharray={kind === 'current' ? '5 3' : undefined} />
    </svg>
  );
}

export function Canopy() {
  return (
    <svg viewBox="0 0 960 240" preserveAspectRatio="xMinYMax slice" aria-hidden="true">
      {BACK.map(([cx, r]) => (
        <g key={cx}>
          <path d={`${arc(cx, r)} Z`} fill="var(--botanical-2)" />
          {[0.86, 0.72].map(k => <path key={k} d={arc(cx, r * k)} fill="none" stroke="var(--accent)" strokeOpacity=".08" />)}
        </g>
      ))}
      {FRONT.map(([cx, r]) => (
        <g key={cx}>
          <path d={`${arc(cx, r)} Z`} fill="var(--botanical)" />
          {[0.84, 0.66, 0.48].map(k => <path key={k} d={arc(cx, r * k)} fill="none" stroke="var(--accent)" strokeOpacity=".15" />)}
        </g>
      ))}
      {BRANCHES.map((pts, i) => (
        <polyline key={i} points={pts.map(p => p.join(',')).join(' ')} fill="none" stroke="var(--limb)" strokeWidth="2" />
      ))}
      {FORKS.map(([x, y]) => <circle key={x} cx={x} cy={y} r="4" fill="var(--limb)" />)}
      {FIGS.map(([x, y]) => <circle key={x} cx={x} cy={y} r="4" fill="var(--node)" />)}
    </svg>
  );
}

// Hanging roots below the limb: [x %, how far down %, ends in a node]. The three that reach the ground are the trunks.
const HANG: [number, number, boolean][] = [
  [6, 34, false], [10, 58, true], [14, 22, false], [30, 46, false], [34, 71, true], [38, 28, false],
  [57, 38, false], [61, 63, true], [66, 18, false], [84, 52, false], [88, 30, true], [93, 66, false],
];
export const TRUNKS: { x: number; kind: 'original' | 'current' | 'responsible'; label: string }[] = [
  { x: 20, kind: 'original', label: 'Original parent' },
  { x: 48, kind: 'current', label: 'Current parent' },
  { x: 78, kind: 'responsible', label: 'Responsible' },
];

export function RootField() {
  return (
    <svg width="100%" height="100%" aria-hidden="true">
      {HANG.map(([x, y, node], i) => (
        <g key={x} className="hang" style={{ animationDelay: `${(i % 6) * 140}ms` }}>
          <rect x={`${x}%`} y="0" width="2" style={{ height: `${y}%` }} fill="var(--root-line)" />
          {node && <circle cx={`${x}%`} cy={`${y}%`} r="3.5" fill="var(--node)" />}
        </g>
      ))}
      {TRUNKS.map(({ x, kind }) => (
        <g key={kind} className={`trunk ${kind}`}>
          <line className="stem" x1={`${x}%`} y1="0" x2={`${x}%`} y2="100%" stroke={`var(--root-${kind})`}
            strokeDasharray={kind === 'current' ? '14 8' : undefined} />
          <line x1={`${x}%`} y1="94%" x2={`${x - 2.5}%`} y2="100%" stroke={`var(--root-${kind})`} strokeWidth="2" />
          <line x1={`${x}%`} y1="94%" x2={`${x + 2.5}%`} y2="100%" stroke={`var(--root-${kind})`} strokeWidth="2" />
          <circle className="pulse" cx={`${x}%`} cy="5" r="5" fill="var(--node)" />
        </g>
      ))}
    </svg>
  );
}

import { useId, type ReactNode } from 'react';

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

/** Line samples for the three roots, drawn exactly as the Roots panel and the figure draw them. */
export function RootSwatch({ kind }: { kind: 'original' | 'current' | 'responsible' }) {
  return (
    <svg viewBox="0 0 28 10" aria-hidden="true">
      <line x1="0" y1="5" x2="28" y2="5" strokeWidth="2.5" stroke={`var(--root-${kind})`}
        strokeDasharray={kind === 'current' ? '5 3' : undefined} />
    </svg>
  );
}

// The crown is built from 48px tiles, each a square and a quarter disc, set like a modular tile panel.
// [column, row, corner of the disc (0 top-left, 1 top-right, 2 bottom-right, 3 bottom-left), tile ground, disc]
type Tile = [number, number, 0 | 1 | 2 | 3, string | null, string];
const LEAF = 'var(--accent)';
const DEEP = 'var(--leaf-deep)';
const CROWN: Tile[] = [
  [1, 0, 2, null, LEAF], [2, 0, 3, null, LEAF], [3, 0, 2, null, LEAF], [4, 0, 3, null, LEAF], [5, 0, 2, null, LEAF], [6, 0, 3, null, LEAF],
  [0, 1, 1, null, LEAF], [1, 1, 1, LEAF, DEEP], [2, 1, 0, LEAF, DEEP], [3, 1, 1, LEAF, DEEP],
  [4, 1, 0, LEAF, DEEP], [5, 1, 1, LEAF, DEEP], [6, 1, 0, LEAF, DEEP], [7, 1, 0, null, LEAF],
];
// Figs: small and round, where the crown meets the limb.
const FIGS: [number, number][] = [[80, 96], [176, 98], [272, 96], [328, 98]];

// The limb is at y 104; the ground at 300. Hanging aerial roots: x and how far down they reach.
const HANGING: [number, number][] = [
  [40, 190], [58, 236], [74, 160], [138, 214], [156, 268], [172, 176], [236, 250], [252, 196], [318, 228], [334, 168], [352, 262],
];

/**
 * A gameleira drawn the way the app reads a process: a crown of tiles, many aerial roots, and three that reached the
 * ground and became trunks. The three are the three ways Gameleira traces where a process came from, drawn as the Roots
 * panel draws them.
 */
export function GameleiraFigure() {
  const clip = useId();
  return (
    <svg viewBox="0 0 400 304" role="img" aria-label="A gameleira: aerial roots hang from a wide crown; three reach the ground">
      <defs><clipPath id={clip}><rect width="48.6" height="48.6" /></clipPath></defs>
      {CROWN.map(([col, row, corner, ground, disc]) => (
        <g key={`${col}:${row}`} transform={`translate(${8 + col * 48} ${8 + row * 48})`} clipPath={`url(#${clip})`}>
          {ground && <rect width="48.6" height="48.6" fill={ground} />}
          <circle cx={corner === 1 || corner === 2 ? 48 : 0} cy={corner >= 2 ? 48 : 0} r="48" fill={disc} />
        </g>
      ))}
      {FIGS.map(([x, y]) => <circle key={x} cx={x} cy={y} r="5" fill="var(--med-mark)" />)}
      <rect x="0" y="104" width="400" height="8" fill="var(--limb)" />
      {HANGING.map(([x, y]) => <rect key={x} x={x} y="112" width="3" height={y - 112} fill="var(--root-current)" opacity=".6" />)}
      <rect x="100" y="112" width="8" height="188" fill="var(--root-original)" />
      <line x1="204" y1="112" x2="204" y2="300" stroke="var(--root-current)" strokeWidth="8" strokeDasharray="16 8" />
      <rect x="292" y="112" width="8" height="188" fill="var(--root-responsible)" />
      <rect x="0" y="300" width="400" height="3" fill="var(--limb)" />
    </svg>
  );
}

import { Component, type ErrorInfo, type ReactNode } from 'react';

/**
 * Last line of defence: a screen that throws would otherwise leave a blank page. This only shows a message. It never
 * touches the stored sessions (they live in IndexedDB and are read again after a reload).
 */
export class ErrorBoundary extends Component<{ children: ReactNode; onReload?: () => void }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } { return { failed: true }; }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    console.error('Gameleira: a screen failed', error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    const reload = this.props.onReload ?? (() => { window.location.reload(); });
    return (
      <main className="shell">
        <div role="alert" className="banner">
          <span className="grow">Something went wrong — reload. Your sessions are saved.</span>
          <button onClick={reload}>Reload</button>
        </div>
      </main>
    );
  }
}

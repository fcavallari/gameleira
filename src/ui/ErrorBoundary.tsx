import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Frame } from './Brand';

/**
 * Last line of defence: a screen that throws would otherwise leave a blank page. This only shows a message. It never
 * touches the stored sessions (they live in IndexedDB and are read again after a reload). A write that was still
 * in flight when the screen failed may not have reached the store, so the message does not promise more than that.
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
      <Frame>
        <div role="alert" className="banner">
          <span className="grow">Something went wrong — reload. Your saved sessions are kept in this browser. A change you made in the last few seconds may not have been saved.</span>
          <button onClick={reload}>Reload</button>
        </div>
      </Frame>
    );
  }
}

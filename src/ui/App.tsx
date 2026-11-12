import { useEffect, useState } from 'react';
import Ping from './ping.worker?worker&inline';

export function App() {
  const [status, setStatus] = useState('starting');
  useEffect(() => {
    const w = new Ping();
    w.onmessage = (e: MessageEvent<string>) => setStatus(e.data);
    w.onerror = () => setStatus('error');
    return () => w.terminate();
  }, []);
  return (
    <main>
      <h1>eslogger viewer</h1>
      <p>worker: {status}</p>
    </main>
  );
}

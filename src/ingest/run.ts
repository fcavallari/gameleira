import LoadWorker from './worker?worker&inline';
import type { LoadedCapture, ProgressFn, WorkerOut } from './load';

// Kept apart from load.ts: the worker imports load.ts, so load.ts must not import the worker.
/** Load a dropped file in a Web Worker (inline blob worker, so it also works from file://). */
export function runLoad(file: File, onProgress: ProgressFn): Promise<LoadedCapture> {
  return new Promise((resolve, reject) => {
    const w = new LoadWorker();
    const finish = () => w.terminate();
    w.onmessage = (e: MessageEvent<WorkerOut>) => {
      const m = e.data;
      if (m.type === 'progress') onProgress(m.bytes, m.total);
      else if (m.type === 'done') { finish(); resolve(m.capture); }
      else { finish(); reject(new Error(m.message)); }
    };
    w.onerror = (e) => { finish(); reject(new Error(e.message || 'Worker failed')); };
    w.onmessageerror = () => { finish(); reject(new Error('Worker reply could not be read')); };
    w.postMessage({ file });
  });
}

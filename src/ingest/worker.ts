import { loadCapture, type WorkerOut } from './load';

const post = (m: WorkerOut) => self.postMessage(m);

self.onmessage = async (e: MessageEvent<{ file: File }>) => {
  try {
    const capture = await loadCapture(e.data.file, (bytes, total) =>
      post({ type: 'progress', bytes, total }));
    post({ type: 'done', capture });
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) });
  }
};

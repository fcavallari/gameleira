import { ModelBuilder } from '../model/builder';
import type { CaptureModel } from '../model/types';
import { analyze, type Analysis } from '../rules/engine';
import { fingerprint } from './fingerprint';
import { streamLines } from './lines';
import { detectLayout, streamObjects } from './records';

export interface LoadedCapture {
  fingerprint: string;
  fileName: string;
  size: number;
  model: CaptureModel;
  analysis: Analysis;
}

export type ProgressFn = (bytes: number, total: number) => void;

export async function loadCapture(blob: Blob, onProgress?: ProgressFn): Promise<LoadedCapture> {
  const layout = await detectLayout(blob);
  const builder = new ModelBuilder();
  if (layout === 'objects') await streamObjects(blob, (r) => builder.addLine(r), onProgress);
  else await streamLines(blob, (l) => builder.addLine(l), onProgress);
  const model = builder.finish();
  if (layout === 'objects') model.stats.layout = 'objects';
  if (model.stats.events === 0) throw new Error('No eslogger or Mac Monitor events found in this file');
  return {
    fingerprint: await fingerprint(blob, model.stats.firstSeq, model.stats.firstTime, layout),
    fileName: (blob as File).name ?? '',
    size: blob.size,
    model,
    analysis: analyze(model),
  };
}

export type WorkerOut =
  | { type: 'progress'; bytes: number; total: number }
  | { type: 'done'; capture: LoadedCapture }
  | { type: 'error'; message: string };
